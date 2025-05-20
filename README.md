# SilentProxy

**SilentProxy** is a powerful Man-in-the-Middle (MITM) proxy tool written in Python. It features a full GUI interface, cookie sniffer, dynamic redirect engine, and a customizable client builder with obfuscation layers.

---

## ✨ Features

- **Full GUI Interface**  
  Control the proxy server, manage redirect rules, and build clients from one place.

- **TLS Interception**  
  Dynamic root CA generation and per-domain leaf certificates for seamless HTTPS MITM.

- **Cookie Sniffer**  
  Extracts and stores HTTP cookies from intercepted traffic into `cookies.json`.

- **Wildcard Redirect Engine**  
  Define domain/path patterns (e.g., `*.instagram.com`) for automatic HTTP/HTTPS redirects.

- **Client Builder**  
  - Embeds custom host, port, and the root certificate into a native Windows executable  
  - Multi-layered evasion:  
    - Random junk code injection  
    - Symbol stripping  
    - UPX compression  
    - PE header timestamp mutation (via `pefile`)  
    - Section renaming (via `lief`)  
    - Overlay noise  

- **Ngrok Integration**  
  One-click TCP tunnel creation with automatic GUI population of public host and port.

---

## 🛠 Requirements

- **Python 3.8+**  
- **g++** or **clang** compiler (for building the client)  
- **[ngrok](https://ngrok.com/)** (optional – for remote tunneling)  
  Make sure `ngrok.exe` is in your `%PATH%` or the same directory as `server_fast_build.py`.

---

## 📦 Python Dependencies

Install all Python requirements with:

```bash
pip install -r requirements.txt
