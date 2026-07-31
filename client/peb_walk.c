/*
 * client/peb_walk.c  –  PEB-based module/export resolution
 * ==========================================================
 * Implements peb_get_module() and peb_get_export() from peb_walk.h.
 * No GetProcAddress, no GetModuleHandle, no CRT calls.
 */

#include "peb_walk.h"
#include <stddef.h>

/* ── peb_get_module ─────────────────────────────────────────────────────── */
/*
 * Walk PEB->Ldr->InMemoryOrderModuleList.
 * Each LIST_ENTRY is embedded inside LDR_DATA_TABLE_ENTRY at
 *   offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks).
 * We use CONTAINING_RECORD to recover the full entry.
 *
 * The UNICODE_STRING BaseDllName holds the filename (e.g. L"ntdll.dll").
 * We hash its characters (lowercase) and compare to nameHash.
 */

/* MinGW's winternl.h may not expose the full LDR entry — define what we need */
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    /* ... remaining fields not needed */
} MY_LDR_DATA_TABLE_ENTRY;

PVOID peb_get_module(DWORD nameHash)
{
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif

    PEB_LDR_DATA *ldr = peb->Ldr;
    LIST_ENTRY   *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY   *cur  = head->Flink;

    while (cur != head) {
        /* InMemoryOrderLinks is the second LIST_ENTRY in the struct,
         * so subtract one LIST_ENTRY size to get to the struct base */
        MY_LDR_DATA_TABLE_ENTRY *entry =
            (MY_LDR_DATA_TABLE_ENTRY *)((BYTE *)cur
                - offsetof(MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            DWORD h = peb_hash_wstr(entry->BaseDllName.Buffer);
            if (h == nameHash)
                return entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}


/* ── peb_get_export ─────────────────────────────────────────────────────── */
/*
 * Walk the PE export directory.
 *
 * Export directory layout:
 *   IMAGE_EXPORT_DIRECTORY
 *     AddressOfNames[i]      → RVA of function name string
 *     AddressOfNameOrdinals[i] → index into AddressOfFunctions[]
 *     AddressOfFunctions[ord]  → RVA of function
 *
 * For each i: hash(Names[i]) == nameHash → return base + Functions[NameOrdinals[i]]
 */
PVOID peb_get_export(PVOID moduleBase, DWORD nameHash)
{
    BYTE *base = (BYTE *)moduleBase;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nth = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD expRva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
    if (!expRva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + expRva);

    DWORD  *names    = (DWORD  *)(base + exp->AddressOfNames);
    WORD   *ordinals = (WORD   *)(base + exp->AddressOfNameOrdinals);
    DWORD  *funcs    = (DWORD  *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (peb_hash_str(name) == nameHash) {
            DWORD funcRva = funcs[ordinals[i]];
            /* Skip forwarder RVAs (inside export section) */
            DWORD expSize = nth->OptionalHeader.DataDirectory
                                [IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            if (funcRva >= expRva && funcRva < expRva + expSize)
                return NULL;   /* forwarder — not handled */
            return (PVOID)(base + funcRva);
        }
    }
    return NULL;
}
