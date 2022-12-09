#ifndef WIN32
#define WIN32
#endif

#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif // !_WINDOWS_

#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <winuser.h>
#include <WinInet.h>
#include <windowsx.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <winternl.h>
#include <ntstatus.h>

#ifndef WIN32
#define WIN32
#endif


#pragma once


struct sockaddr_in socket_stdIn;
unsigned short sPort = 50005;
char* sIP = "192.168.1.226";
WSADATA wData;

