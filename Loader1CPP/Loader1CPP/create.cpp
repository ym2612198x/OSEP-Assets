#include <iostream>
#include <vector>
#include <Windows.h>


//
// remote suspended process creation
//
BOOL Create(HANDLE &hProcess, HANDLE &hThread, DWORD &dwProcessId)
{

    STARTUPINFO         si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    BOOL                bStatus = FALSE;


    //
    // create process
    //
    bStatus = CreateProcessW(
        L"C:\\Windows\\System32\\RuntimeBroker.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,
        NULL,
        NULL,
        &si,
        &pi);
    if (!bStatus)
    {
        return FALSE;
    }


    //
    // return stuff
    //
    dwProcessId = pi.dwProcessId;
    hProcess = pi.hProcess;
    hThread = pi.hThread;


    return TRUE;

}