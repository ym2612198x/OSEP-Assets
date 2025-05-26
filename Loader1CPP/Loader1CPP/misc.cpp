#include <Windows.h>
#include <iostream>
#include <iomanip>


//
// just delays initial exectuon for whatever reason
//
BOOL Delay(DWORD dwSeconds)
{

    DWORD       dwMilliSeconds  = dwSeconds * 1000;
    HANDLE      hEvent          = NULL;
    ULONGLONG   dwT0            = NULL;
    ULONGLONG   dwT1            = NULL;


    hEvent = CreateEventW(
        NULL,
        NULL,
        NULL,
        NULL);
    if (hEvent == NULL)
    {
        return FALSE;
    }


    dwT0 = GetTickCount64();
    if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED)
    {
        return FALSE;
    }
    dwT1 = GetTickCount64();


    if ((DWORD)(dwT1 - dwT0) < dwMilliSeconds)
    {
        return FALSE;
    }


    CloseHandle(hEvent);

    return TRUE;

}


//
// prints payload data in hex format
//
VOID PrintHexData(PBYTE Data, SIZE_T Size)
{
    for (SIZE_T i = 0; i < Size; i++)
    {
        if (i % 16 == 0)
        {
            std::cout << "\n\t";
        }
        std::cout << "0x"
            << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(Data[i])
            << (i < Size - 1 ? ", " : " ");
    }


    std::cout << std::endl << std::endl;

}