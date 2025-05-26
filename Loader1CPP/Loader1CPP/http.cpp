#include <vector>
#include <Windows.h>
#include <winhttp.h>
#include <iostream>

#pragma comment(lib, "winhttp.lib")


std::vector<BYTE> Download(LPCWSTR lpUrl)
{

    //
    // vars
    //
    std::vector<BYTE>   svBuffer;                               // download data buffer
    HINTERNET	        hSession        = NULL;                 // session stuff
    HINTERNET           hConnect        = NULL;                 // session stuff
    HINTERNET           hRequest        = NULL;                 // session stuff
    BOOL                bStatus         = FALSE;                // bool status var
    DWORD               dwHttpOpenFlags = 0;                    // flags
    DWORD		        dwOptionFlags   = 0;                    // flags
    DWORD               dwBytesRead     = 0;                    // downloaded bytes var
    DWORD               dwStatusCode    = 0;                    // response status code
    DWORD               dwSize          = sizeof(dwStatusCode); // ???
    INT                 iStatus         = 0;                    // int status var
    URL_COMPONENTS      urlComponents   = {};                   // url components
    std::wstring        urlPath;                                // http url path
    std::wstring        hostName;                               // http hostname
    INT                 port            = 0;                    // http port
    urlComponents.dwStructSize          = sizeof(URL_COMPONENTS);
    urlComponents.dwSchemeLength        = 1;
    urlComponents.dwHostNameLength      = 1;
    urlComponents.dwUrlPathLength       = 1;
    urlComponents.dwExtraInfoLength     = 1;


    //
    // check if secure http
    //
    iStatus = wcsncmp(
        lpUrl,
        L"https://",
        wcslen(L"https://"));
    if (iStatus == 0)
    {
        dwHttpOpenFlags = WINHTTP_FLAG_SECURE;
    }


    //
    // url crack, get hostname, port and stuff
    //
    bStatus = WinHttpCrackUrl(
        lpUrl,
        0,
        0,
        &urlComponents);
    if (!bStatus)
    {
        goto _EndOfFunction;
    }
    port = urlComponents.nPort;
    urlPath.assign(
        urlComponents.lpszUrlPath, 
        urlComponents.dwUrlPathLength);
    hostName.assign(
        urlComponents.lpszHostName, 
        urlComponents.dwHostNameLength);


    //
    // http open
    //
    hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        NULL);
    if (!hSession)
    {
        goto _EndOfFunction;
    }


    //
    // http connect
    //
    hConnect = WinHttpConnect(
        hSession,
        hostName.c_str(),
        port,
        0);
    if (!hConnect)
    {
        goto _EndOfFunction;
    }


    //
    // http open
    //
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        urlPath.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwHttpOpenFlags);
    if (!hRequest)
    {
        goto _EndOfFunction;
    }


    //
    // set https options if required
    //
    if (dwHttpOpenFlags == WINHTTP_FLAG_SECURE)
    {
        dwOptionFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        bStatus = WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &dwOptionFlags,
            sizeof(DWORD));

        if (!hRequest || bStatus == FALSE)
        {
            goto _EndOfFunction;
        }
    }


    //
    // send request
    //
    bStatus = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);
    if (!bStatus)
    {
        goto _EndOfFunction;
    }


    //
    // receive response
    //
    bStatus = WinHttpReceiveResponse(
        hRequest,
        NULL);
    if (!bStatus)
    {
        goto _EndOfFunction;
    }


    //
    // check http status code
    //
    bStatus = WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &dwStatusCode,
        &dwSize,
        WINHTTP_NO_HEADER_INDEX);
    if (!bStatus || dwStatusCode == HTTP_STATUS_NOT_FOUND)
    {
        goto _EndOfFunction;
    }


    //
    // read data into buffer
    //
    do
    {
        BYTE temp[4096]{};
        WinHttpReadData(
            hRequest,
            temp,
            sizeof(temp),
            &dwBytesRead);

        if (dwBytesRead > 0)
        {
            svBuffer.insert(
                svBuffer.end(),
                temp,
                temp + dwBytesRead);
        }

    } while (dwBytesRead > 0);


    //
    // end
    //
_EndOfFunction:
    if (hRequest)
    {
        WinHttpCloseHandle(hRequest);
    }
    if (hConnect)
    {
        WinHttpCloseHandle(hConnect);
    }
    if (hSession)
    {
        WinHttpCloseHandle(hSession);
    }

    return svBuffer;

}