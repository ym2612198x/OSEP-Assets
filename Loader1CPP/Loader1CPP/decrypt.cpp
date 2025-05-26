#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <iostream>
#include "common.h"

#pragma comment(lib, "bcrypt.lib")


// key and iv used for encrypt/decrypt
extern unsigned char pKey[] = {
        0x66, 0x7E, 0x40, 0xAB, 0x25, 0x57, 0x2A, 0xE2, 0x0C, 0x2D, 0x85, 0x49, 0x44, 0x39, 0xBC, 0x96,
        0x7C, 0x47, 0xB6, 0xF2, 0xE6, 0xF6, 0xA8, 0x4E, 0x4C, 0x5E, 0x30, 0x56, 0xB6, 0x60, 0x74, 0x78
};

extern unsigned char pIV[] = {
        0xF6, 0x65, 0x65, 0xC7, 0x63, 0xC9, 0x2E, 0xAE, 0x09, 0xE7, 0x3E, 0x6A, 0xF6, 0x94, 0x54, 0xE0
};


//
// takes encrypted payload and size, creates decrypted payload and size
//
BOOL Decrypt(BYTE* pbPayloadEncrypted, SIZE_T szPayloadEncryptedSize, BYTE* &pbPayloadDecrypted, SIZE_T &szPayloadDecryptedSize)
{

    NTSTATUS            nStatus                     = 0;
    DWORD               dwBytes                     = 0;
    DWORD               dwPayloadUnencryptedSize    = 0;
    BCRYPT_ALG_HANDLE   hAlgorithm                  = NULL;
    BCRYPT_KEY_HANDLE   hKey                        = NULL;

    
    nStatus = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (!BCRYPT_SUCCESS(nStatus))
    {
        return FALSE;
    }


    nStatus = BCryptSetProperty(
        hAlgorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);
    if (!BCRYPT_SUCCESS(nStatus))
    {
        return FALSE;
    }


    nStatus = BCryptGenerateSymmetricKey(
        hAlgorithm,
        &hKey,
        NULL,
        0,
        (PUCHAR)pKey,
        32,
        0);
    if (!BCRYPT_SUCCESS(nStatus))
    {
        return FALSE;
    }


    nStatus = BCryptDecrypt(
        hKey,
        pbPayloadEncrypted,
        (ULONG)szPayloadEncryptedSize,
        NULL,
        pIV,
        16,
        NULL,
        0,
        &dwPayloadUnencryptedSize,
        BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(nStatus))
    {
        return FALSE;
    }


    BYTE* outputBuffer = new BYTE[dwPayloadUnencryptedSize];
    nStatus = BCryptDecrypt(
        hKey,
        pbPayloadEncrypted,
        (ULONG)szPayloadEncryptedSize,
        NULL,
        pIV,
        16,
        outputBuffer,
        dwPayloadUnencryptedSize,
        &dwBytes,
        BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(nStatus))
    {
        delete[] outputBuffer;
        return FALSE;
    }


    //
    // return values
    //
    pbPayloadDecrypted = outputBuffer;
    szPayloadDecryptedSize = dwPayloadUnencryptedSize;


    return TRUE;

}