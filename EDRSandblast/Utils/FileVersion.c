/*

--- ntoskrnl.exe / wdigest.dll version compute functions.

*/
#include <Tchar.h>
#include <stdio.h>

#include "../EDRSandblast.h"

#include "FileVersion.h"

void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename) {
    DWORD verHandle = 0;
    UINT size = 0;
    LPVOID lpBuffer = NULL;

    DWORD verSize = GetFileVersionInfoSize(filename, &verHandle);

    if (verSize != 0) {
        LPTSTR verData = (LPTSTR)calloc(verSize, 1);

        if (!verData) {
            _putts_or_not(TEXT("[!] Couldn't allocate memory to retrieve version data"));
            return;
        }

        if (GetFileVersionInfo(filename, 0, verSize, verData)) {
            if (VerQueryValue(verData, TEXT("\\"), &lpBuffer, &size)) {
                if (size) {
                    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
                    if (verInfo->dwSignature == 0xfeef04bd) {
                        DWORD majorVersion = (verInfo->dwFileVersionLS >> 16) & 0xffff;
                        DWORD minorVersion = (verInfo->dwFileVersionLS >> 0) & 0xffff;
                        _stprintf_s(buffer, bufferLen, TEXT("%ld-%ld"), majorVersion, minorVersion);
                        //_tprintf_or_not(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
                    }
                }
            }
        }
        free(verData);
    }
}


// code base from https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
// modified for sha256 sum

DWORD sha256sum(LPCWSTR filename, TCHAR* checksum, BOOL verbose)
{
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[SHA256LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    //LPCWSTR filename = L"filename.txt";

    // Logic to check usage goes here.

    hFile = CreateFile(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        printf("Error opening file %ls\nError: %d\n", filename,
            dwStatus);
        return dwStatus;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        //PROV_RSA_FULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        return dwStatus;
    }

    //if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        printf("ReadFile failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    //cbHash = MD5LEN;
    cbHash = SHA256LEN;
    if (verbose)
        wprintf_s(L"[sha256sum] checksum from CSV file :\t\t\t%s\n[sha256sum] checksum from %s :\t", checksum, filename);

    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        DWORD j = 0;
        char c1, c2, c3, c4;
        for (DWORD i = 0; i < cbHash; i++)
        {
            if (verbose)
                printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
            //printf("\n");
            c1 = checksum[j];
            c2 = checksum[j + 1];
            c3 = rgbDigits[rgbHash[i] >> 4];
            c4 = rgbDigits[rgbHash[i] & 0xf];
            //printf("\nrun %d (%c and %c) : %c and %c ", i,c1, c2, c3, c4);
            if (c1 == c3 && c2 == c4) {
                //printf(" equals !");
                j += 2;
            }
            else {
                //printf(" not equal !");
                dwStatus = -1;
                return dwStatus;
            }
        }
    }
    else
    {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return dwStatus;
}

