#pragma once

#include <Windows.h>

LPTSTR GetNtoskrnlPath();

void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename);

LPTSTR GetNtoskrnlVersion();

LPTSTR GetWdigestVersion();

#define BUFSIZE 1024
#define SHA256LEN  64
DWORD sha256sum(LPCWSTR filename, TCHAR* checksum);