#pragma once


#include <Windows.h>
#include "common.h"

VOID InstallHawkDrv();
VOID UninstallHawkDrv();
bool TestDrv();

enum DrvStartFailReason
{
	DrvStartOk = 0,
	DrvStartFailGeneric,
	DrvStartFailSignature,
	DrvStartFailKernelLayout,
};
DrvStartFailReason InstallHawkDrvWithReason();
DrvStartFailReason GetLastDriverStartFailReason();
const char* GetLastDriverCompatRef();
DWORD GetLastDriverStartError();

VOID GetKernelVaRegion(KERNEL_VA_REGION* in, KERNEL_VA_REGION* out);
VOID  GetVirtualAddressPte(GET_VIRTUAL_ADDRESS_PTE* inout);
VOID GetVirtualAddressPfn(GET_VIRTUAL_ADDRESS_PFN* inout);
VOID OpenProcessHandle(OPEN_PROCESS_HANDLE* inout);
VOID ReadProcessPage(READ_MEMORY_PAGES* in, READ_MEMORY_PAGES* out);
VOID GetModulePathByPid(GET_MODULE_PATH* inout);
VOID  CheckValidHwnd(CHECK_VALID_HWND* inout);
VOID IGuardPitScan(IGUARD_PIT_SCAN* inout);

DWORD EnableTestSigning(LPWSTR outLogBuf, DWORD outLogBufChars);
DWORD DisableTestSigning(LPWSTR outLogBuf, DWORD outLogBufChars);
bool IsRunningAsAdmin();
bool IsSecureBootEnabled();
bool TestSigningBcdEnabled();
void SetHawkeyeInstanceMutex(HANDLE mutex);
bool RestartHawkeyeAsAdministrator();