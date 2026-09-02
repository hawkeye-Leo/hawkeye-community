#pragma once

#include <ntstrsafe.h>
#include <intrin.h>

#if DBG
#define DBG_PRINT(x, ...)   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, x##"\n", __VA_ARGS__)
#else
#define DBG_PRINT(x, ...)
#endif

#define HAWK_POOL_TAG       'kawH'
#define PA_MASK             0x0000fffffffff000
#define MAX_USER_ADDRESS    0x7fffffffffffull

typedef struct _SYSTEM_MODULE
{
    ULONG_PTR Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
