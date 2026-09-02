#pragma once

#include <ntddk.h>
#include "utils.h"

#define MIN_KERNEL_MODULE_BASE      0xFFFF000000000000ULL
#define HawkSystemModuleInformation 11u
#define MAX_SYSTEM_MODULE_COUNT     4096u
#define MODULE_NAME_BUFFER_SIZE     64u

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

PVOID HawkGetKernelModuleBase(const char* moduleName, PULONG moduleSize);

VOID HawkIoctlGetProcessModulePathByAddress(PIRP Irp);
