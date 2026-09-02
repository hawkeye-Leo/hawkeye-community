#pragma once

#include <ntddk.h>

#define READ_PAGE_USER_VA_MAX    0x7FFFFFFFFFFFULL
#define READ_PAGE_KERNEL_VA_MIN  0xFFFF000000000000ULL

typedef DWORD64(NTAPI* MiGetSystemRegionType)(DWORD64 Page);

BOOLEAN MmIsAddressValidEx(PVOID Address);

VOID HawkResolveSystemRegionType(VOID);
VOID HawkResolvePfnBase(VOID);
VOID HawkResolvePteBase(VOID);

extern DWORD64 g_PteMType;
extern DWORD64 g_PfnMType;
extern DWORD64 g_ImageMType;
extern DWORD64 g_StackMType;
extern DWORD64 g_SectionMType;
extern DWORD64 g_UnusedMType;
extern DWORD64 g_NonpagedMType;
extern DWORD64 g_PagedMType;
extern DWORD64 g_SystemMType;
extern DWORD64 g_SpecialPoolPagedMType;

extern MiGetSystemRegionType g_MiGetSystemRegionType;
extern UINT64 g_PteBase;
extern UINT64 g_PfnBase;

VOID HawkIoctlGetKernelVaRegion(PIRP Irp);
VOID HawkIoctlGetVirtualAddressPte(PIRP Irp);
VOID HawkIoctlGetVirtualAddressPfn(PIRP Irp);
VOID HawkIoctlReadProcessPages(PIRP Irp);
