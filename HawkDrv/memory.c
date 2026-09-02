#include "memory.h"
#include "utils.h"
#include "feature.h"
#include "..\common.h"
#include "module.h"
#include "process.h"
#include "HawkMain.h"
#include <ntifs.h>

DWORD64 g_PteMType = 4;
DWORD64 g_PfnMType = 4;
DWORD64 g_ImageMType = 12;
DWORD64 g_StackMType = 14;
DWORD64 g_SectionMType = 1;
DWORD64 g_UnusedMType = 0;
DWORD64 g_NonpagedMType = 5;
DWORD64 g_PagedMType = 6;
DWORD64 g_SystemMType = 9;
DWORD64 g_SpecialPoolPagedMType = 7;

static BOOLEAN g_TriedMiGetSystemRegionType = FALSE;
MiGetSystemRegionType g_MiGetSystemRegionType = NULL;

UINT64 g_PteBase = 0ull;
UINT64 g_PfnBase = 0ull;
static BOOLEAN g_GotPfnMType = FALSE;
static BOOLEAN g_GotPteMType = FALSE;


#define HAWK_LAYOUT_SCAN_WINDOW  0x100

BOOLEAN MmIsAddressValidEx(PVOID Address)
{
	return (Address != NULL && MmIsAddressValid(Address));
}

static BOOLEAN IsWindows10OrLater(VOID)
{
	RTL_OSVERSIONINFOW versionInfo;

	RtlZeroMemory(&versionInfo, sizeof(versionInfo));
	versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
	if (!NT_SUCCESS(RtlGetVersion(&versionInfo)))
	{
		return FALSE;
	}

	return (versionInfo.dwMajorVersion >= 10);
}

static VOID ProbeMemoryRegionTypes(VOID)
{
	ULONG stackMark = 0;
	PHYSICAL_ADDRESS maxPhysical;
	UINT64* systemBuffer = NULL;
	PVOID nonPagedBuffer = NULL;
	PVOID pagedBuffer = NULL;

	if (g_MiGetSystemRegionType == NULL)
	{
		return;
	}

	if (g_HawkImageBase != 0)
	{
		g_ImageMType = g_MiGetSystemRegionType(g_HawkImageBase);
		DBG_PRINT("g_ImageMType: %d", g_ImageMType);
	}

	maxPhysical.QuadPart = MAXULONG64;
	systemBuffer = (UINT64*)MmAllocateContiguousMemory(PAGE_SIZE, maxPhysical);
	if (systemBuffer != NULL)
	{
		g_SystemMType = g_MiGetSystemRegionType((DWORD64)systemBuffer);
		DBG_PRINT("g_SystemMType: %d", g_SystemMType);

		PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)systemBuffer);
		if (pa.QuadPart)
		{
			PVOID  va = MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
			if (va)
			{
				g_SpecialPoolPagedMType = g_MiGetSystemRegionType((DWORD64)va);
				DBG_PRINT("g_SpecialPoolPagedMType: %d", g_SpecialPoolPagedMType);
				MmUnmapIoSpace(va, PAGE_SIZE);
			}
		}
		MmFreeContiguousMemory(systemBuffer);
	}

	nonPagedBuffer = ExAllocatePoolWithTag(NonPagedPool, 32, HAWK_POOL_TAG);
	if (nonPagedBuffer != NULL)
	{
		g_NonpagedMType = g_MiGetSystemRegionType((DWORD64)nonPagedBuffer);
		DBG_PRINT("g_NonpagedMType: %d", g_NonpagedMType);
		ExFreePoolWithTag(nonPagedBuffer, HAWK_POOL_TAG);
	}

	pagedBuffer = ExAllocatePoolWithTag(PagedPool, 32, HAWK_POOL_TAG);
	if (pagedBuffer != NULL)
	{
		g_PagedMType = g_MiGetSystemRegionType((DWORD64)pagedBuffer);
		DBG_PRINT("g_PagedMType: %d", g_PagedMType);
		ExFreePoolWithTag(pagedBuffer, HAWK_POOL_TAG);
	}

	g_StackMType = g_MiGetSystemRegionType((DWORD64)&stackMark);
	DBG_PRINT("g_StackMType: %d", g_StackMType);
}

static BOOLEAN ResolveMiGetSystemRegionType(VOID)
{
	static const CHAR kPattern[] =
		"8D 81 00 FF FF FF 48 8D 0D ?? ?? ?? ?? 0F B6 04 08 C3";
	const UCHAR* match;

	match = (const UCHAR*)HawkFindPatternInModule("ntoskrnl.exe", ".text", kPattern);
	if (match == NULL)
	{
		return FALSE;
	}

	if (*(match - 18) == 0x80 && *(match - 17) == 0xFF && *(match - 25) == 0x48)
	{
		g_MiGetSystemRegionType = (MiGetSystemRegionType)(match - 25);
	}
	else if (*(match - 22) == 0x80 && *(match - 21) == 0xFF && *(match - 29) == 0x48)
	{
		g_MiGetSystemRegionType = (MiGetSystemRegionType)(match - 29);
	}

	return (g_MiGetSystemRegionType != NULL);
}

VOID HawkResolveSystemRegionType(VOID)
{
	if (g_TriedMiGetSystemRegionType)
	{
		return;
	}

	g_TriedMiGetSystemRegionType = TRUE;

	if (!ResolveMiGetSystemRegionType())
	{
		return;
	}

	DBG_PRINT("MiGetSystemRegionType: 0x%I64x", (DWORD64)g_MiGetSystemRegionType);
	ProbeMemoryRegionTypes();
}

static BOOLEAN TryResolvePfnAndPteBase(VOID)
{
	static const CHAR kPfnPattern[] =
		"48 8B C1 48 C1 E8 0C 48 8D 14 40 48 03 D2 48 B8 ?? ?? ?? ?? ?? ?? ?? ??";
	static const CHAR kPtePattern[] =
		"48 8B 04 D0 48 C1 E0 19 48 BA ?? ?? ?? ?? ?? ?? ?? ??";
	const UCHAR* start;
	const UCHAR* pfnHit;
	const UCHAR* pteHit;

	if (g_PfnBase != 0ull && g_PteBase != 0ull)
	{
		return TRUE;
	}

	if (!IsWindows10OrLater())
	{
		return FALSE;
	}

	start = (const UCHAR*)MmGetVirtualForPhysical;
	if (!MmIsAddressValidEx((PVOID)start))
	{
		return FALSE;
	}

	pfnHit = HawkFindPattern(start, HAWK_LAYOUT_SCAN_WINDOW, kPfnPattern);
	if (pfnHit != NULL)
	{
		UINT64 pfnImm = 0;
		if (HawkReadMatchU64(pfnHit, 16, &pfnImm))
		{
			g_PfnBase = pfnImm - 8;
		}
	}

	pteHit = HawkFindPattern(start, HAWK_LAYOUT_SCAN_WINDOW, kPtePattern);
	if (pteHit != NULL)
	{
		UINT64 pteImm = 0;
		if (HawkReadMatchU64(pteHit, 10, &pteImm))
		{
			g_PteBase = pteImm;
		}
	}

	return (g_PfnBase != 0ull);
}

VOID HawkResolvePfnBase(VOID)
{
	if (g_PfnBase == 0ull)
	{
		TryResolvePfnAndPteBase();
	}

	if (g_PfnBase != 0ull && g_MiGetSystemRegionType != NULL && !g_GotPfnMType)
	{
		g_PfnMType = g_MiGetSystemRegionType(g_PfnBase);
		DBG_PRINT("g_PfnMType: %d", g_PfnMType);
		g_GotPfnMType = TRUE;
	}
}

VOID HawkResolvePteBase(VOID)
{
	if (g_PteBase == 0ull)
	{
		TryResolvePfnAndPteBase();
	}

	if (g_PteBase != 0ull && g_MiGetSystemRegionType != NULL && !g_GotPteMType)
	{
		g_PteMType = g_MiGetSystemRegionType(g_PteBase);
		DBG_PRINT("g_PteMType: %d", g_PteMType);
		g_GotPteMType = TRUE;
	}
}


static VOID FillKernelMTypeFields(PKERNEL_VA_REGION out)
{
	if (out == NULL)
	{
		return;
	}

	out->pteMType = g_PteMType;
	out->pfnMType = g_PfnMType;
	out->imageMType = g_ImageMType;
	out->stackMType = g_StackMType;
	out->sectionMType = g_SectionMType;
	out->unusedMType = g_UnusedMType;
	out->nonpagedMType = g_NonpagedMType;
	out->pagedMType = g_PagedMType;
	out->systemMType = g_SystemMType;
	out->specialPoolPagedMType = g_SpecialPoolPagedMType;
}

VOID HawkIoctlGetKernelVaRegion(PIRP Irp)
{
	KERNEL_VA_REGION out = { 0 };

	KERNEL_VA_REGION* input = (KERNEL_VA_REGION*)(Irp->AssociatedIrp.SystemBuffer);
	if (input)
	{
		FillKernelMTypeFields(&out);

		if (input->va > 0xFFFF000000000000)
		{
			DWORD64 regionType;

			out.va = input->va;
			regionType = g_MiGetSystemRegionType(input->va);
			out.regionValue = (ULONG)regionType;

			if (regionType == g_ImageMType) { out.mRegion = 12; }
			else if (regionType == g_SystemMType) { out.mRegion = 9; }
			else if (regionType == g_NonpagedMType) { out.mRegion = 5; }
			else if (regionType == g_PagedMType) { out.mRegion = 6; }
			else if (regionType == g_StackMType) { out.mRegion = 14; }
			else if (regionType == g_PteMType) { out.mRegion = 4; }
			else if (regionType == g_PfnMType) { out.mRegion = 4; }
			else if (regionType == g_SectionMType) { out.mRegion = 1; }
			else if (regionType == g_SpecialPoolPagedMType) { out.mRegion = 7; }
			else { out.mRegion = 0; }
		}
	}

	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &out, sizeof(KERNEL_VA_REGION));
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(KERNEL_VA_REGION);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}


#define PTE_PFN_MASK             0xFFFFFFFFFull

static BOOLEAN LookupVaPte(
	ULONG pid,
	DWORD64 va,
	DWORD64* outData,
	PDWORD64 entryAddress,
	PUCHAR entryType)
{
	PEPROCESS pProcess = NULL;
	KAPC_STATE apcState;
	BOOLEAN attached = FALSE;
	ULONG64 pteVa = 0;
	ULONG64* pdeVa = NULL;
	BOOLEAN ok = FALSE;

	if (outData == NULL || entryType == NULL)
	{
		return FALSE;
	}

	*outData = 0;
	*entryType = 0;
	if (entryAddress != NULL)
	{
		*entryAddress = 0;
	}

	if (pid == 4)
	{
		if (va <= READ_PAGE_KERNEL_VA_MIN)
		{
			return FALSE;
		}
	}
	else if (pid > 4)
	{
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pProcess)))
		{
			return FALSE;
		}

		KeStackAttachProcess((PRKPROCESS)pProcess, &apcState);
		attached = TRUE;
	}
	else
	{
		return FALSE;
	}

	pteVa = (ULONG64)va & PA_MASK;
	pteVa = ((pteVa >> 12) << 3) + g_PteBase;
	pdeVa = (ULONG64*)(g_PteBase + ((((ULONG64)pteVa & PA_MASK) >> 12) << 3));

	if (MmIsAddressValidEx((PVOID)pteVa))
	{
		*outData = *(ULONG64*)pteVa;
		*entryType = VA_PTE_ENTRY_TYPE_PTE;
		if (entryAddress != NULL)
		{
			*entryAddress = pteVa;
		}
		ok = TRUE;
	}
	else if (MmIsAddressValidEx(pdeVa))
	{
		*outData = *pdeVa;
		*entryType = VA_PTE_ENTRY_TYPE_PDE;
		if (entryAddress != NULL)
		{
			*entryAddress = (DWORD64)pdeVa;
		}
		ok = TRUE;
	}

	if (attached)
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pProcess);
	}
	return ok;
}

#define KERNEL_READ_PTE_PA_MASK       0x0000FFFFFFFFF000ull
#define KERNEL_READ_PTE_PRESENT       0x1ull
#define KERNEL_READ_PTE_LARGE_PAGE    0x80ull
#define KERNEL_READ_LARGE_PAGE_MASK   0x000FFFFFFFE00000ull
#define KERNEL_READ_LARGE_PAGE_OFFSET 0x1FFFFFull

static BOOLEAN GetKernelPagePhysicalAddress(
	ULONG pid,
	DWORD64 va,
	PULONG64 physicalAddressOut)
{
	DWORD64 entryData = 0;
	UCHAR entryType = 0;

	if (physicalAddressOut == NULL || g_PteBase == 0)
	{
		return FALSE;
	}

	if (!LookupVaPte(pid, va, &entryData, NULL, &entryType))
	{
		return FALSE;
	}

	if ((entryData & KERNEL_READ_PTE_PRESENT) == 0)
	{
		return FALSE;
	}

	if (entryType == VA_PTE_ENTRY_TYPE_PDE || (entryData & KERNEL_READ_PTE_LARGE_PAGE) != 0)
	{
		*physicalAddressOut =
			(entryData & KERNEL_READ_LARGE_PAGE_MASK) + (va & KERNEL_READ_LARGE_PAGE_OFFSET);
		return TRUE;
	}

	*physicalAddressOut = (entryData & KERNEL_READ_PTE_PA_MASK) + (va & 0xFFFull);
	return TRUE;
}

VOID HawkIoctlGetVirtualAddressPte(PIRP Irp)
{
	GET_VIRTUAL_ADDRESS_PTE* inout = (GET_VIRTUAL_ADDRESS_PTE*)(Irp->AssociatedIrp.SystemBuffer);
	DWORD64 pteData = 0;
	DWORD64 entryAddress = 0;
	UCHAR entryType = 0;

	if (inout == NULL)
	{
		goto Complete;
	}

	inout->pteData = 0;
	inout->entryAddress = 0;
	inout->entryType = 0;
	inout->errCode = 0;

	if (g_PteBase == 0)
	{
		inout->errCode = 2;
		goto Complete;
	}

	if (LookupVaPte(inout->pid, inout->va, &pteData, &entryAddress, &entryType))
	{
		inout->pteData = pteData;
		inout->entryAddress = entryAddress;
		inout->entryType = entryType;
		inout->errCode = 1;
	}

Complete:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(GET_VIRTUAL_ADDRESS_PTE);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}

static BOOLEAN GetPfnFromPteData(
	DWORD64 pteData,
	PULONG64 pfnNumber,
	PDWORD64 pfnEntryAddress,
	PUCHAR pfnBuffer)
{
	ULONG64 pfnIndex = 0;
	PVOID pfnEntry = NULL;

	if (pfnNumber == NULL || g_PfnBase == 0)
	{
		return FALSE;
	}

	*pfnNumber = 0;
	if (pfnEntryAddress != NULL)
	{
		*pfnEntryAddress = 0;
	}
	if (pfnBuffer != NULL)
	{
		RtlZeroMemory(pfnBuffer, VA_PFN_DATA_SIZE);
	}

	if ((pteData & 0x1ull) == 0)
	{
		return FALSE;
	}

	pfnIndex = (pteData >> 12) & PTE_PFN_MASK;
	pfnEntry = (PVOID)(g_PfnBase + (VA_PFN_DATA_SIZE * pfnIndex));
	if (!MmIsAddressValidEx(pfnEntry))
	{
		return FALSE;
	}

	if (pfnBuffer != NULL)
	{
		RtlCopyMemory(pfnBuffer, pfnEntry, VA_PFN_DATA_SIZE);
	}
	*pfnNumber = pfnIndex;
	if (pfnEntryAddress != NULL)
	{
		*pfnEntryAddress = (DWORD64)pfnEntry;
	}
	return TRUE;
}

VOID HawkIoctlGetVirtualAddressPfn(PIRP Irp)
{
	GET_VIRTUAL_ADDRESS_PFN* inout = (GET_VIRTUAL_ADDRESS_PFN*)(Irp->AssociatedIrp.SystemBuffer);
	DWORD64 pteData = 0;
	DWORD64 entryAddress = 0;
	DWORD64 pfnEntryAddress = 0;
	ULONG64 pfnNumber = 0;
	UCHAR entryType = 0;

	if (inout == NULL)
	{
		goto Complete;
	}

	inout->pteData = 0;
	inout->entryAddress = 0;
	inout->pfnNumber = 0;
	inout->pfnEntryAddress = 0;
	inout->entryType = 0;
	inout->errCode = VA_PFN_ERR_NONE;
	RtlZeroMemory(inout->pfnData, sizeof(inout->pfnData));

	if (g_PteBase == 0 || g_PfnBase == 0)
	{
		inout->errCode = VA_PFN_ERR_BASE_UNAVAILABLE;
		goto Complete;
	}

	if (inout->pid < 4)
	{
		goto Complete;
	}

	if (!LookupVaPte(inout->pid, inout->va, &pteData, &entryAddress, &entryType))
	{
		inout->errCode = VA_PFN_ERR_PTE_NOT_FOUND;
		goto Complete;
	}

	inout->pteData = pteData;
	inout->entryAddress = entryAddress;
	inout->entryType = entryType;

	if ((pteData & 0x1ull) == 0)
	{
		inout->errCode = VA_PFN_ERR_PTE_INVALID;
		goto Complete;
	}

	if (!GetPfnFromPteData(pteData, &pfnNumber, &pfnEntryAddress, inout->pfnData))
	{
		inout->errCode = VA_PFN_ERR_PFN_READ_FAILED;
		goto Complete;
	}

	inout->pfnNumber = pfnNumber;
	inout->pfnEntryAddress = pfnEntryAddress;
	inout->errCode = VA_PFN_ERR_SUCCESS;

Complete:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(GET_VIRTUAL_ADDRESS_PFN);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}


static BOOLEAN ReadKernelPage(
	ULONG pid,
	PVOID pageAlignedVa,
	UCHAR readMethod,
	PUCHAR outPage,
	PULONG bytesGot,
	PUCHAR errStep,
	PLONG outStatus);

VOID HawkIoctlReadProcessPages(PIRP Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	READ_MEMORY_PAGES* input = (READ_MEMORY_PAGES*)(Irp->AssociatedIrp.SystemBuffer);
	if (input)
	{
		HANDLE pid = (HANDLE)input->pid;
		DWORD64  va = input->va;

	READ_MEMORY_PAGES* output = ExAllocatePoolWithTag(NonPagedPool, sizeof(READ_MEMORY_PAGES), HAWK_POOL_TAG);
		if (output)
		{
			RtlZeroMemory(output, sizeof(READ_MEMORY_PAGES));
			output->pid = input->pid;
			output->va = input->va;
			output->readMethod = input->readMethod;

			if (pid == (HANDLE)4)
			{
				if (va > READ_PAGE_KERNEL_VA_MIN)
				{
					PVOID addrWithPageAlign = (PVOID)(va & 0xFFFFFFFFFFFFF000);

					ReadKernelPage(
						(ULONG)input->pid,
						addrWithPageAlign,
						input->readMethod,
						output->page,
						&output->bytesRead,
						&output->errStep,
						&output->status);
				}
				else
				{
					output->errStep = READ_PAGE_ERR_VA_RANGE;
				}
			}
			else
			{
				PEPROCESS ep = NULL;

				status = PsLookupProcessByProcessId(pid, &ep);
				if (!NT_SUCCESS(status))
				{
					output->errStep = READ_PAGE_ERR_LOOKUP_FAILED;
				}
				else
				{
					KAPC_STATE apcState;

					KeStackAttachProcess((PRKPROCESS)ep, &apcState);

					if (va <= READ_PAGE_USER_VA_MAX)
					{
						__try
						{
							PVOID addrWithPageAlign = (PVOID)(va & 0xFFFFFFFFFFFFF000);

							RtlCopyMemory(output->page, addrWithPageAlign, PAGE_SIZE);
							output->bytesRead = PAGE_SIZE;
						}
						__except (EXCEPTION_EXECUTE_HANDLER)
						{
							output->errStep = READ_PAGE_ERR_USER_ACCESS;
						}
					}
					else if (va > READ_PAGE_KERNEL_VA_MIN)
					{
						PVOID addrWithPageAlign = (PVOID)(va & 0xFFFFFFFFFFFFF000);

						ReadKernelPage(
							(ULONG)input->pid,
							addrWithPageAlign,
							input->readMethod,
							output->page,
							&output->bytesRead,
							&output->errStep,
							&output->status);
					}
					else
					{
						output->errStep = READ_PAGE_ERR_VA_RANGE;
					}

					KeUnstackDetachProcess(&apcState);
					ObDereferenceObject(ep);
				}
			}

			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, output, sizeof(READ_MEMORY_PAGES));
			ExFreePoolWithTag(output, HAWK_POOL_TAG);
		}
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(READ_MEMORY_PAGES);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}


static BOOLEAN ReadPageViaPhysicalVa(
	PVOID pageAlignedVa,
	PUCHAR outPage,
	PULONG bytesGot,
	PUCHAR errStep,
	PLONG outStatus)
{
	PHYSICAL_ADDRESS phyAddr;
	MM_COPY_ADDRESS readSrc = { 0 };
	SIZE_T copied = 0;
	NTSTATUS copyStatus;

	if (!MmIsAddressValidEx(pageAlignedVa))
	{
		*errStep = READ_PAGE_ERR_PHYS_INVALID;
		return FALSE;
	}

	phyAddr = MmGetPhysicalAddress(pageAlignedVa);
	if (phyAddr.QuadPart == 0)
	{
		*errStep = READ_PAGE_ERR_PHYS_NO_PA;
		return FALSE;
	}

	readSrc.PhysicalAddress.QuadPart = phyAddr.QuadPart;
	copyStatus = MmCopyMemory(outPage, readSrc, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &copied);
	if (!NT_SUCCESS(copyStatus))
	{
		*errStep = READ_PAGE_ERR_PHYS_COPY;
		*outStatus = (LONG)copyStatus;
		return FALSE;
	}

	*bytesGot = PAGE_SIZE;
	return TRUE;
}

static BOOLEAN ReadPageViaMapIo(
	ULONG pid,
	PVOID pageAlignedVa,
	PUCHAR outPage,
	PULONG bytesGot,
	PUCHAR errStep,
	PLONG outStatus)
{
	ULONG64 physicalAddress = 0;
	PHYSICAL_ADDRESS phyAddr;
	PVOID mapVa = NULL;
	ULONG pageOffset = 0;

	UNREFERENCED_PARAMETER(outStatus);

	if (g_PteBase == 0)
	{
		*errStep = READ_PAGE_ERR_PTE_BASE;
		return FALSE;
	}

	if (!GetKernelPagePhysicalAddress(pid, (DWORD64)pageAlignedVa, &physicalAddress))
	{
		*errStep = READ_PAGE_ERR_PTE_INVALID;
		return FALSE;
	}

	pageOffset = (ULONG)(physicalAddress & 0xFFFull);
	phyAddr.QuadPart = physicalAddress & KERNEL_READ_PTE_PA_MASK;
	mapVa = MmMapIoSpaceEx(phyAddr, PAGE_SIZE, PAGE_READWRITE);
	if (mapVa == NULL)
	{
		*errStep = READ_PAGE_ERR_MAP_IO;
		return FALSE;
	}

	RtlCopyMemory(outPage, (PUCHAR)mapVa + pageOffset, PAGE_SIZE);
	MmUnmapIoSpace(mapVa, PAGE_SIZE);

	*bytesGot = PAGE_SIZE;
	return TRUE;
}

static BOOLEAN ReadKernelPage(
	ULONG pid,
	PVOID pageAlignedVa,
	UCHAR readMethod,
	PUCHAR outPage,
	PULONG bytesGot,
	PUCHAR errStep,
	PLONG outStatus)
{
	if (readMethod == READ_KERNEL_METHOD_PTE_REMAP)
	{
		*errStep = READ_PAGE_ERR_PTE_REMAP;
		return FALSE;
	}
	if (readMethod == READ_KERNEL_METHOD_MAP_IO)
	{
		return ReadPageViaMapIo(pid, pageAlignedVa, outPage, bytesGot, errStep, outStatus);
	}
	return ReadPageViaPhysicalVa(pageAlignedVa, outPage, bytesGot, errStep, outStatus);
}
