#include "hook.h"
#include "memory.h"
#include "module.h"
#include "..\common.h"
#include "HawkMain.h"
#include <ntimage.h>

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	_In_ PVOID Base
);

static BOOLEAN IsKernelCanonicalVa(DWORD64 va)
{
	return (va > 0xFFFF000000000000ULL);
}

static BOOLEAN MapRegionToMRegion(DWORD64 regionValue, PULONG outMRegion)
{
	if (regionValue == g_SystemMType)
	{
		if (outMRegion != NULL)
		{
			*outMRegion = 9;
		}
		return TRUE;
	}

	if (regionValue == g_NonpagedMType)
	{
		if (outMRegion != NULL)
		{
			*outMRegion = 5;
		}
		return TRUE;
	}

	if (regionValue == g_ImageMType)
	{
		if (outMRegion != NULL)
		{
			*outMRegion = 12;
		}
		return TRUE;
	}

	if (regionValue == g_PagedMType)
	{
		if (outMRegion != NULL)
		{
			*outMRegion = 6;
		}
		return TRUE;
	}

	return FALSE;
}

static BOOLEAN IsPresentAccessedExecutable(DWORD64 va)
{
	DWORD64 pteVa = va & PA_MASK;
	pteVa = ((pteVa >> 12) << 3) + g_PteBase;
	if (MmIsAddressValidEx((PVOID)pteVa))
	{
		DWORD64 pteData = *(ULONG64*)pteVa;
		if (pteData & 0x1 &&
			pteData & 0x20 &&
			(pteData & (UINT64)0x8000000000000000ull) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

static BOOLEAN IsPresentAccessedDirtyExecutable(DWORD64 va)
{
	DWORD64 pteVa = va & PA_MASK;
	pteVa = ((pteVa >> 12) << 3) + g_PteBase;
	if (MmIsAddressValidEx((PVOID)pteVa))
	{
		DWORD64 pteData = *(ULONG64*)pteVa;
		if (pteData & 0x1 &&
			pteData & 0x20 &&
			pteData & 0x800 &&
			(pteData & (UINT64)0x8000000000000000ull) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

static VOID RecordPitHit(
	IGUARD_PIT_SCAN* out,
	PULONG hitIndex,
	DWORD64 pitAddr,
	DWORD64 pitData,
	DWORD64 regionValue,
	ULONG mRegion)
{
	if (out == NULL || hitIndex == NULL)
	{
		return;
	}

	if (*hitIndex >= MAX_IGUARD_PIT_HITS)
	{
		out->errCode = 4;
		return;
	}

	out->hits[*hitIndex].pitAddr = pitAddr;
	out->hits[*hitIndex].pitData = pitData;
	out->hits[*hitIndex].mRegion = mRegion;
	out->hits[*hitIndex].regionValue = (ULONG)regionValue;
	(*hitIndex)++;
}

static VOID ScanSectionRange(
	PUCHAR sectionStart,
	ULONG sectionSize,
	IGUARD_PIT_SCAN* out,
	PULONG hitIndex)
{
	PUCHAR p;
	PUCHAR sectionEnd;

	if (sectionStart == NULL || sectionSize == 0 || out == NULL || hitIndex == NULL)
	{
		return;
	}

	sectionEnd = sectionStart + sectionSize;
	if (sectionEnd <= sectionStart)
	{
		return;
	}

	for (p = sectionStart; p + sizeof(DWORD64) <= sectionEnd; )
	{
		DWORD64 pitData;
		DWORD64 regionValue;
		ULONG mRegion;

		if (out->errCode == 4)
		{
			break;
		}

		if (!MmIsAddressValidEx(p))
		{
			DWORD64 nextPage = ((DWORD64)p & ~0xFFFULL) + PAGE_SIZE;
			if (nextPage <= (DWORD64)p)
			{
				break;
			}
			p = (PUCHAR)nextPage;
			continue;
		}

		pitData = *(DWORD64 UNALIGNED*)p;
		if (!IsKernelCanonicalVa(pitData))
		{
			p += 4;
			continue;
		}

		if (!MmIsAddressValidEx((PVOID)pitData))
		{
			p += 4;
			continue;
		}

		regionValue = g_MiGetSystemRegionType(pitData);
		if (!MapRegionToMRegion(regionValue, &mRegion))
		{
			p += 4;
			continue;
		}

		if (mRegion == 12)
		{
			if (!IsPresentAccessedDirtyExecutable(pitData))
			{
				p += 4;
				continue;
			}
		}
		else
		{
			if (!IsPresentAccessedExecutable(pitData))
			{
				p += 4;
				continue;
			}
		}

		RecordPitHit(out, hitIndex, (DWORD64)p, pitData, regionValue, mRegion);
		p += 4;
	}
}

static VOID ScanPeImageForPit(DWORD64 sysBase, IGUARD_PIT_SCAN* out)
{
	PIMAGE_NT_HEADERS64 ntHeaders;
	PIMAGE_SECTION_HEADER section;
	PUCHAR imageBase;
	USHORT sectionIndex;
	ULONG hitIndex = 0;

	out->sysBase = sysBase;
	out->sysEnd = 0;
	out->hitCount = 0;
	out->errCode = 0;

	if (!IsKernelCanonicalVa(sysBase) || !MmIsAddressValidEx((PVOID)sysBase))
	{
		out->errCode = 2;
		return;
	}

	imageBase = (PUCHAR)sysBase;
	if (*(PUSHORT)imageBase != IMAGE_DOS_SIGNATURE)
	{
		out->errCode = 3;
		return;
	}

	ntHeaders = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(imageBase);
	if (ntHeaders == NULL ||
		ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		out->errCode = 3;
		return;
	}

	out->sysEnd = sysBase + ntHeaders->OptionalHeader.SizeOfImage;
	section = IMAGE_FIRST_SECTION(ntHeaders);
	for (sectionIndex = 0; sectionIndex < ntHeaders->FileHeader.NumberOfSections; sectionIndex++)
	{
		PUCHAR sectionStart = imageBase + section[sectionIndex].VirtualAddress;
		ULONG sectionSize = section[sectionIndex].Misc.VirtualSize;

		ScanSectionRange(sectionStart, sectionSize, out, &hitIndex);
		if (out->errCode == 4)
		{
			break;
		}
	}

	out->hitCount = hitIndex;
	if (out->errCode == 0)
	{
		out->errCode = 1;
	}
}

VOID HawkIoctlIGuardPitScan(PIRP Irp)
{
	IGUARD_PIT_SCAN* input = (IGUARD_PIT_SCAN*)(Irp->AssociatedIrp.SystemBuffer);
	IGUARD_PIT_SCAN* output = (IGUARD_PIT_SCAN*)(Irp->AssociatedIrp.SystemBuffer);
	DWORD64 sysBase = 0;

	sysBase = input->sysBase;
	ScanPeImageForPit(sysBase, output);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(IGUARD_PIT_SCAN);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}
