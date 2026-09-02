#include "hwnd.h"
#include "module.h"
#include "memory.h"
#include "..\common.h"
#include "HawkMain.h"

typedef struct _TAG_WND
{
	DWORD64 hWnd;
	UINT64 windowCount;
	struct Win32Thread* pWin32Thread;
	char padding_1[0x10];
	struct WindowStyle* windowStyle;
	UINT64 userCopyHeapOffset;
	char padding_2[0x20];
	struct _TAG_WND* next;
	struct _TAG_WND* previous;
	struct _TAG_WND* parent;
	struct _TAG_WND* child;
	char padding_3[0x40];
	PWCH* windowName;
	char padding_4[0x8];
	struct _TAG_WND* self;
} TAG_WND, *PTAG_WND;

typedef PVOID(NTAPI* VALIDATEHWND)(
	DWORD64 hwnd
	);

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID BaseOfImage,
	_In_ PCSTR RoutineName
);

static BOOLEAN g_ValidateHwndInitialized = FALSE;
static BOOLEAN g_SectionMTypeInitialized = FALSE;
static VALIDATEHWND g_ValidateHwnd = NULL;

static VOID InitializeValidateHwnd(VOID)
{
	PVOID win32kBase;

	if (g_ValidateHwndInitialized)
	{
		return;
	}

	g_ValidateHwndInitialized = TRUE;
	win32kBase = HawkGetKernelModuleBase("win32kbase.sys", NULL);
	if (!MmIsAddressValidEx(win32kBase))
	{
		return;
	}

	g_ValidateHwnd = (VALIDATEHWND)RtlFindExportedRoutineByName(win32kBase, "ValidateHwnd");
}

VOID HawkIoctlCheckValidHwnd(PIRP Irp)
{
	CHECK_VALID_HWND* msg = (CHECK_VALID_HWND*)(Irp->AssociatedIrp.SystemBuffer);
	CHECK_VALID_HWND local = { 0 };
	PTAG_WND tagWnd = NULL;

	if (msg == NULL)
	{
		goto Complete;
	}

	local.hwnd = msg->hwnd;
	InitializeValidateHwnd();

	if (!MmIsAddressValidEx((PVOID)g_ValidateHwnd))
	{
		local.errCode = 2;
		goto CopyOut;
	}

	tagWnd = (PTAG_WND)g_ValidateHwnd((DWORD64)local.hwnd);
	if (MmIsAddressValidEx(tagWnd))
	{
		local.isValid = 1;
		local.tagWnd = (DWORD64)tagWnd;
	}

	local.errCode = 1;

CopyOut:
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &local, sizeof(CHECK_VALID_HWND));

Complete:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(CHECK_VALID_HWND);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}



VOID HawkInitSectionMType(VOID)
{
	PTAG_WND tagWnd = NULL;

	if (g_SectionMTypeInitialized)
	{
		return;
	}

	g_SectionMTypeInitialized = TRUE;

	InitializeValidateHwnd();
	if (MmIsAddressValidEx((PVOID)g_ValidateHwnd) && g_MiGetSystemRegionType)
	{
		for (ULONG hwnd = 0x10000; hwnd < 0x10020; hwnd += 4)
		{
			__try {
				tagWnd = (PTAG_WND)g_ValidateHwnd((DWORD64)hwnd);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				tagWnd = NULL;
			}
			if (MmIsAddressValidEx(tagWnd))
			{
				g_SectionMType = g_MiGetSystemRegionType((DWORD64)tagWnd);
				DBG_PRINT("g_SectionMType: %d", g_SectionMType);
				break;
			}
		}
	}
}
