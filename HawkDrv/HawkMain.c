#include "HawkMain.h"
#include "..\common.h"
#include "process.h"
#include "memory.h"
#include "module.h"
#include "hwnd.h"
#include "hook.h"

PDEVICE_OBJECT g_HawkDevice = NULL;
DWORD64 g_HawkImageBase = 0;

NTSTATUS HawkCompleteUnusedIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

VOID HawkIoctlComplete(PIRP Irp, NTSTATUS status, ULONG information)
{
	if (Irp == NULL) {
		return;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG index = 0;

	g_HawkImageBase = (DWORD64)DriverObject->DriverStart;

	HawkResolveSystemRegionType();
	HawkResolvePteBase();
	HawkResolvePfnBase();
	if (g_MiGetSystemRegionType == NULL)
	{
		DBG_PRINT("DriverEntry: MiGetSystemRegionType unavailable on this OS build");
		return STATUS_HAWK_NO_MIGETSYSTEMREGION;
	}
	if (g_PteBase == 0)
	{
		DBG_PRINT("DriverEntry: PTE base unavailable on this OS build");
		return STATUS_HAWK_NO_PTE_BASE;
	}
	if (g_PfnBase == 0)
	{
		DBG_PRINT("DriverEntry: PFN base unavailable on this OS build");
		return STATUS_HAWK_NO_PFN_BASE;
	}

	for (index = 0; index < IRP_MJ_MAXIMUM_FUNCTION; ++index) {
		DriverObject->MajorFunction[index] = HawkCompleteUnusedIrp;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HawkDispatchDeviceControl;
	status = CreateHawkDevice(DriverObject);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	DriverObject->DriverUnload = HawkDriverUnload;
	return STATUS_SUCCESS;
}

VOID HawkDriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (g_HawkDevice)
	{
		UNICODE_STRING symbolicLinkName;
		RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(g_HawkDevice);
		g_HawkDevice = NULL;
	}
}

NTSTATUS HawkCompleteUnusedIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS
HawkDispatchDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

	ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

	switch (controlCode)
	{
	case IOCTL_GET_KERNEL_VA_MEMORY_REGION:
	{
		if (inputLength != sizeof(KERNEL_VA_REGION) || outputLength != sizeof(KERNEL_VA_REGION))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkInitSectionMType();
		HawkIoctlGetKernelVaRegion(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_READ_PROCESS_PAGE:
	{
		if (inputLength != sizeof(READ_MEMORY_PAGES) || outputLength != sizeof(READ_MEMORY_PAGES))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlReadProcessPages(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_GET_MODULE_PATH_BY_PID:
	{
		if (inputLength != sizeof(GET_MODULE_PATH) || outputLength != sizeof(GET_MODULE_PATH))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlGetProcessModulePathByAddress(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_CHECK_VALID_HWND:
	{
		if (inputLength != sizeof(CHECK_VALID_HWND) || outputLength != sizeof(CHECK_VALID_HWND))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlCheckValidHwnd(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_IGUARD_PIT_SCAN:
	{
		if (inputLength != sizeof(IGUARD_PIT_SCAN) || outputLength != sizeof(IGUARD_PIT_SCAN))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlIGuardPitScan(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_GET_VIRTUAL_ADDRESS_PTE:
	{
		if (inputLength != sizeof(GET_VIRTUAL_ADDRESS_PTE) || outputLength != sizeof(GET_VIRTUAL_ADDRESS_PTE))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlGetVirtualAddressPte(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_GET_VIRTUAL_ADDRESS_PFN:
	{
		if (inputLength != sizeof(GET_VIRTUAL_ADDRESS_PFN) || outputLength != sizeof(GET_VIRTUAL_ADDRESS_PFN))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlGetVirtualAddressPfn(Irp);
		return STATUS_SUCCESS;
	}

	case IOCTL_OPEN_PROCESS_HANDLE:
	{
		if (inputLength != sizeof(OPEN_PROCESS_HANDLE) || outputLength != sizeof(OPEN_PROCESS_HANDLE))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		HawkIoctlOpenProcessHandle(Irp);
		return STATUS_SUCCESS;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	HawkIoctlComplete(Irp, status, 0);
	return status;
}

NTSTATUS CreateHawkDevice(_In_ PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName = { 0 };
	UNICODE_STRING symbolicLinkName = { 0 };
	PDEVICE_OBJECT DeviceObject;

	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	status = IoCreateDevice(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
		);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
	}
	else {
		g_HawkDevice = DeviceObject;
		g_HawkDevice->Flags |= DO_BUFFERED_IO;
		g_HawkDevice->Flags &= ~DO_DEVICE_INITIALIZING;
	}
	return status;
}
