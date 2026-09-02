#pragma once

#include <ntddk.h>

#define DEVICE_NAME              L"\\Device\\hawkeye123"
#define SYMBOLIC_LINK_NAME       L"\\DosDevices\\hawkeye123"

extern DWORD64 g_HawkImageBase;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD HawkDriverUnload;

NTSTATUS CreateHawkDevice(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS HawkDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
VOID HawkIoctlComplete(PIRP Irp, NTSTATUS status, ULONG information);
