#include "process.h"
#include "..\common.h"
#include "HawkMain.h"
#include <ntifs.h>

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ          0x0010
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

HANDLE HawkOpenProcessByPid(HANDLE pid)
{
	NTSTATUS  status = STATUS_SUCCESS;
	PEPROCESS process = NULL;
	HANDLE ProcessHandle = NULL;

	__try
	{
		status = PsLookupProcessByProcessId(pid, &process);
		if (NT_SUCCESS(status))
		{
			status = ObOpenObjectByPointer(process,
				0, NULL, 0, 0,
				KernelMode,
				&ProcessHandle);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_UNSUCCESSFUL;
	}

	if (process) {
		ObDereferenceObject(process);
	}
	return ProcessHandle;
}

static NTSTATUS DuplicateProcessHandleToRequestor(
	PIRP Irp,
	HANDLE targetPid,
	ACCESS_MASK desiredAccess,
	PHANDLE userProcessHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS targetProcess = NULL;
	PEPROCESS requestorProcess = NULL;
	HANDLE kernelTargetHandle = NULL;
	HANDLE requestorProcessHandle = NULL;
	HANDLE duplicatedHandle = NULL;

	if (Irp == NULL || userProcessHandle == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	*userProcessHandle = NULL;
	requestorProcess = IoGetRequestorProcess(Irp);
	if (requestorProcess == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = PsLookupProcessByProcessId(targetPid, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ObOpenObjectByPointer(
		targetProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		desiredAccess,
		*PsProcessType,
		KernelMode,
		&kernelTargetHandle);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(targetProcess);
		return status;
	}

	status = ObOpenObjectByPointer(
		requestorProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		PROCESS_DUP_HANDLE,
		*PsProcessType,
		KernelMode,
		&requestorProcessHandle);
	if (!NT_SUCCESS(status))
	{
		ZwClose(kernelTargetHandle);
		ObDereferenceObject(targetProcess);
		return status;
	}

	status = ZwDuplicateObject(
		NtCurrentProcess(),
		kernelTargetHandle,
		requestorProcessHandle,
		&duplicatedHandle,
		0,
		0,
		DUPLICATE_SAME_ACCESS);

	ZwClose(requestorProcessHandle);
	ZwClose(kernelTargetHandle);
	ObDereferenceObject(targetProcess);

	if (NT_SUCCESS(status))
	{
		*userProcessHandle = duplicatedHandle;
	}

	return status;
}

VOID HawkIoctlOpenProcessHandle(PIRP Irp)
{
	OPEN_PROCESS_HANDLE* input = (OPEN_PROCESS_HANDLE*)(Irp->AssociatedIrp.SystemBuffer);
	OPEN_PROCESS_HANDLE* output = (OPEN_PROCESS_HANDLE*)(Irp->AssociatedIrp.SystemBuffer);
	ACCESS_MASK desiredAccess = 0;
	HANDLE userHandle = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (input == NULL || output == NULL)
	{
		goto Complete;
	}

	output->processHandle = 0;
	output->errCode = 0;
	output->status = 0;

	if (input->pid == 0)
	{
		output->status = (LONG)STATUS_INVALID_PARAMETER;
		goto Complete;
	}

	desiredAccess = input->desiredAccess;
	if (desiredAccess == 0)
	{
		desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
	}

	status = DuplicateProcessHandleToRequestor(
		Irp,
		(HANDLE)(ULONG_PTR)input->pid,
		desiredAccess,
		&userHandle);

	output->status = (LONG)status;
	if (NT_SUCCESS(status) && userHandle != NULL)
	{
		output->processHandle = (ULONG64)(ULONG_PTR)userHandle;
		output->errCode = 1;
	}

Complete:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(OPEN_PROCESS_HANDLE);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}
