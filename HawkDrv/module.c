#include "module.h"
#include "memory.h"
#include "process.h"
#include "..\common.h"
#include "HawkMain.h"
#include <ntifs.h>

static PVOID g_NtoskrnlBase = NULL;
static ULONG g_NtoskrnlSize = 0;

static BOOLEAN IsValidKernelModuleBase(PVOID imageBase)
{
	return ((ULONG_PTR)imageBase >= MIN_KERNEL_MODULE_BASE);
}

static BOOLEAN NormalizeModuleName(const char* sysName, char* nameBuffer, ULONG nameBufferSize)
{
	size_t nameLength;

	if (sysName == NULL || nameBuffer == NULL || nameBufferSize < 2)
	{
		return FALSE;
	}

	nameLength = strlen(sysName);
	if (nameLength == 0 || nameLength >= nameBufferSize)
	{
		return FALSE;
	}

	RtlZeroMemory(nameBuffer, nameBufferSize);
	RtlCopyMemory(nameBuffer, sysName, nameLength);
	_strlwr(nameBuffer);
	return TRUE;
}

static BOOLEAN MatchModuleName(const SYSTEM_MODULE* module, const char* sysNameLower)
{
	const char* moduleFileName;

	if (module == NULL || sysNameLower == NULL)
	{
		return FALSE;
	}

	if (module->ModuleNameOffset >= sizeof(module->ImageName))
	{
		return FALSE;
	}

	moduleFileName = module->ImageName + module->ModuleNameOffset;
	return (_stricmp(moduleFileName, sysNameLower) == 0);
}

static PSYSTEM_MODULE_INFORMATION QuerySystemModuleList(VOID)
{
	NTSTATUS status;
	ULONG bufferSize = 0;
	ULONG returnedSize = 0;
	PSYSTEM_MODULE_INFORMATION moduleList = NULL;

	status = ZwQuerySystemInformation(
		HawkSystemModuleInformation,
		NULL,
		0,
		&bufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH || bufferSize == 0)
	{
		return NULL;
	}

	moduleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(
		NonPagedPool,
		bufferSize,
		HAWK_POOL_TAG);
	if (moduleList == NULL)
	{
		return NULL;
	}

	status = ZwQuerySystemInformation(
		HawkSystemModuleInformation,
		moduleList,
		bufferSize,
		&returnedSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(moduleList, HAWK_POOL_TAG);
		return NULL;
	}

	return moduleList;
}

PVOID HawkGetKernelModuleBase(const char* moduleName, PULONG moduleSize)
{
	PSYSTEM_MODULE_INFORMATION moduleList = NULL;
	PVOID moduleBase = NULL;
	char nameBuffer[MODULE_NAME_BUFFER_SIZE];
	ULONG moduleCount;
	ULONG index;

	if (!NormalizeModuleName(moduleName, nameBuffer, sizeof(nameBuffer)))
	{
		return NULL;
	}

	if (g_NtoskrnlBase != NULL && strcmp(nameBuffer, "ntoskrnl.exe") == 0)
	{
		if (moduleSize != NULL)
		{
			*moduleSize = g_NtoskrnlSize;
		}
		return g_NtoskrnlBase;
	}

	moduleList = QuerySystemModuleList();
	if (moduleList == NULL)
	{
		return NULL;
	}

	moduleCount = moduleList->NumberOfModules;
	if (moduleCount == 0 || moduleCount > MAX_SYSTEM_MODULE_COUNT)
	{
		ExFreePoolWithTag(moduleList, HAWK_POOL_TAG);
		return NULL;
	}

	for (index = 0; index < moduleCount; index++)
	{
		const SYSTEM_MODULE* module = &moduleList->Modules[index];

		if (!IsValidKernelModuleBase(module->Base))
		{
			moduleBase = NULL;
			break;
		}

		if (!MatchModuleName(module, nameBuffer))
		{
			continue;
		}

		moduleBase = module->Base;
		if (moduleSize != NULL)
		{
			*moduleSize = module->Size;
		}

		if (strcmp(nameBuffer, "ntoskrnl.exe") == 0)
		{
			g_NtoskrnlBase = moduleBase;
			g_NtoskrnlSize = module->Size;
		}
		break;
	}

	ExFreePoolWithTag(moduleList, HAWK_POOL_TAG);
	return moduleBase;
}


#ifndef MEM_IMAGE
#define MEM_IMAGE    0x1000000
#endif

#define HawkMemorySectionName  ((MEMORY_INFORMATION_CLASS)2)

VOID HawkIoctlGetProcessModulePathByAddress(PIRP Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	GET_MODULE_PATH* input = (GET_MODULE_PATH*)(Irp->AssociatedIrp.SystemBuffer);
	if (input)
	{
		HANDLE pid = (HANDLE)input->pid;
		DWORD64 va = input->va;

		if (pid == (HANDLE)4)
		{
			PSYSTEM_MODULE_INFORMATION moduleList = QuerySystemModuleList();
			if (moduleList != NULL)
			{
				SYSTEM_MODULE module;
				ULONG i;

				for (i = 0; i < moduleList->NumberOfModules; i++)
				{
					DWORD64 imageBase;

					RtlZeroMemory(input->path, sizeof(input->path));
					module = moduleList->Modules[i];
					imageBase = (DWORD64)module.Base;
					if (imageBase < MIN_KERNEL_MODULE_BASE)
					{
						break;
					}

					if (va >= imageBase && va < imageBase + module.Size)
					{
						UNICODE_STRING unicodePath = { 0 };
						ANSI_STRING ansiPath = { 0 };

						RtlInitAnsiString(&ansiPath, (PCSZ)module.ImageName);
						status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
						if (NT_SUCCESS(status) && unicodePath.Buffer)
						{
							RtlCopyMemory(input->path, unicodePath.Buffer, unicodePath.Length);
							RtlFreeUnicodeString(&unicodePath);
						}
						input->image = 1;
						break;
					}
				}
				ExFreePoolWithTag(moduleList, HAWK_POOL_TAG);
			}

			if (input->image == 0)
			{
				RtlCopyMemory(input->path, L"HEAP MEMORY", wcslen(L"HEAP MEMORY") * 2);
			}
		}
		else
		{
			HANDLE processHandle = HawkOpenProcessByPid(pid);
			if (processHandle)
			{
				MEMORY_BASIC_INFORMATION mbi = { 0 };
				status = ZwQueryVirtualMemory(
					processHandle,
					(PVOID)va,
					MemoryBasicInformation,
					&mbi,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL);
				if (NT_SUCCESS(status))
				{
					if (mbi.Type == MEM_IMAGE)
					{
						status = ZwQueryVirtualMemory(
							processHandle,
							(PVOID)va,
							HawkMemorySectionName,
							input->temp,
							sizeof(input->temp),
							NULL);
						if (NT_SUCCESS(status))
						{
							PUNICODE_STRING sectionName = (PUNICODE_STRING)input->temp;
							if (MmIsAddressValidEx(sectionName->Buffer))
							{
								RtlCopyMemory(input->path, sectionName->Buffer, sectionName->Length);
							}
						}
						input->image = 1;
					}
					else
					{
						RtlCopyMemory(input->path, L"HEAP MEMORY", wcslen(L"HEAP MEMORY") * 2);
					}
				}
				ZwClose(processHandle);
			}
		}
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = sizeof(GET_MODULE_PATH);
	HawkIoctlComplete(Irp, Irp->IoStatus.Status, (ULONG)Irp->IoStatus.Information);
}