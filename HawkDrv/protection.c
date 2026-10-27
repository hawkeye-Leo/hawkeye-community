#include "protection.h"

typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		} Flags;
	} u;
} PS_PROTECTION, *PPS_PROTECTION;

#define PsProtectedTypeProtectedLight 1
#define PsProtectedSignerAntimalware  3

#ifndef SeImageSignatureEmbedded
#define SeImageSignatureEmbedded 1
#endif

static ULONG g_ProtectionOffset = 0;
static ULONG g_SignatureLevelOffset = 0;

static NTSTATUS HawkFindProtectionOffset(void)
{
	UNICODE_STRING routineName;
	PUCHAR routine;
	ULONG offset;

	RtlInitUnicodeString(&routineName, L"PsGetProcessProtection");
	routine = (PUCHAR)MmGetSystemRoutineAddress(&routineName);
	if (routine == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	if (routine[0] == 0x8A && routine[1] == 0x81)
	{
		offset = *(PULONG)(routine + 2);
		g_ProtectionOffset = offset;
		g_SignatureLevelOffset = offset - (2 * sizeof(UCHAR));
		return STATUS_SUCCESS;
	}

	return STATUS_NOT_FOUND;
}

static NTSTATUS HawkEnsureProtectionOffsets(void)
{
	if (g_ProtectionOffset != 0 && g_SignatureLevelOffset != 0)
	{
		return STATUS_SUCCESS;
	}

	return HawkFindProtectionOffset();
}

static NTSTATUS HawkWriteProcessProtection(
	PEPROCESS process,
	UCHAR signatureLevel,
	UCHAR protectionLevel)
{
	PUCHAR eprocess;
	NTSTATUS status = STATUS_SUCCESS;

	eprocess = (PUCHAR)process;

	__try
	{
		*(PUCHAR)(eprocess + g_SignatureLevelOffset) = signatureLevel;
		*(PUCHAR)(eprocess + g_ProtectionOffset) = protectionLevel;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = STATUS_ACCESS_VIOLATION;
	}

	return status;
}

static NTSTATUS HawkSetProcessPpl(ULONG pid, BOOLEAN enable)
{
	NTSTATUS status;
	PEPROCESS process = NULL;
	UCHAR signatureLevel;
	UCHAR protectionLevel;

	status = HawkEnsureProtectionOffsets();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = PsLookupProcessByProcessId(UlongToHandle(pid), &process);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (enable)
	{
		signatureLevel = (UCHAR)((SeImageSignatureEmbedded << 4) | SE_SIGNING_LEVEL_ANTIMALWARE);
		protectionLevel = (UCHAR)((PsProtectedSignerAntimalware << 4) | PsProtectedTypeProtectedLight);
	}
	else
	{
		signatureLevel = 0;
		protectionLevel = 0;
	}

	status = HawkWriteProcessProtection(process, signatureLevel, protectionLevel);
	ObDereferenceObject(process);
	return status;
}

NTSTATUS HawkEnablePpl(_In_ ULONG Pid)
{
	if (Pid == 0 || Pid == 4)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return HawkSetProcessPpl(Pid, TRUE);
}

NTSTATUS HawkDisablePpl(_In_ ULONG Pid)
{
	if (Pid == 0 || Pid == 4)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return HawkSetProcessPpl(Pid, FALSE);
}
