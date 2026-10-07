#include "usermode_callback.h"
#include "utils.h"
#include "memory.h"
#include <ntifs.h>

#define HAWK_MSR_SYSCALL_ENTRY          0xC0000082UL

ULONG64 g_HawkAsmKvaShadow = 0;
ULONG64 g_HawkAsmStackGsOffset = 8;

static PVOID HawkAllocateKernelStackTop(VOID)
{
	PVOID allocation = NULL;
	PVOID stackTop = NULL;
	SIZE_T totalSize = HAWK_KERNEL_STACK_SIZE + PAGE_SIZE;

	allocation = ExAllocatePoolWithTag(NonPagedPool, totalSize, HAWK_POOL_TAG);
	if (allocation == NULL)
	{
		return NULL;
	}

	RtlZeroMemory(allocation, totalSize);
	stackTop = (PVOID)((ULONG_PTR)allocation + totalSize);
	return stackTop;
}

static VOID HawkFreeKernelStackTop(_In_opt_ PVOID StackTop)
{
	if (StackTop == NULL)
	{
		return;
	}

	ExFreePoolWithTag(
		(PVOID)((ULONG_PTR)StackTop - (HAWK_KERNEL_STACK_SIZE + PAGE_SIZE)),
		HAWK_POOL_TAG);
}

static ULONG64 HawkComputeUserSyntheticStack(VOID)
{
	return HawkComputeCurrentUserSyntheticStack();
}

static BOOLEAN HawkFillUserSyntheticStack(
	ULONG64 userSyntheticStack,
	ULONG64 postCallRoutine,
	ULONG64 arg1,
	ULONG64 arg2,
	ULONG64 arg3,
	ULONG64 arg4,
	ULONG64 arg5,
	ULONG64 arg6)
{
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x20, arg1))
	{
		return FALSE;
	}
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x28, arg2))
	{
		return FALSE;
	}
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x30, arg3))
	{
		return FALSE;
	}
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x38, arg4))
	{
		return FALSE;
	}
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x70, arg5))
	{
		return FALSE;
	}
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x78, arg6))
	{
		return FALSE;
	}
	if (!HawkWriteCurrentProcessUserU64(userSyntheticStack + 0x48, postCallRoutine))
	{
		return FALSE;
	}

	return TRUE;
}

static VOID HawkApplyKvaShadowGlobals(_In_ ULONG64 ShadowEnabled, _In_ ULONG64 StackGsOffset)
{
	g_HawkAsmKvaShadow = ShadowEnabled;
	g_HawkAsmStackGsOffset = StackGsOffset;
}

static NTSTATUS HawkDetectKvaShadow(_Out_ PULONG64 ShadowEnabled, _Out_ PULONG64 StackGsOffset)
{
	ULONG64 syscallEntry = 0;
	ULONG offsetEncoded = 0;
	ULONG stackOffset = 0;

	if (ShadowEnabled == NULL || StackGsOffset == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	*ShadowEnabled = 0;
	*StackGsOffset = 8;

	syscallEntry = __readmsr(HAWK_MSR_SYSCALL_ENTRY);
	if (syscallEntry == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	offsetEncoded = *(PULONG)((PUCHAR)(ULONG_PTR)syscallEntry + 8);
	if ((offsetEncoded & 0xFFu) != 0x10u)
	{
		return STATUS_NOT_SUPPORTED;
	}

	stackOffset = offsetEncoded & 0xFF00u;
	*StackGsOffset = (ULONG64)stackOffset + 8ULL;

	if (stackOffset != 0)
	{
		*ShadowEnabled = 1;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HawkUsermodeCallbackInitialize(
	_Inout_ PHAWK_USERMODE_CALLBACK_CTX Ctx,
	_In_ PVOID LandingStub,
	_In_ PVOID PostCallRoutine
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 shadowEnabled = 0;
	ULONG64 stackGsOffset = 8;

	if (Ctx == NULL || LandingStub == NULL || PostCallRoutine == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (Ctx->KernelStackTop == NULL)
	{
		Ctx->KernelStackTop = HawkAllocateKernelStackTop();
		if (Ctx->KernelStackTop == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	Ctx->LandingStub = LandingStub;
	Ctx->PostCallRoutine = PostCallRoutine;

	status = HawkDetectKvaShadow(&shadowEnabled, &stackGsOffset);
	if (!NT_SUCCESS(status))
	{
		shadowEnabled = 0;
		stackGsOffset = 8;
		DBG_PRINT("HawkUsermodeCallbackInitialize: KVA shadow detect failed, using legacy path");
	}

	HawkApplyKvaShadowGlobals(shadowEnabled, stackGsOffset);

	return STATUS_SUCCESS;
}

VOID HawkUsermodeCallbackUninitialize(_Inout_ PHAWK_USERMODE_CALLBACK_CTX Ctx)
{
	if (Ctx == NULL)
	{
		return;
	}

	HawkFreeKernelStackTop(Ctx->KernelStackTop);
	RtlZeroMemory(Ctx, sizeof(*Ctx));
}

ULONG64 HawkUsermodeCallbackCall6(
	_Inout_ PHAWK_USERMODE_CALLBACK_CTX Ctx,
	_In_ ULONG64 TargetFunction,
	_In_ ULONG64 Arg1,
	_In_ ULONG64 Arg2,
	_In_ ULONG64 Arg3,
	_In_ ULONG64 Arg4,
	_In_ ULONG64 Arg5,
	_In_ ULONG64 Arg6,
	_Out_opt_ PULONG64 UserSyntheticStackOut,
	_Out_opt_ PBOOLEAN StackPrepared
	)
{
	ULONG64 kernelStack = 0;
	ULONG64 kernelStackControl = 0;
	ULONG64 userSyntheticStack = 0;
	ULONG64 returnValue = 0;
	ULONG64 returnSlot = 0;
	HAWK_CALL_USER_DATA callData = { 0 };
	USHORT savedKernelApcDisable = 0;
	USHORT savedSpecialApcDisable = 0;
	UCHAR savedApcIndex = 0;

	if (StackPrepared != NULL)
	{
		*StackPrepared = FALSE;
	}
	if (UserSyntheticStackOut != NULL)
	{
		*UserSyntheticStackOut = 0;
	}

	if (Ctx == NULL || Ctx->KernelStackTop == NULL ||
		Ctx->LandingStub == NULL || Ctx->PostCallRoutine == NULL)
	{
		return 0;
	}

	if (TargetFunction == 0 || TargetFunction > MAX_USER_ADDRESS)
	{
		return 0;
	}

	userSyntheticStack = HawkComputeUserSyntheticStack();
	if (userSyntheticStack == 0)
	{
		return 0;
	}

	if (UserSyntheticStackOut != NULL)
	{
		*UserSyntheticStackOut = userSyntheticStack;
	}

	if (!HawkFillUserSyntheticStack(
		userSyntheticStack,
		(ULONG64)(ULONG_PTR)Ctx->PostCallRoutine,
		Arg1,
		Arg2,
		Arg3,
		Arg4,
		Arg5,
		Arg6))
	{
		return 0;
	}

	if (StackPrepared != NULL)
	{
		*StackPrepared = TRUE;
	}

	{
		PHAWK_KTHREAD_USERMODE_VIEW threadView = HawkGetCurrentKthreadUsermodeView();
		PHAWK_KTHREAD_CALLBACK_APC_VIEW apcView = HawkGetCurrentKthreadApcView();

		kernelStack = (ULONG64)Ctx->KernelStackTop;
		kernelStackControl = kernelStack - HAWK_KERNEL_STACK_CONTROL_SIZE;

		*(PULONG64)(kernelStackControl + 0x00) = kernelStack;
		*(PULONG64)(kernelStackControl + 0x08) = kernelStack - HAWK_KERNEL_STACK_SIZE;
		*(PULONG64)(kernelStackControl + 0x10) = (ULONG64)(ULONG_PTR)threadView->StackBase;
		*(PULONG64)(kernelStackControl + 0x18) = (ULONG64)(ULONG_PTR)threadView->StackLimit;
		*(PULONG64)(kernelStackControl + 0x28) = (ULONG64)(ULONG_PTR)threadView->InitialStack;
		*(PULONG64)(kernelStackControl + 0x20) = 0;
		*(PULONG64)(kernelStackControl + 0x30) = 0;
		*(PULONG64)(kernelStackControl + 0x38) = 0;
		*(PULONG64)(kernelStackControl + 0x40) = 0;
		*(PULONG64)(kernelStackControl + 0x48) = 0;

		callData.LandingStub = Ctx->LandingStub;
		callData.UserSyntheticStack = (PVOID)(ULONG_PTR)userSyntheticStack;
		callData.TargetFunction = (PVOID)(ULONG_PTR)TargetFunction;

		savedKernelApcDisable = apcView->KernelApcDisable;
		savedSpecialApcDisable = apcView->SpecialApcDisable;
		savedApcIndex = apcView->ApcStateIndex;

		apcView->KernelApcDisable = 0;
		apcView->SpecialApcDisable = 0;
		apcView->ApcStateIndex = 0;

		returnSlot = 0;
		HawkKiCallUserMode2((ULONG64)&returnSlot, (ULONG64)(ULONG_PTR)&callData, kernelStackControl);

		apcView->KernelApcDisable = savedKernelApcDisable;
		apcView->SpecialApcDisable = savedSpecialApcDisable;
		apcView->ApcStateIndex = savedApcIndex;
	}

	/* returnSlot = user result VA (synthetic+0x70); read the qword there. */
	if (returnSlot != 0 && returnSlot <= MAX_USER_ADDRESS)
	{
		ULONG64 userResult = 0;

		if (!HawkReadCurrentProcessUserU64(returnSlot, &userResult))
		{
			return 0;
		}

		returnValue = userResult;
	}
	else
	{
		returnValue = returnSlot;
	}

	return returnValue;
}
