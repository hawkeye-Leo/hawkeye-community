#pragma once

#include <ntddk.h>
#include "..\common.h"
#include "hawk_kernel_thread.h"

#define HAWK_KERNEL_STACK_SIZE          0x6000UL
#define HAWK_KERNEL_STACK_CONTROL_SIZE  0x50UL
#define HAWK_KERNEL_STACK_SCRATCH_SIZE  0x30UL
#define HAWK_CALLBACK_STACK_HEAD (HAWK_KERNEL_STACK_CONTROL_SIZE + HAWK_KERNEL_STACK_SCRATCH_SIZE)

C_ASSERT(HAWK_CALLBACK_STACK_HEAD == 0x80UL);

/*
 * Callback pool stack (addresses decrease from KernelStackTop):
 *   [top - CONTROL, top)              control block
 *   [top - HEAD, top - CONTROL)       scratch (OutputLength at control - SCRATCH_SIZE)
 *   [top - POOL, top - HEAD)          pool body
 */

typedef struct _HAWK_CALL_USER_DATA
{
	PVOID LandingStub;          /* sysret rcx (RIP) */
	PVOID UserSyntheticStack;   /* sysret rsp */
	PVOID TargetFunction;       /* sysret rax */
} HAWK_CALL_USER_DATA, *PHAWK_CALL_USER_DATA;

C_ASSERT(sizeof(HAWK_CALL_USER_DATA) == 24);

typedef struct _HAWK_USERMODE_CALLBACK_CTX
{
	PVOID LandingStub;
	PVOID PostCallRoutine;
	PVOID KernelStackTop;
} HAWK_USERMODE_CALLBACK_CTX, *PHAWK_USERMODE_CALLBACK_CTX;

NTSTATUS HawkUsermodeCallbackInitialize(
	_Inout_ PHAWK_USERMODE_CALLBACK_CTX Ctx,
	_In_ PVOID LandingStub,
	_In_ PVOID PostCallRoutine
	);

VOID HawkUsermodeCallbackUninitialize(
	_Inout_ PHAWK_USERMODE_CALLBACK_CTX Ctx
	);

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
	);

extern VOID HawkKiCallUserMode2(
	_In_ ULONG64 ReturnValuePointer,
	_In_ ULONG64 CallDataPointer,
	_In_ ULONG64 KernelStackControlPointer
	);
