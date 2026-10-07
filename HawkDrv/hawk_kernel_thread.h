#pragma once

/*
 * Partial _KTHREAD / _KTRAP_FRAME views (x64). Offsets verified with C_ASSERT.
 */

#include <ntddk.h>

#if !defined(_AMD64_)
#error hawk_kernel_thread.h is x64-only
#endif

typedef struct _HAWK_KTHREAD_USERMODE_VIEW
{
	DISPATCHER_HEADER Header;
	UCHAR ReservedBeforeInitialStack[0x28 - sizeof(DISPATCHER_HEADER)];
	PVOID InitialStack;
	PVOID StackLimit;
	PVOID StackBase;
	UCHAR ReservedBeforeTrapFrame[0x90 - 0x40];
	PKTRAP_FRAME TrapFrame;
	UCHAR ReservedBeforeTeb[0xF0 - 0x98];
	PVOID Teb;
} HAWK_KTHREAD_USERMODE_VIEW, *PHAWK_KTHREAD_USERMODE_VIEW;

typedef struct _HAWK_KTHREAD_CALLBACK_APC_VIEW
{
	UCHAR Reserved[0x1E4];
	USHORT KernelApcDisable;
	USHORT SpecialApcDisable;
	UCHAR ReservedBeforeApcStateIndex[0x24A - 0x1E8];
	UCHAR ApcStateIndex;
} HAWK_KTHREAD_CALLBACK_APC_VIEW, *PHAWK_KTHREAD_CALLBACK_APC_VIEW;

C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_USERMODE_VIEW, InitialStack) == 0x28);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_USERMODE_VIEW, StackLimit) == 0x30);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_USERMODE_VIEW, StackBase) == 0x38);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_USERMODE_VIEW, TrapFrame) == 0x90);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_USERMODE_VIEW, Teb) == 0xF0);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_CALLBACK_APC_VIEW, KernelApcDisable) == 0x1E4);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_CALLBACK_APC_VIEW, SpecialApcDisable) == 0x1E6);
C_ASSERT(FIELD_OFFSET(HAWK_KTHREAD_CALLBACK_APC_VIEW, ApcStateIndex) == 0x24A);
C_ASSERT(FIELD_OFFSET(KTRAP_FRAME, Rip) == 0x168);
C_ASSERT(FIELD_OFFSET(KTRAP_FRAME, Rsp) == 0x180);

static __forceinline PKTHREAD HawkGetCurrentKthread(VOID)
{
	return (PKTHREAD)__readgsqword(0x188);
}

static __forceinline PHAWK_KTHREAD_USERMODE_VIEW HawkGetCurrentKthreadUsermodeView(VOID)
{
	return (PHAWK_KTHREAD_USERMODE_VIEW)HawkGetCurrentKthread();
}

static __forceinline PHAWK_KTHREAD_CALLBACK_APC_VIEW HawkGetCurrentKthreadApcView(VOID)
{
	return (PHAWK_KTHREAD_CALLBACK_APC_VIEW)HawkGetCurrentKthread();
}

static __forceinline PKTRAP_FRAME HawkGetCurrentTrapFrame(VOID)
{
	PHAWK_KTHREAD_USERMODE_VIEW thread = HawkGetCurrentKthreadUsermodeView();

	if (thread == NULL)
	{
		return NULL;
	}

	return thread->TrapFrame;
}

static __forceinline ULONG64 HawkGetTrapFrameUserRsp(VOID)
{
	PKTRAP_FRAME trapFrame = HawkGetCurrentTrapFrame();

	if (trapFrame == NULL)
	{
		return 0;
	}

	return trapFrame->Rsp;
}

static __forceinline ULONG64 HawkGetTrapFrameUserRip(VOID)
{
	PKTRAP_FRAME trapFrame = HawkGetCurrentTrapFrame();

	if (trapFrame == NULL)
	{
		return 0;
	}

	return trapFrame->Rip;
}

static __forceinline ULONG64 HawkComputeUserSyntheticStackFromRsp(ULONG64 userRspRaw)
{
	if (userRspRaw == 0)
	{
		return 0;
	}

	return (userRspRaw - 0x98) & ~0xFULL;
}

static __forceinline ULONG64 HawkComputeCurrentUserSyntheticStack(VOID)
{
	return HawkComputeUserSyntheticStackFromRsp(HawkGetTrapFrameUserRsp());
}
