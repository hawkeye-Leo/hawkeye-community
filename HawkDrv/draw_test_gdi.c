#include "draw_test_gdi.h"
#include "usermode_callback.h"
#include "HawkMain.h"

static HAWK_USERMODE_CALLBACK_CTX g_DrawTestCallbackCtx = { 0 };
static BOOLEAN g_DrawTestCallbackReady = FALSE;

extern ULONG64 g_HawkAsmKvaShadow;
extern ULONG64 g_HawkAsmStackGsOffset;

VOID HawkIoctlUsermodeCallbackInit(_In_ PIRP Irp)
{
	PUSERMODE_CALLBACK_INIT request = (PUSERMODE_CALLBACK_INIT)Irp->AssociatedIrp.SystemBuffer;
	NTSTATUS status = STATUS_SUCCESS;

	if (request == NULL)
	{
		HawkIoctlComplete(Irp, STATUS_INVALID_PARAMETER, 0);
		return;
	}

	request->errCode = 0;
	request->status = (LONG)STATUS_SUCCESS;

	if (request->landingStub == 0 || request->postCallRoutine == 0)
	{
		request->errCode = 1;
		request->status = (LONG)STATUS_INVALID_PARAMETER;
		HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
		return;
	}

	if (g_DrawTestCallbackReady)
	{
		HawkUsermodeCallbackUninitialize(&g_DrawTestCallbackCtx);
		g_DrawTestCallbackReady = FALSE;
	}

	status = HawkUsermodeCallbackInitialize(
		&g_DrawTestCallbackCtx,
		(PVOID)(ULONG_PTR)request->landingStub,
		(PVOID)(ULONG_PTR)request->postCallRoutine);

	if (!NT_SUCCESS(status))
	{
		request->errCode = 2;
		request->status = (LONG)status;
		HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
		return;
	}

	g_DrawTestCallbackReady = TRUE;
	request->kvaShadowEnabled = g_HawkAsmKvaShadow;
	request->stackGsOffset = g_HawkAsmStackGsOffset;
	request->kernelStackTop = (ULONG64)(ULONG_PTR)g_DrawTestCallbackCtx.KernelStackTop;
	if (g_DrawTestCallbackCtx.KernelStackTop != NULL)
	{
		request->kernelStackControl =
			(ULONG64)(ULONG_PTR)g_DrawTestCallbackCtx.KernelStackTop - HAWK_KERNEL_STACK_CONTROL_SIZE;
		request->kernelStackLimit =
			(ULONG64)(ULONG_PTR)g_DrawTestCallbackCtx.KernelStackTop - HAWK_KERNEL_STACK_SIZE;
	}
	request->errCode = 0;
	request->status = (LONG)STATUS_SUCCESS;
	HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
}

VOID HawkIoctlUsermodeCallbackCall6(_In_ PIRP Irp)
{
	PUSERMODE_CALLBACK_CALL6 request = (PUSERMODE_CALLBACK_CALL6)Irp->AssociatedIrp.SystemBuffer;

	if (request == NULL)
	{
		HawkIoctlComplete(Irp, STATUS_INVALID_PARAMETER, 0);
		return;
	}

	request->errCode = 0;
	request->status = (LONG)STATUS_SUCCESS;
	request->returnValue = 0;

	if (!g_DrawTestCallbackReady)
	{
		request->errCode = USERMODE_CALLBACK_CALL6_ERR_NOT_READY;
		request->status = (LONG)STATUS_DEVICE_NOT_READY;
		HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
		return;
	}

	if (request->targetFunction == 0)
	{
		request->errCode = USERMODE_CALLBACK_CALL6_ERR_BAD_PARAMETER;
		request->status = (LONG)STATUS_INVALID_PARAMETER;
		HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
		return;
	}

	{
		BOOLEAN stackPrepared = FALSE;

		request->userSyntheticStack = 0;
		request->returnValue = HawkUsermodeCallbackCall6(
			&g_DrawTestCallbackCtx,
			request->targetFunction,
			request->arg1,
			request->arg2,
			request->arg3,
			request->arg4,
			request->arg5,
			request->arg6,
			&request->userSyntheticStack,
			&stackPrepared);

		if (!stackPrepared)
		{
			request->errCode = USERMODE_CALLBACK_CALL6_ERR_STACK_WRITE;
			request->status = (LONG)STATUS_UNSUCCESSFUL;
			HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
			return;
		}
	}

	request->errCode = 0;
	request->status = (LONG)STATUS_SUCCESS;
	HawkIoctlComplete(Irp, STATUS_SUCCESS, sizeof(*request));
}
