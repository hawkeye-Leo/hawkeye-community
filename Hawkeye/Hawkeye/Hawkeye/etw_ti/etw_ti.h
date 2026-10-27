#pragma once

#include <Windows.h>

#include <functional>
#include <QString>

struct EtwTiEvent
{
	char TypeName[80];
	USHORT EventId;
	ULONG OperationStatus;
	ULONG CallerPid;
	ULONG TargetPid;
	ULONG TargetThreadId;
	ULONG SyscallEnum;
	ULONG CodeIntegrityOption;
	WCHAR ObjectName[128];
	ULONGLONG BaseAddress;
	ULONGLONG RegionSize;
	ULONG ProtectionMask;
};

using EtwTiEventCallback = std::function<void(const EtwTiEvent& event)>;

QString EtwTiDescribeProcessProtection(void);

BOOL EtwTiRun(const EtwTiEventCallback& onEvent, QString* outError);
void EtwTiRequestStop(void);
