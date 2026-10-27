#include "etw_ti.h"

#include <Evntcons.h>
#include <Evntrace.h>
#include <Tdh.h>
#include <Wmistr.h>

#include <cstdio>
#include <cstring>
#include <vector>

#pragma comment(lib, "tdh.lib")

//powershell:wevtutil gp Microsoft-Windows-Threat-Intelligence

#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000001
#endif

#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x00000010
#endif

namespace {

#ifndef ProcessProtectionInformation
#define ProcessProtectionInformation 61
#endif

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
		};
	};
} PS_PROTECTION;

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtQueryInformationProcessFn)(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

static const GUID kEtwTiProviderGuid =
{ 0xf4e1897c, 0xbb5d, 0x5668, { 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44 } };

static const WCHAR kEtwTiSessionName[] = L"HawkeyeCommunityEtwTi";

static const ULONGLONG kKwAllocVmRemote = 0x4ULL;
static const ULONGLONG kKwProtectVmRemote = 0x40ULL;
static const ULONGLONG kKwMapViewRemote = 0x400ULL;
static const ULONGLONG kKwQueueApcRemote = 0x1000ULL;
static const ULONGLONG kKwSetCtxRemote = 0x4000ULL;
static const ULONGLONG kKwReadVmRemote = 0x20000ULL;
static const ULONGLONG kKwWriteVmRemote = 0x80000ULL;
static const ULONGLONG kKwFreezeProcess = 0x1000000ULL;
static const ULONGLONG kKwThawProcess = 0x2000000ULL;
static const ULONGLONG kKwDriverEvents = 0x40000000ULL;
static const ULONGLONG kKwProcessSyscallUsage = 0x10000000000ULL;

static const ULONGLONG kEtwTiEnableKeywords =
	kKwAllocVmRemote |
	kKwProtectVmRemote |
	kKwMapViewRemote |
	kKwQueueApcRemote |
	kKwSetCtxRemote |
	kKwReadVmRemote |
	kKwWriteVmRemote |
	kKwFreezeProcess |
	kKwThawProcess |
	kKwDriverEvents |
	kKwProcessSyscallUsage;

struct EtwTiSession
{
	volatile LONG stop;
	TRACEHANDLE sessionHandle;
	TRACEHANDLE traceHandle;
	EtwTiEventCallback onEvent;
	std::vector<BYTE> propertiesBuffer;
	std::vector<WCHAR> sessionName;
};

static EtwTiSession* g_activeSession = nullptr;

static PS_PROTECTION QueryCurrentPsProtection(void)
{
	PS_PROTECTION protection = {};
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
	{
		return protection;
	}

	const auto ntQueryInformationProcess =
		reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
	if (ntQueryInformationProcess == NULL)
	{
		return protection;
	}

	ntQueryInformationProcess(
		GetCurrentProcess(),
		ProcessProtectionInformation,
		&protection,
		sizeof(protection),
		nullptr);
	return protection;
}

static void CopyTypeName(char* dest, size_t destSize, const char* name)
{
	if (dest == nullptr || destSize == 0 || name == nullptr)
	{
		return;
	}

	strncpy_s(dest, destSize, name, _TRUNCATE);
}

static const char* KeywordToTypeName(ULONGLONG keyword)
{
	if (keyword & kKwAllocVmRemote)
	{
		return "ALLOCVM_REMOTE";
	}
	if (keyword & kKwProtectVmRemote)
	{
		return "PROTECTVM_REMOTE";
	}
	if (keyword & kKwMapViewRemote)
	{
		return "MAPVIEW_REMOTE";
	}
	if (keyword & kKwQueueApcRemote)
	{
		return "QUEUEAPC_REMOTE";
	}
	if (keyword & kKwSetCtxRemote)
	{
		return "SETTHREADCONTEXT_REMOTE";
	}
	if (keyword & kKwReadVmRemote)
	{
		return "READVM_REMOTE";
	}
	if (keyword & kKwWriteVmRemote)
	{
		return "WRITEVM_REMOTE";
	}
	if (keyword & kKwFreezeProcess)
	{
		return "FREEZE_PROCESS";
	}
	if (keyword & kKwThawProcess)
	{
		return "THAW_PROCESS";
	}
	if (keyword & kKwDriverEvents)
	{
		return "DRIVER_EVENT";
	}
	if (keyword & kKwProcessSyscallUsage)
	{
		return "PROCESS_SYSCALL_USAGE";
	}
	return nullptr;
}

static const char* EventIdToTypeName(USHORT eventId)
{
	switch (eventId)
	{
	case 19: return "FREEZE_PROCESS";
	case 20: return "THAW_PROCESS";
	case 29: return "DRIVER_CREATE";
	case 30: return "DRIVER_DELETE";
	case 31: return "DEVICE_CREATE";
	case 32: return "DEVICE_DELETE";
	case 33: return "PROCESS_IMPERSONATION_UP";
	case 34: return "PROCESS_IMPERSONATION_REVERT";
	case 35: return "PROCESS_SYSCALL_USAGE";
	case 36: return "PROCESS_IMPERSONATION_DOWN";
	default: return nullptr;
	}
}

static void BuildTiTypeName(USHORT eventId, ULONGLONG keyword, char* dest, size_t destSize)
{
	const char* name = EventIdToTypeName(eventId);
	if (name == nullptr)
	{
		name = KeywordToTypeName(keyword);
	}
	if (name == nullptr)
	{
		snprintf(dest, destSize, "TI_EVENT_%u", static_cast<unsigned>(eventId));
		return;
	}

	CopyTypeName(dest, destSize, name);
}

template<typename T>
static bool GetTiProperty(PEVENT_RECORD record, LPCWSTR name, T& value)
{
	PROPERTY_DATA_DESCRIPTOR desc = {};
	desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
	desc.ArrayIndex = ULONG_MAX;

	return TdhGetProperty(
		record,
		0,
		nullptr,
		1,
		&desc,
		sizeof(value),
		reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS;
}

static bool GetTiPropertyU64(PEVENT_RECORD record, LPCWSTR name, ULONGLONG& value)
{
	UINT64 raw = 0;
	if (!GetTiProperty(record, name, raw))
	{
		return false;
	}

	value = raw;
	return true;
}

static ULONGLONG GetTiSizeProperty(PEVENT_RECORD record)
{
	ULONGLONG value = 0;
	if (GetTiPropertyU64(record, L"RegionSize", value) ||
		GetTiPropertyU64(record, L"ViewSize", value) ||
		GetTiPropertyU64(record, L"BytesCopied", value) ||
		GetTiPropertyU64(record, L"FullRegionSize", value))
	{
		return value;
	}

	return 0;
}

static ULONG GetTiProtectionProperty(PEVENT_RECORD record)
{
	ULONG value = 0;
	if (GetTiProperty(record, L"ProtectionMask", value) ||
		GetTiProperty(record, L"LastProtectionMask", value))
	{
		return value;
	}

	return 0;
}

static bool GetTiStringProperty(
	PEVENT_RECORD record,
	LPCWSTR name,
	USHORT charLength,
	WCHAR* out,
	size_t outChars)
{
	PROPERTY_DATA_DESCRIPTOR desc = {};
	ULONG size = 0;
	size_t copyChars = 0;

	if (out == nullptr || outChars == 0)
	{
		return false;
	}

	out[0] = L'\0';
	desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
	desc.ArrayIndex = ULONG_MAX;

	if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size < sizeof(WCHAR))
	{
		return false;
	}

	std::vector<BYTE> buffer(size);
	if (TdhGetProperty(record, 0, nullptr, 1, &desc, size, buffer.data()) != ERROR_SUCCESS)
	{
		return false;
	}

	const WCHAR* text = reinterpret_cast<const WCHAR*>(buffer.data());
	const size_t wcharCount = size / sizeof(WCHAR);

	if (charLength > 0)
	{
		copyChars = charLength;
	}
	else
	{
		for (size_t i = 0; i < wcharCount; ++i)
		{
			if (text[i] == L'\0')
			{
				copyChars = i;
				break;
			}
		}
		if (copyChars == 0 && wcharCount > 0)
		{
			copyChars = wcharCount;
		}
	}

	if (copyChars > wcharCount)
	{
		copyChars = wcharCount;
	}
	if (copyChars >= outChars)
	{
		copyChars = outChars - 1;
	}

	if (copyChars == 0)
	{
		return false;
	}

	wmemcpy(out, text, copyChars);
	out[copyChars] = L'\0';
	return true;
}

static bool GetTiObjectName(PEVENT_RECORD record, WCHAR* out, size_t outChars)
{
	USHORT nameLength = 0;

	if (GetTiProperty(record, L"DriverNameLength", nameLength) &&
		GetTiStringProperty(record, L"DriverName", nameLength, out, outChars))
	{
		return true;
	}

	nameLength = 0;
	if (GetTiProperty(record, L"DeviceNameLength", nameLength) &&
		GetTiStringProperty(record, L"DeviceName", nameLength, out, outChars))
	{
		return true;
	}

	return GetTiStringProperty(record, L"DriverName", 0, out, outChars) ||
		GetTiStringProperty(record, L"DeviceName", 0, out, outChars);
}

static void HandleTiEventRecord(PEVENT_RECORD record, EtwTiEventCallback& onEvent)
{
	if (record == nullptr || onEvent == nullptr)
	{
		return;
	}

	const ULONGLONG keyword = record->EventHeader.EventDescriptor.Keyword;
	const USHORT eventId = record->EventHeader.EventDescriptor.Id;

	EtwTiEvent event = {};
	event.EventId = eventId;
	BuildTiTypeName(eventId, keyword, event.TypeName, sizeof(event.TypeName));

	GetTiProperty(record, L"OperationStatus", event.OperationStatus);
	GetTiProperty(record, L"CallingProcessId", event.CallerPid);
	GetTiProperty(record, L"TargetProcessId", event.TargetPid);
	GetTiProperty(record, L"TargetThreadId", event.TargetThreadId);
	GetTiProperty(record, L"SyscallEnum", event.SyscallEnum);
	GetTiProperty(record, L"CodeIntegrityOption", event.CodeIntegrityOption);
	GetTiPropertyU64(record, L"BaseAddress", event.BaseAddress);
	event.RegionSize = GetTiSizeProperty(record);
	event.ProtectionMask = GetTiProtectionProperty(record);

	GetTiObjectName(record, event.ObjectName, _countof(event.ObjectName));

	onEvent(event);
}

static void WINAPI EtwTiTraceRecordCallback(PEVENT_RECORD record)
{
	if (g_activeSession == nullptr || InterlockedCompareExchange(&g_activeSession->stop, 0, 0) != 0)
	{
		return;
	}

	HandleTiEventRecord(record, g_activeSession->onEvent);
}

static bool BuildSessionProperties(EtwTiSession& session)
{
	session.sessionName.assign(kEtwTiSessionName, kEtwTiSessionName + wcslen(kEtwTiSessionName) + 1);

	const ULONG propertiesSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES));
	const ULONG totalSize = propertiesSize + static_cast<ULONG>(session.sessionName.size() * sizeof(WCHAR));
	session.propertiesBuffer.assign(totalSize, 0);

	auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(session.propertiesBuffer.data());
	properties->Wnode.BufferSize = totalSize;
	properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	properties->LoggerNameOffset = propertiesSize;
	memcpy(
		session.propertiesBuffer.data() + propertiesSize,
		session.sessionName.data(),
		session.sessionName.size() * sizeof(WCHAR));
	return true;
}

static void StopExistingSession(EtwTiSession& session)
{
	std::vector<BYTE> stopBuffer = session.propertiesBuffer;
	ControlTraceW(
		0,
		session.sessionName.data(),
		reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBuffer.data()),
		EVENT_TRACE_CONTROL_STOP);
}

static void StopActiveSession(EtwTiSession& session)
{
	if (session.traceHandle != INVALID_PROCESSTRACE_HANDLE)
	{
		CloseTrace(session.traceHandle);
		session.traceHandle = INVALID_PROCESSTRACE_HANDLE;
	}

	if (session.sessionHandle != 0)
	{
		ControlTraceW(
			session.sessionHandle,
			nullptr,
			reinterpret_cast<EVENT_TRACE_PROPERTIES*>(session.propertiesBuffer.data()),
			EVENT_TRACE_CONTROL_STOP);
		session.sessionHandle = 0;
	}
}

} // namespace

QString EtwTiDescribeProcessProtection(void)
{
	const PS_PROTECTION protection = QueryCurrentPsProtection();
	const QString typeText = [&protection]() -> QString {
		switch (protection.Type)
		{
		case 0: return QStringLiteral("none");
		case 1: return QStringLiteral("PPL");
		case 2: return QStringLiteral("PP");
		default: return QStringLiteral("type=%1").arg(protection.Type);
		}
	}();

	return QStringLiteral("PS_PROTECTION: type=%1 signer=%2 audit=%3 raw=0x%4")
		.arg(typeText)
		.arg(protection.Signer)
		.arg(protection.Audit)
		.arg(protection.Level, 2, 16, QChar('0'));
}

void EtwTiRequestStop(void)
{
	if (g_activeSession == nullptr)
	{
		return;
	}

	InterlockedExchange(&g_activeSession->stop, 1);
	if (g_activeSession->traceHandle != INVALID_PROCESSTRACE_HANDLE)
	{
		CloseTrace(g_activeSession->traceHandle);
	}
}

BOOL EtwTiRun(const EtwTiEventCallback& onEvent, QString* outError)
{
	if (onEvent == nullptr)
	{
		if (outError != nullptr)
		{
			*outError = QStringLiteral("Internal error: missing event callback.");
		}
		return FALSE;
	}

	EtwTiSession session = {};
	session.stop = 0;
	session.traceHandle = INVALID_PROCESSTRACE_HANDLE;
	session.onEvent = onEvent;
	g_activeSession = &session;

	if (!BuildSessionProperties(session))
	{
		g_activeSession = nullptr;
		if (outError != nullptr)
		{
			*outError = QStringLiteral("Failed to build ETW session properties.");
		}
		return FALSE;
	}

	StopExistingSession(session);

	ULONG startStatus = StartTraceW(
		&session.sessionHandle,
		session.sessionName.data(),
		reinterpret_cast<EVENT_TRACE_PROPERTIES*>(session.propertiesBuffer.data()));
	if (startStatus != ERROR_SUCCESS)
	{
		g_activeSession = nullptr;
		if (outError != nullptr)
		{
			*outError = QStringLiteral("StartTraceW failed (%1).").arg(startStatus);
		}
		return FALSE;
	}

	const ULONG enableStatus = EnableTraceEx2(
		session.sessionHandle,
		&kEtwTiProviderGuid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		kEtwTiEnableKeywords,
		0,
		0,
		nullptr);
	if (enableStatus != ERROR_SUCCESS)
	{
		StopActiveSession(session);
		g_activeSession = nullptr;
		if (outError != nullptr)
		{
			if (enableStatus == ERROR_ACCESS_DENIED)
			{
				*outError = QStringLiteral(
					"EnableTraceEx2 failed (ERROR_ACCESS_DENIED). "
					"Microsoft-Windows-Threat-Intelligence requires Antimalware PPL (see !etw_ti_ppl).\n"
					"         %1")
					.arg(EtwTiDescribeProcessProtection());
			}
			else
			{
				*outError = QStringLiteral("EnableTraceEx2 failed (%1).\n         %2")
					.arg(enableStatus)
					.arg(EtwTiDescribeProcessProtection());
			}
		}
		return FALSE;
	}

	std::vector<WCHAR> loggerName(session.sessionName);
	EVENT_TRACE_LOGFILEW logfile = {};
	logfile.LoggerName = loggerName.data();
	logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	logfile.EventRecordCallback = EtwTiTraceRecordCallback;

	session.traceHandle = OpenTraceW(&logfile);
	if (session.traceHandle == INVALID_PROCESSTRACE_HANDLE)
	{
		EnableTraceEx2(
			session.sessionHandle,
			&kEtwTiProviderGuid,
			EVENT_CONTROL_CODE_DISABLE_PROVIDER,
			0,
			0,
			0,
			0,
			nullptr);
		StopActiveSession(session);
		g_activeSession = nullptr;
		if (outError != nullptr)
		{
			*outError = QStringLiteral("OpenTraceW failed (%1).").arg(GetLastError());
		}
		return FALSE;
	}

	const ULONG processStatus = ProcessTrace(&session.traceHandle, 1, nullptr, nullptr);

	EnableTraceEx2(
		session.sessionHandle,
		&kEtwTiProviderGuid,
		EVENT_CONTROL_CODE_DISABLE_PROVIDER,
		0,
		0,
		0,
		0,
		nullptr);
	StopActiveSession(session);
	g_activeSession = nullptr;

	if (processStatus != ERROR_SUCCESS && processStatus != ERROR_CANCELLED)
	{
		if (outError != nullptr)
		{
			*outError = QStringLiteral("ProcessTrace failed (%1).").arg(processStatus);
		}
		return FALSE;
	}

	if (outError != nullptr)
	{
		outError->clear();
	}
	return TRUE;
}
