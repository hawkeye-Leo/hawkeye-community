#include "etw_ti_worker.h"

#include "etw_ti.h"
#include "Driver.h"

#include <Windows.h>

namespace {

QString GetProcessNameByPid(DWORD pid)
{
	wchar_t image[MAX_PATH];
	DWORD imageChars = MAX_PATH;
	image[0] = L'\0';

	HANDLE process = OpenProcessForQuery(pid);
	if (process == NULL)
	{
		return QStringLiteral("?");
	}

	if (!QueryFullProcessImageNameW(process, 0, image, &imageChars))
	{
		CloseHandle(process);
		return QStringLiteral("?");
	}
	CloseHandle(process);

	const QString path = QString::fromWCharArray(image);
	const int slash = path.lastIndexOf(QLatin1Char('\\'));
	return slash >= 0 ? path.mid(slash + 1) : path;
}

const char* SyscallEnumToName(ULONG syscallEnum)
{
	switch (syscallEnum)
	{
	case 0: return "SystemModuleInformation";
	case 1: return "SystemModuleInformationEx";
	case 2: return "SystemLocksInformation";
	case 3: return "SystemStackTraceInformation";
	case 4: return "SystemHandleInformation";
	case 5: return "SystemExtendedHandleInformation";
	case 6: return "SystemObjectInformation";
	case 7: return "SystemBigPoolInformation";
	case 8: return "SystemExtendedProcessInformation";
	case 9: return "SystemSessionProcessInformation";
	case 10: return "SystemMemoryTopologyInformation";
	case 11: return "SystemMemoryChannelInformation";
	case 12: return "SystemCoverageInformation";
	case 13: return "SystemPlatformBinaryInformation";
	case 14: return "SystemFirmwareTableInformation";
	case 15: return "SystemBootMetadataInformation";
	case 16: return "SystemWheaIpmiHardwareInformation";
	case 17: return "SystemSuperfetchPrefetch";
	case 18: return "SystemSuperfetchPfnQuery";
	case 19: return "SystemSuperfetchPrivSourceQuery";
	case 20: return "SystemSuperfetchMemoryListQuery";
	case 21: return "SystemSuperfetchMemoryRangesQuery";
	case 22: return "SystemSuperfetchPfnSetPriority";
	case 23: return "SystemSuperfetchMovePages";
	case 24: return "SystemSuperfetchPfnSetPageHeat";
	case 25: return "SysDbgGetTriageDump";
	case 26: return "SysDbgGetLiveKernelDump";
	default: return nullptr;
	}
}

QString FormatTiEvent(const EtwTiEvent& event)
{
	QString line = QStringLiteral("[id=%1 %2]")
		.arg(event.EventId)
		.arg(QString::fromLatin1(event.TypeName));

	if (event.OperationStatus != 0)
	{
		line += QStringLiteral(" status=0x%1").arg(event.OperationStatus, 0, 16);
	}
	if (event.CallerPid != 0)
	{
		line += QStringLiteral(" caller=%1(%2)")
			.arg(event.CallerPid)
			.arg(GetProcessNameByPid(event.CallerPid));
	}
	if (event.TargetPid != 0)
	{
		line += QStringLiteral(" target=%1(%2)")
			.arg(event.TargetPid)
			.arg(GetProcessNameByPid(event.TargetPid));
	}
	if (event.TargetThreadId != 0)
	{
		line += QStringLiteral(" tid=%1").arg(event.TargetThreadId);
	}
	if (event.SyscallEnum != 0)
	{
		const char* syscallName = SyscallEnumToName(event.SyscallEnum);
		if (syscallName != nullptr)
		{
			line += QStringLiteral(" syscall=%1(%2)")
				.arg(event.SyscallEnum)
				.arg(QString::fromLatin1(syscallName));
		}
		else
		{
			line += QStringLiteral(" syscall=%1").arg(event.SyscallEnum);
		}
	}
	if (event.ObjectName[0] != L'\0')
	{
		line += QStringLiteral(" name=%1").arg(QString::fromWCharArray(event.ObjectName));
	}
	if (event.CodeIntegrityOption != 0)
	{
		line += QStringLiteral(" ci=0x%1").arg(event.CodeIntegrityOption, 0, 16);
	}
	if (event.BaseAddress != 0 || event.RegionSize != 0 || event.ProtectionMask != 0)
	{
		line += QStringLiteral(" base=0x%1 size=0x%2 prot=0x%3")
			.arg(event.BaseAddress, 0, 16)
			.arg(event.RegionSize, 0, 16)
			.arg(event.ProtectionMask, 0, 16);
	}

	return line;
}

} // namespace

EtwTiWorker::EtwTiWorker(QObject* parent)
	: QThread(parent)
	, m_stop(0)
{
}

EtwTiWorker::~EtwTiWorker()
{
	requestStop();
	wait(5000);
}

void EtwTiWorker::requestStop()
{
	InterlockedExchange(&m_stop, 1);
	EtwTiRequestStop();
}

void EtwTiWorker::run()
{
	InterlockedExchange(&m_stop, 0);

	QString error;
	const auto onEvent = [this](const EtwTiEvent& event) {
		if (InterlockedCompareExchange(&m_stop, 0, 0) != 0)
		{
			return;
		}
		emit eventLineReady(FormatTiEvent(event));
	};

	if (!EtwTiRun(onEvent, &error))
	{
		emit traceFailed(error);
		return;
	}

	emit traceStopped();
}
