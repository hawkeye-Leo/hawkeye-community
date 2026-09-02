#include "CompatReport.h"
#include "Driver.h"
#include "HawkeyeVersion.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

#include <QStringList>

namespace {

typedef NTSTATUS(WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOW);

QString QueryWindowsVersion()
{
    RTL_OSVERSIONINFOW versionInfo = {};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (rtlGetVersion == nullptr || rtlGetVersion(&versionInfo) != 0) {
        return QStringLiteral("Windows (unknown)");
    }

    return QStringLiteral("Windows %1.%2 build %3")
        .arg(versionInfo.dwMajorVersion)
        .arg(versionInfo.dwMinorVersion)
        .arg(versionInfo.dwBuildNumber);
}

QString QueryDisplayVersion()
{
    wchar_t buffer[128] = {};
    DWORD bufferBytes = sizeof(buffer);
    const LONG status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"DisplayVersion",
        RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
        nullptr,
        buffer,
        &bufferBytes);
    if (status == ERROR_SUCCESS && buffer[0] != L'\0') {
        return QString::fromWCharArray(buffer);
    }
    return QString();
}

typedef NTSTATUS(WINAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

struct SystemCodeIntegrityInformation
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

bool g_memoryIntegrityRunning = false;

bool queryCodeIntegrityOptions(ULONG* options)
{
    constexpr ULONG kSystemCodeIntegrityInformation = 103;
    if (options == nullptr) {
        return false;
    }

    const auto ntQuery = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (ntQuery == nullptr) {
        return false;
    }

    SystemCodeIntegrityInformation info = {};
    info.Length = sizeof(info);
    ULONG returnLength = 0;
    if (ntQuery(kSystemCodeIntegrityInformation, &info, sizeof(info), &returnLength) != 0) {
        return false;
    }
    *options = info.CodeIntegrityOptions;
    return true;
}

bool queryMemoryIntegrityRunningNow()
{
    constexpr ULONG kHvciKmciEnabled = 0x400;
    ULONG options = 0;
    if (!queryCodeIntegrityOptions(&options)) {
        return false;
    }
    return (options & kHvciKmciEnabled) != 0;
}

bool queryMemoryIntegrityConfigured(bool* known)
{
    DWORD configuredValue = 0;
    DWORD configuredBytes = sizeof(configuredValue);
    const LONG status = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"Enabled",
        RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
        nullptr,
        &configuredValue,
        &configuredBytes);
    if (known != nullptr) {
        *known = (status == ERROR_SUCCESS);
    }
    return status == ERROR_SUCCESS && configuredValue != 0;
}

QString QueryMemoryIntegrityStatus()
{
    constexpr ULONG kSystemCodeIntegrityInformation = 103;
    constexpr ULONG kHvciKmciEnabled = 0x400;
    constexpr ULONG kHvciKmciAudit = 0x800;

    bool runningKnown = false;
    bool running = false;
    bool audit = false;

    const auto ntQuery = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (ntQuery != nullptr) {
        SystemCodeIntegrityInformation info = {};
        info.Length = sizeof(info);
        ULONG returnLength = 0;
        if (ntQuery(kSystemCodeIntegrityInformation, &info, sizeof(info), &returnLength) == 0) {
            runningKnown = true;
            running = (info.CodeIntegrityOptions & kHvciKmciEnabled) != 0;
            audit = (info.CodeIntegrityOptions & kHvciKmciAudit) != 0;
        }
    }

    bool configuredKnown = false;
    const bool configured = queryMemoryIntegrityConfigured(&configuredKnown);

    if (!runningKnown) {
        if (!configuredKnown) {
            return QStringLiteral("unknown");
        }
        return configured
            ? QStringLiteral("configured (runtime status unknown)")
            : QStringLiteral("off (runtime status unknown)");
    }

    if (running) {
        if (configuredKnown && !configured) {
            return QStringLiteral("on (settings off, reboot pending)");
        }
        return QStringLiteral("on");
    }
    if (audit) {
        return QStringLiteral("audit (not enforced)");
    }
    if (configured) {
        return QStringLiteral("off (settings on, reboot pending)");
    }
    return QStringLiteral("off");
}

void appendCommonFields(QStringList& lines)
{
    lines << QStringLiteral("Product: %1  Release %2")
                 .arg(QStringLiteral(HAWKEYE_PRODUCT_NAME),
                      QStringLiteral(HAWKEYE_VERSION_STRING));
    lines << QStringLiteral("Edition: Community");
    lines << QStringLiteral("OS: %1").arg(QueryWindowsVersion());
    const QString displayVersion = QueryDisplayVersion();
    if (!displayVersion.isEmpty()) {
        lines << QStringLiteral("Display version: %1").arg(displayVersion);
    }
    lines << QStringLiteral("Memory integrity: %1").arg(QueryMemoryIntegrityStatus());
    lines << QStringLiteral("Test signing: %1")
                 .arg(TestSigningIsEnabled() ? QStringLiteral("on") : QStringLiteral("off"));
}

void appendDriverStartLines(QStringList& lines, DWORD driverStartError)
{
    const bool driverLoaded = TestDrv();
    lines << QStringLiteral("Driver: %1").arg(driverLoaded ? QStringLiteral("loaded") : QStringLiteral("not loaded"));
    if (driverLoaded) {
        return;
    }

    const DrvStartFailReason reason = GetLastDriverStartFailReason();
    const DWORD err = driverStartError != 0 ? driverStartError : GetLastDriverStartError();
    if (reason == DrvStartFailSignature) {
        lines << (err != 0
                      ? QStringLiteral("Driver start: Windows blocked the signature (%1)").arg(err)
                      : QStringLiteral("Driver start: Windows blocked the signature"));
        return;
    }
    if (reason == DrvStartFailKernelLayout) {
        const char* compatRef = GetLastDriverCompatRef();
        lines << (compatRef != nullptr
                      ? QStringLiteral("Driver start: this Windows build is not supported (%1)")
                            .arg(QString::fromLatin1(compatRef))
                      : QStringLiteral("Driver start: this Windows build is not supported"));
        return;
    }
    if (err != 0) {
        lines << QStringLiteral("Driver start: failed (%1)").arg(err);
        return;
    }
    if (reason == DrvStartFailGeneric) {
        lines << QStringLiteral("Driver start: failed");
    }
}

} // namespace

void CaptureMemoryIntegrityState()
{
    g_memoryIntegrityRunning = queryMemoryIntegrityRunningNow();
}

bool MemoryIntegrityIsRunning()
{
    return g_memoryIntegrityRunning;
}

bool MemoryIntegrityIsRunningNow()
{
    return queryMemoryIntegrityRunningNow();
}

bool MemoryIntegrityRestartNeeded()
{
    bool configuredKnown = false;
    const bool configured = queryMemoryIntegrityConfigured(&configuredKnown);
    return configuredKnown && !configured && queryMemoryIntegrityRunningNow();
}

bool TestSigningIsEnabled()
{
    constexpr ULONG kTestSign = 0x02;
    ULONG options = 0;
    if (!queryCodeIntegrityOptions(&options)) {
        return false;
    }
    return (options & kTestSign) != 0;
}

QString CompatReportText(const char* compatRef, DWORD driverStartError)
{
    const bool compatFailure = compatRef != nullptr && compatRef[0] != '\0';

    QStringList lines;
    if (compatFailure) {
        const QString reference = QString::fromLatin1(compatRef);
        lines << QStringLiteral("Hawkeye Community compatibility report");
        lines << QString();
        lines << QStringLiteral(
            "Sorry - this Windows build is not supported yet. "
            "This is not a configuration mistake on your side.");
        lines << QString();
        appendCommonFields(lines);
        appendDriverStartLines(lines, driverStartError);
        lines << QStringLiteral("Reference: %1").arg(reference);
        lines << QString();
        lines << QStringLiteral("Website: %1").arg(QStringLiteral(HAWKEYE_WEBSITE_URL));
        lines << QStringLiteral("Email this report to %1").arg(QStringLiteral(HAWKEYE_SUPPORT_EMAIL));
        lines << QStringLiteral("Subject: [%1] Windows compatibility").arg(reference);
        return lines.join(QLatin1Char('\n'));
    }

    lines << QStringLiteral("Hawkeye Community support report");
    lines << QString();
    appendCommonFields(lines);
    appendDriverStartLines(lines, driverStartError);
    lines << QString();
    lines << QStringLiteral(
        "If you hit a bug, copy this report into an email to support. "
        "Briefly describe what went wrong and paste any error text from the console.");
    lines << QString();
    lines << QStringLiteral("Website: %1").arg(QStringLiteral(HAWKEYE_WEBSITE_URL));
    lines << QStringLiteral("Email: %1").arg(QStringLiteral(HAWKEYE_SUPPORT_EMAIL));
    lines << QStringLiteral("Subject: [Hawkeye Community] Support request");
    return lines.join(QLatin1Char('\n'));
}
