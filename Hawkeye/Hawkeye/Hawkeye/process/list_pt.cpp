#include "list_pt.h"

#include "Driver.h"
#include "PathConvert.h"
#include "process.h"
#include "common.h"

#include <QString>

#include <Windows.h>

#include <algorithm>
#include <memory>

QString GetKernelMemoryRegionName(DWORD64 va);

namespace {

constexpr std::uint64_t kKernelCanonicalThreshold = 0xFFFF000000000000ULL;

struct HandleCloser
{
    void operator()(HANDLE handle) const
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using ScopedHandle = std::unique_ptr<void, HandleCloser>;

QString formatOep(std::uint64_t oep)
{
    return QStringLiteral("0x") + QString("%1").arg(oep, 16, 16, QChar('0')).toUpper();
}

bool isKernelCanonicalAddress(std::uint64_t address)
{
    return address >= kKernelCanonicalThreshold;
}

QString formatUserProtectLabel(DWORD protect)
{
    switch (protect & 0xFF)
    {
    case PAGE_NOACCESS:
        return QStringLiteral("NA");
    case PAGE_READONLY:
        return QStringLiteral("R");
    case PAGE_READWRITE:
        return QStringLiteral("RW");
    case PAGE_WRITECOPY:
        return QStringLiteral("WC");
    case PAGE_EXECUTE:
        return QStringLiteral("X");
    case PAGE_EXECUTE_READ:
        return QStringLiteral("RX");
    case PAGE_EXECUTE_READWRITE:
        return QStringLiteral("RWX");
    case PAGE_EXECUTE_WRITECOPY:
        return QStringLiteral("RWX");
    default:
        return QString("0x%1").arg(protect, 0, 16);
    }
}

bool isUserProtectRwx(DWORD protect)
{
    switch (protect & 0xFF)
    {
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

QString formatKernelRegionLabel(std::uint64_t oep)
{
    const QString regionName = GetKernelMemoryRegionName(oep);
    if (regionName.isEmpty() || regionName == QStringLiteral("[unknown region]")) {
        return QStringLiteral("-");
    }
    return regionName;
}

QString formatHardwarePteProtectSummary(std::uint64_t pte)
{
    if (pte == 0) {
        return QStringLiteral("-");
    }

    const bool present = (pte & 0x1) != 0;
    const bool writable = (pte & 0x2) != 0;
    const bool executable = (pte & 0x8000000000000000ull) == 0;

    if (!present) {
        return QStringLiteral("NP");
    }
    if (writable && executable) {
        return QStringLiteral("RWX");
    }
    if (!writable && executable) {
        return QStringLiteral("RX");
    }
    if (writable && !executable) {
        return QStringLiteral("RW");
    }
    return QStringLiteral("R");
}

bool isHardwarePteRwx(std::uint64_t pte)
{
    if ((pte & 0x1) == 0) {
        return false;
    }
    return (pte & 0x2) != 0 && (pte & 0x8000000000000000ull) == 0;
}

bool queryUserOepProtect(HANDLE processHandle, std::uint64_t oep, QString* outProtect, bool* outIsRwx)
{
    if (processHandle == nullptr || outProtect == nullptr || oep == 0) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(
            processHandle,
            reinterpret_cast<LPCVOID>(oep),
            &mbi,
            sizeof(mbi)) == 0)
    {
        return false;
    }

    *outProtect = formatUserProtectLabel(mbi.Protect);
    if (outIsRwx) {
        *outIsRwx = isUserProtectRwx(mbi.Protect);
    }
    return true;
}

bool isKernelNonImageRegion(std::uint64_t oep)
{
    KERNEL_VA_REGION regionIn = { 0 };
    KERNEL_VA_REGION regionOut = { 0 };
    regionIn.va = oep;
    GetKernelVaRegion(&regionIn, &regionOut);
    if (regionOut.va == 0) {
        return false;
    }
    return regionOut.mRegion != 12;
}

bool queryKernelOepDetails(
    std::uint32_t pid,
    std::uint64_t oep,
    QString* outRegion,
    QString* outProtect,
    bool* outIsRwx)
{
    if (outRegion == nullptr || outProtect == nullptr) {
        return false;
    }

    *outRegion = formatKernelRegionLabel(oep);

    GET_VIRTUAL_ADDRESS_PTE pteQuery = { 0 };
    pteQuery.pid = pid;
    pteQuery.va = oep;
    GetVirtualAddressPte(&pteQuery);
    if (pteQuery.errCode != 1) {
        *outProtect = QStringLiteral("-");
        if (outIsRwx) {
            *outIsRwx = false;
        }
        return false;
    }

    *outProtect = formatHardwarePteProtectSummary(pteQuery.pteData);
    if (outIsRwx) {
        *outIsRwx = isHardwarePteRwx(pteQuery.pteData);
    }
    return true;
}

void emitLine(const ListPtOutput& output, const QString& line)
{
    if (output.line) {
        output.line(line);
    }
}

void emitColoredLine(const ListPtOutput& output, const QString& line, const QColor& color)
{
    if (output.coloredLine) {
        output.coloredLine(line, color);
        return;
    }
    emitLine(output, line);
}

bool queryKernelRegionNumber(std::uint64_t oep, std::uint32_t* outRegion, QString* outRegionLabel)
{
    KERNEL_VA_REGION regionIn = { 0 };
    KERNEL_VA_REGION regionOut = { 0 };
    regionIn.va = oep;
    GetKernelVaRegion(&regionIn, &regionOut);
    if (regionOut.va == 0) {
        return false;
    }

    if (outRegion) {
        *outRegion = regionOut.mRegion;
    }
    if (outRegionLabel) {
        *outRegionLabel = formatKernelRegionLabel(oep);
    }
    return true;
}

bool isHighRiskKernelThreadOep(std::uint64_t oep, std::uint32_t* outRegion)
{
    if (!isKernelCanonicalAddress(oep)) {
        return false;
    }

    std::uint32_t region = 0;
    if (!queryKernelRegionNumber(oep, &region, nullptr)) {
        return false;
    }

    if (outRegion) {
        *outRegion = region;
    }
    return region == 5 || region == 9;
}

} // namespace

bool runListPt(std::uint32_t pid, const ListPtOutput& output, QString* outError)
{
    if (!Process::isPlausiblePid(pid)) {
        if (outError) {
            *outError = QString("Invalid PID %1.").arg(pid);
        }
        return false;
    }

    const std::vector<Process::ThreadInfo> threads = Process::enumerateThreads(pid);
    if (threads.empty()) {
        if (outError) {
            *outError = QString("No threads found for PID %1 (process may have exited).").arg(pid);
        }
        return false;
    }

    const std::wstring processPathW = Process::getPath(pid);
    const QString processPath = processPathW.empty()
        ? QStringLiteral("(path unavailable)")
        : QString::fromStdWString(convertSystemRootPathW(processPathW.c_str()));

    emitLine(output, QString("PID %1  %2").arg(pid).arg(processPath));
    emitLine(output, QString("Threads: %1").arg(threads.size()));
    emitLine(output, QStringLiteral("TID        OEP                  Region               Protect"));
    emitLine(output, QStringLiteral("---------  -------------------  -------------------  -------"));

    const ScopedHandle processHandle(Process::openForQuery(pid));

    std::vector<Process::ThreadInfo> sortedThreads = threads;
    std::sort(sortedThreads.begin(), sortedThreads.end(), [](const Process::ThreadInfo& left,
                                                            const Process::ThreadInfo& right) {
        return left.tid < right.tid;
    });

    for (const Process::ThreadInfo& thread : sortedThreads)
    {
        const QString tidText = QString("%1").arg(thread.tid, 9);
        const QString oepText = thread.oepAvailable
            ? formatOep(thread.oep)
            : QStringLiteral("(unavailable)");

        QString regionText = QStringLiteral("-");
        QString protectText = QStringLiteral("-");
        bool highlight = false;

        if (thread.oepAvailable)
        {
            if (isKernelCanonicalAddress(thread.oep)) {
                bool isRwx = false;
                queryKernelOepDetails(pid, thread.oep, &regionText, &protectText, &isRwx);
                highlight = isKernelNonImageRegion(thread.oep) || isRwx;
            }
            else if (processHandle.get() != nullptr) {
                bool isRwx = false;
                queryUserOepProtect(
                    static_cast<HANDLE>(processHandle.get()),
                    thread.oep,
                    &protectText,
                    &isRwx);
                highlight = isRwx;
            }
        }

        const QString row = QString("%1  %2  %3  %4")
            .arg(tidText, -9)
            .arg(oepText, -19)
            .arg(regionText, -19)
            .arg(protectText);
        if (highlight) {
            emitColoredLine(output, row, QColor(180, 0, 0));
        } else {
            emitLine(output, row);
        }
    }

    return true;
}

bool runListPtTriage(std::uint32_t pid, ListPtTriageResult* out)
{
    if (out == nullptr) {
        return false;
    }

    *out = ListPtTriageResult{};
    out->pid = pid;

    if (!Process::isPlausiblePid(pid)) {
        out->error = QString("Invalid PID %1.").arg(pid);
        return false;
    }

    const std::vector<Process::ThreadInfo> threads = Process::enumerateThreads(pid);
    if (threads.empty()) {
        out->error = QString("No threads found for PID %1 (process may have exited).").arg(pid);
        return false;
    }

    out->ok = true;
    out->threadCount = static_cast<int>(threads.size());

    for (const Process::ThreadInfo& thread : threads)
    {
        if (!thread.oepAvailable || thread.oep == 0) {
            continue;
        }

        std::uint32_t region = 0;
        if (!isHighRiskKernelThreadOep(thread.oep, &region)) {
            continue;
        }

        QString regionLabel;
        QString protectLabel;
        bool isRwx = false;
        queryKernelRegionNumber(thread.oep, nullptr, &regionLabel);
        queryKernelOepDetails(pid, thread.oep, &regionLabel, &protectLabel, &isRwx);

        ListPtThreadFinding finding;
        finding.tid = thread.tid;
        finding.oep = thread.oep;
        finding.kernelRegion = region;
        finding.regionLabel = regionLabel;
        finding.protectLabel = protectLabel;
        finding.isRwx = isRwx;
        out->findings.push_back(finding);
    }

    out->highRiskCount = static_cast<int>(out->findings.size());
    return true;
}
