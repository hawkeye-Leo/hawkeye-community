#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "inline_hook_sim.h"

#include "inject_sim.h"
#include "process.h"

#include <cstdint>
#include <vector>

namespace {

constexpr std::uintptr_t kPatchRegionRva = 0x1000;
constexpr std::size_t kPatchScanSize = 0x1000;

InlineHookSimOutcome Fail(const QString& message, std::uint32_t pid = 0)
{
    InlineHookSimOutcome out;
    out.ok = false;
    out.error = message;
    out.pid = pid;
    return out;
}

QString Win32ErrorString(DWORD error)
{
    return QString("Win32 error %1").arg(error);
}

bool ReadRemoteBytes(HANDLE process, std::uintptr_t address, std::size_t size, std::vector<std::uint8_t>& buffer)
{
    buffer.assign(size, 0);
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(
               process,
               reinterpret_cast<LPCVOID>(address),
               buffer.data(),
               buffer.size(),
               &bytesRead) == TRUE
        && bytesRead == buffer.size();
}

bool WriteRemoteByte(HANDLE process, std::uintptr_t address, std::uint8_t value)
{
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(
               process,
               reinterpret_cast<LPVOID>(address),
               &value,
               sizeof(value),
               &bytesWritten) == TRUE
        && bytesWritten == sizeof(value);
}

} // namespace

InlineHookSimOutcome InlineHookSimStart(std::uint32_t pid, const InlineHookSimState& currentState)
{
    if (currentState.active) {
        return Fail(QStringLiteral("inline hook simulation is already active (use !inline_hook_sim -stop first)"), pid);
    }

    if (!Process::isPlausiblePid(pid) || pid <= 4) {
        return Fail(QStringLiteral("invalid target PID"), pid);
    }

    const DWORD selfPid = GetCurrentProcessId();
    if (pid == selfPid) {
        return Fail(QStringLiteral("refusing to patch Hawkeye itself"), pid);
    }

    enableDebugPrivilege();

    InlineHookSimOutcome out;
    out.pid = pid;

    const std::uintptr_t moduleBase = InjectSimFindRemoteModuleBase(pid);
    if (moduleBase == 0) {
        return Fail(
            QStringLiteral("HawkUnsignedStub.dll is not loaded in PID:%1 (inject separately with !inject_sim if needed)")
                .arg(pid),
            pid);
    }

    QString openError;
    HANDLE process = Process::openForRemotePatch(pid);
    if (process == NULL) {
        openError = Win32ErrorString(GetLastError());
        return Fail(QStringLiteral("OpenProcess failed: %1").arg(openError), pid);
    }

    const std::uintptr_t scanBase = moduleBase + kPatchRegionRva;
    std::vector<std::uint8_t> region(kPatchScanSize);
    if (!ReadRemoteBytes(process, scanBase, kPatchScanSize, region)) {
        CloseHandle(process);
        return Fail(
            QStringLiteral("ReadProcessMemory failed at 0x%1").arg(scanBase, 0, 16),
            pid);
    }

    std::vector<std::uintptr_t> patchAddresses;
    for (std::size_t offset = 0; offset + 1 < region.size(); ++offset) {
        if (region[offset] == 0xCC && region[offset + 1] == 0xCC) {
            patchAddresses.push_back(scanBase + offset);
        }
    }

    if (patchAddresses.empty()) {
        CloseHandle(process);
        return Fail(
            QStringLiteral("no 0xCC 0xCC pattern found at module+0x%1 (size 0x%2)")
                .arg(kPatchRegionRva, 0, 16)
                .arg(static_cast<qulonglong>(kPatchScanSize), 0, 16),
            pid);
    }

    for (const std::uintptr_t patchAddress : patchAddresses) {
        if (!WriteRemoteByte(process, patchAddress, 0x90)) {
            const DWORD error = GetLastError();
            CloseHandle(process);
            return Fail(
                QStringLiteral("WriteProcessMemory failed at 0x%1 (Win32 error %2)")
                    .arg(patchAddress, 0, 16)
                    .arg(error),
                pid);
        }
    }

    CloseHandle(process);

    out.ok = true;
    out.remoteModule = moduleBase;
    out.patchedAddresses = std::move(patchAddresses);
    return out;
}

InlineHookSimOutcome InlineHookSimStop(const InlineHookSimState& state)
{
    if (!state.active) {
        return Fail(QStringLiteral("inline hook simulation is not active"));
    }

    if (state.patchedAddresses.empty()) {
        InlineHookSimOutcome out;
        out.ok = true;
        out.pid = state.pid;
        out.remoteModule = state.remoteModule;
        return out;
    }

    enableDebugPrivilege();

    QString openError;
    HANDLE process = Process::openForRemotePatch(state.pid);
    if (process == NULL) {
        openError = Win32ErrorString(GetLastError());
        return Fail(QStringLiteral("OpenProcess failed: %1").arg(openError), state.pid);
    }

    for (const std::uintptr_t patchAddress : state.patchedAddresses) {
        std::uint8_t current = 0;
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(
                process,
                reinterpret_cast<LPCVOID>(patchAddress),
                &current,
                sizeof(current),
                &bytesRead) != TRUE
            || bytesRead != sizeof(current))
        {
            CloseHandle(process);
            return Fail(
                QStringLiteral("ReadProcessMemory failed at 0x%1 during restore").arg(patchAddress, 0, 16),
                state.pid);
        }

        if (current == 0xCC) {
            continue;
        }

        if (!WriteRemoteByte(process, patchAddress, 0xCC)) {
            const DWORD error = GetLastError();
            CloseHandle(process);
            return Fail(
                QStringLiteral("WriteProcessMemory restore failed at 0x%1 (Win32 error %2)")
                    .arg(patchAddress, 0, 16)
                    .arg(error),
                state.pid);
        }
    }

    CloseHandle(process);

    InlineHookSimOutcome out;
    out.ok = true;
    out.pid = state.pid;
    out.remoteModule = state.remoteModule;
    out.patchedAddresses = state.patchedAddresses;
    return out;
}
