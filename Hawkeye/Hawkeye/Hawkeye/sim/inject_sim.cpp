#include "inject_sim.h"

#include "process.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

#include <Windows.h>

namespace {

constexpr wchar_t kStubModuleName[] = L"HawkUnsignedStub.dll";

QString Win32ErrorString(DWORD error)
{
    return QString("Win32 error %1").arg(error);
}

HANDLE OpenTargetProcess(std::uint32_t pid, QString* errorOut)
{
    HANDLE process = Process::openForRemotePatch(pid);
    if (process != NULL) {
        return process;
    }

    const DWORD error = GetLastError();
    if (errorOut != nullptr) {
        *errorOut = Win32ErrorString(error);
    }
    return NULL;
}

InjectSimOutcome Fail(const QString& message, std::uint32_t pid = 0)
{
    InjectSimOutcome out;
    out.ok = false;
    out.error = message;
    out.pid = pid;
    return out;
}

std::uintptr_t FindRemoteModuleBase(std::uint32_t pid)
{
    const std::vector<Process::ModuleInfo> modules = Process::enumerateModules(pid);
    for (const Process::ModuleInfo& mod : modules) {
        if (mod.base == 0 || mod.path.empty()) {
            continue;
        }

        const std::wstring fileName = mod.path.substr(mod.path.find_last_of(L"\\/") + 1);
        if (_wcsicmp(fileName.c_str(), kStubModuleName) == 0) {
            return static_cast<std::uintptr_t>(mod.base);
        }
    }

    return 0;
}

bool RemoteModuleLoaded(std::uint32_t pid)
{
    return FindRemoteModuleBase(pid) != 0;
}

} // namespace

std::uintptr_t InjectSimFindRemoteModuleBase(std::uint32_t pid)
{
    return FindRemoteModuleBase(pid);
}

bool InjectSimResolveStubPath(QString* dllPathOut, QString* errorOut)
{
    if (dllPathOut == nullptr) {
        if (errorOut) {
            *errorOut = QStringLiteral("internal error: null dllPathOut");
        }
        return false;
    }

    const QString simDir = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("sim"));
    const QString dllPath = QDir(simDir).filePath(QStringLiteral("HawkUnsignedStub.dll"));
    if (!QFileInfo::exists(dllPath)) {
        if (errorOut) {
            *errorOut = QStringLiteral("stub DLL not found: %1").arg(QDir::toNativeSeparators(dllPath));
        }
        return false;
    }

    *dllPathOut = QDir::toNativeSeparators(QFileInfo(dllPath).absoluteFilePath());
    return true;
}

InjectSimOutcome InjectSimLoad(std::uint32_t pid)
{
    if (!Process::isPlausiblePid(pid)) {
        return Fail(QStringLiteral("invalid target PID"), pid);
    }

    if (pid <= 4) {
        return Fail(QStringLiteral("refusing to inject into system or invalid PID"), pid);
    }

    const DWORD selfPid = GetCurrentProcessId();
    if (pid == selfPid) {
        return Fail(QStringLiteral("refusing to inject into Hawkeye itself"), pid);
    }

    enableDebugPrivilege();

    QString dllPath;
    QString resolveError;
    if (!InjectSimResolveStubPath(&dllPath, &resolveError)) {
        return Fail(resolveError, pid);
    }

    const std::wstring dllPathW = dllPath.toStdWString();
    const SIZE_T pathBytes = (dllPathW.size() + 1) * sizeof(wchar_t);

    QString openError;
    HANDLE process = OpenTargetProcess(pid, &openError);
    if (process == NULL) {
        return Fail(QStringLiteral("OpenProcess failed: %1").arg(openError), pid);
    }

    LPVOID remotePath = VirtualAllocEx(process, NULL, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remotePath == NULL) {
        const DWORD error = GetLastError();
        CloseHandle(process);
        return Fail(QStringLiteral("VirtualAllocEx failed: %1").arg(Win32ErrorString(error)), pid);
    }

    InjectSimOutcome out;
    out.dllPath = dllPath;
    out.pid = pid;

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(process, remotePath, dllPathW.c_str(), pathBytes, &bytesWritten)
        || bytesWritten != pathBytes)
    {
        const DWORD error = GetLastError();
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return Fail(QStringLiteral("WriteProcessMemory failed: %1").arg(Win32ErrorString(error)), pid);
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == NULL) {
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return Fail(QStringLiteral("GetModuleHandleW(kernel32) failed"), pid);
    }

    const FARPROC loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW");
    if (loadLibraryW == NULL) {
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return Fail(QStringLiteral("GetProcAddress(LoadLibraryW) failed"), pid);
    }

    HANDLE remoteThread = CreateRemoteThread(
        process,
        NULL,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryW),
        remotePath,
        0,
        NULL);
    if (remoteThread == NULL) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        CloseHandle(process);
        return Fail(QStringLiteral("CreateRemoteThread(LoadLibraryW) failed: %1").arg(Win32ErrorString(error)), pid);
    }

    WaitForSingleObject(remoteThread, 30000);

    DWORD exitCode = 0;
    GetExitCodeThread(remoteThread, &exitCode);
    CloseHandle(remoteThread);
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);

    if (exitCode == 0 && !RemoteModuleLoaded(pid)) {
        return Fail(QStringLiteral("LoadLibraryW returned NULL in target process (unsigned stub not loaded)"), pid);
    }

    const std::uintptr_t moduleBase = FindRemoteModuleBase(pid);
    if (moduleBase == 0) {
        return Fail(QStringLiteral("LoadLibrary finished but HawkUnsignedStub.dll was not found in the target module list"), pid);
    }

    out.ok = true;
    out.remoteModule = moduleBase;
    return out;
}

InjectSimOutcome InjectSimUnload(const InjectSimState& state)
{
    if (!state.active || state.pid == 0) {
        return Fail(QStringLiteral("inject simulation is not active"));
    }

    enableDebugPrivilege();

    std::uintptr_t moduleBase = FindRemoteModuleBase(state.pid);
    if (moduleBase == 0) {
        InjectSimOutcome out;
        out.ok = true;
        out.pid = state.pid;
        out.dllPath = state.dllPath;
        out.error = QStringLiteral("stub already unloaded");
        return out;
    }

    QString openError;
    HANDLE process = OpenTargetProcess(state.pid, &openError);
    if (process == NULL) {
        return Fail(QStringLiteral("OpenProcess failed: %1").arg(openError), state.pid);
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const FARPROC freeLibrary = kernel32 ? GetProcAddress(kernel32, "FreeLibrary") : NULL;
    if (freeLibrary == NULL) {
        CloseHandle(process);
        return Fail(QStringLiteral("GetProcAddress(FreeLibrary) failed"), state.pid);
    }

    HANDLE remoteThread = CreateRemoteThread(
        process,
        NULL,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibrary),
        reinterpret_cast<LPVOID>(moduleBase),
        0,
        NULL);
    if (remoteThread == NULL) {
        const DWORD error = GetLastError();
        CloseHandle(process);
        return Fail(QStringLiteral("CreateRemoteThread(FreeLibrary) failed: %1").arg(Win32ErrorString(error)), state.pid);
    }

    WaitForSingleObject(remoteThread, 30000);

    DWORD exitCode = 0;
    GetExitCodeThread(remoteThread, &exitCode);
    CloseHandle(remoteThread);
    CloseHandle(process);

    InjectSimOutcome out;
    out.pid = state.pid;
    out.dllPath = state.dllPath;
    out.remoteModule = moduleBase;

    if (!RemoteModuleLoaded(state.pid)) {
        out.ok = true;
        return out;
    }

    if (exitCode == 0) {
        out.error = QStringLiteral("FreeLibrary returned FALSE and HawkUnsignedStub.dll is still loaded");
        return out;
    }

    out.ok = true;
    return out;
}
