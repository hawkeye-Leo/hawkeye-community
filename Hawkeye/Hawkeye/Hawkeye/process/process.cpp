#include "process.h"

#include "PathConvert.h"
#include "common.h"

#include <Windows.h>
#include <Psapi.h>

#include <memory>
#include <set>
#include <vector>
#include"Driver.h"

#pragma comment(lib, "Psapi.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace {

using NtStatus = LONG;
constexpr NtStatus kStatusInfoLengthMismatch = static_cast<NtStatus>(0xC0000004L);
constexpr std::uint64_t kMinKernelModuleBase = 0xFFFF000000000000ULL;

struct UnicodeString
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct SystemProcessInformation
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UnicodeString ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
};

struct ClientIdPair
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct SystemThreadInformation
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    ClientIdPair ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct SystemProcessInformationWithThreads
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UnicodeString ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SystemThreadInformation Threads[1];
};

enum class SystemInformationClass : ULONG
{
    ProcessInformation = 5,
    ModuleInformation = 11,
};

enum class MemoryInformationClass : ULONG
{
    BasicInformation = 0,
};

using ZwQueryVirtualMemoryFn = NtStatus(NTAPI*)(
    HANDLE processHandle,
    PVOID baseAddress,
    MemoryInformationClass memoryInformationClass,
    PVOID buffer,
    SIZE_T length,
    PSIZE_T resultLength);

struct MemoryBasicInformation64
{
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    ULONG AllocationProtect;
    ULONG __alignment1;
    ULONGLONG RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
    ULONG __alignment2;
};

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

using NtQuerySystemInformationFn = NtStatus(NTAPI*)(
    SystemInformationClass systemInformationClass,
    PVOID systemInformation,
    ULONG systemInformationLength,
    PULONG returnLength);

NtQuerySystemInformationFn queryNtSystemInformation()
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return nullptr;
    }

    return reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "ZwQuerySystemInformation"));
}

ZwQueryVirtualMemoryFn queryVirtualMemory()
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return nullptr;
    }

    return reinterpret_cast<ZwQueryVirtualMemoryFn>(
        GetProcAddress(ntdll, "ZwQueryVirtualMemory"));
}

std::wstring ansiToWide(const char* value)
{
    if (!value || value[0] == '\0') {
        return L"";
    }

    const int length = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (length <= 0) {
        return L"";
    }

    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, &result[0], length);
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

} // namespace

void enableDebugPrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return;
    }

    TOKEN_PRIVILEGES privileges{};
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    }

    CloseHandle(token);
}

namespace {

std::wstring convertNtPathToDosPath(std::wstring ntPath)
{
    if (ntPath.empty()) {
        return ntPath;
    }

    wchar_t driveStrings[512] = {};
    if (!GetLogicalDriveStringsW(static_cast<DWORD>(sizeof(driveStrings) / sizeof(driveStrings[0])), driveStrings)) {
        return ntPath;
    }

    for (wchar_t* drive = driveStrings; *drive != L'\0'; drive += wcslen(drive) + 1) {
        wchar_t deviceName[128] = {};
        if (!QueryDosDeviceW(drive, deviceName, static_cast<DWORD>(sizeof(deviceName) / sizeof(deviceName[0])))) {
            continue;
        }

        const size_t deviceLength = wcslen(deviceName);
        if (_wcsnicmp(ntPath.c_str(), deviceName, deviceLength) != 0) {
            continue;
        }

        std::wstring dosPath = drive;
        dosPath += ntPath.substr(deviceLength);
        return dosPath;
    }

    return ntPath;
}

bool isNtDevicePath(const std::wstring& path)
{
    return path.compare(0, 8, L"\\Device\\") == 0
        || path.compare(0, 4, L"\\??\\") == 0;
}

std::wstring ensureDosPath(std::wstring path)
{
    if (path.empty() || !isNtDevicePath(path)) {
        return path;
    }

    return convertNtPathToDosPath(std::move(path));
}

std::wstring imageNameFromEntry(const SystemProcessInformation* entry)
{
    if (!entry->ImageName.Buffer || entry->ImageName.Length == 0) {
        return L"";
    }

    return std::wstring(
        entry->ImageName.Buffer,
        entry->ImageName.Length / sizeof(wchar_t));
}

std::wstring queryWin32ProcessImagePath(HANDLE process)
{
    using QueryFullProcessImageNameFn = BOOL(WINAPI*)(HANDLE, DWORD, LPWSTR, PDWORD);
    const auto queryFullProcessImageName = reinterpret_cast<QueryFullProcessImageNameFn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW"));
    if (!queryFullProcessImageName) {
        return L"";
    }

    DWORD capacity = MAX_PATH;
    std::wstring path(capacity, L'\0');
    while (capacity <= 32768) {
        DWORD length = capacity;
        if (queryFullProcessImageName(process, 0, &path[0], &length)) {
            path.resize(length);
            return path;
        }

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return L"";
        }

        capacity *= 2;
        path.resize(capacity);
    }

    return L"";
}

std::wstring queryPsapiProcessImagePath(HANDLE process)
{
    wchar_t imagePath[MAX_PATH] = {};
    if (GetProcessImageFileNameW(process, imagePath, MAX_PATH) == 0) {
        return L"";
    }

    return convertNtPathToDosPath(imagePath);
}

std::wstring queryNtProcessImagePath(HANDLE process)
{
    using NtQueryInformationProcessFn = NtStatus(NTAPI*)(
        HANDLE processHandle,
        ULONG processInformationClass,
        PVOID processInformation,
        ULONG processInformationLength,
        PULONG returnLength);

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return L"";
    }

    const auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!ntQueryInformationProcess) {
        return L"";
    }

    std::vector<std::uint8_t> buffer(4096);
    constexpr ULONG kProcessImageFileName = 27;
    const NtStatus status = ntQueryInformationProcess(
        process,
        kProcessImageFileName,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        nullptr);
    if (status < 0) {
        return L"";
    }

    const auto* imageName = reinterpret_cast<const UnicodeString*>(buffer.data());
    if (!imageName->Buffer || imageName->Length == 0) {
        return L"";
    }

    return convertNtPathToDosPath(std::wstring(
        imageName->Buffer,
        imageName->Length / sizeof(wchar_t)));
}

std::wstring resolveProcessPath(DWORD pid, const std::wstring& imageNameHint)
{
    if (pid == 0) {
        return L"System Idle Process";
    }

    if (pid == 4) {
        return L"System";
    }

    const HANDLE process = Process::openForQuery(pid);
    if (!process) {
        return L"";
    }

    const auto closer = [](HANDLE handle) { CloseHandle(handle); };
    std::unique_ptr<void, decltype(closer)> processGuard(process, closer);

    std::wstring path = queryWin32ProcessImagePath(process);
    if (!path.empty()) {
        return ensureDosPath(std::move(path));
    }

    path = queryPsapiProcessImagePath(process);
    if (!path.empty()) {
        return ensureDosPath(std::move(path));
    }

    path = queryNtProcessImagePath(process);
    if (!path.empty()) {
        return ensureDosPath(std::move(path));
    }

    return imageNameHint.empty() ? L"path unavailable" : imageNameHint;
}

std::vector<std::uint8_t> queryProcessInformationBuffer(NtQuerySystemInformationFn queryFn)
{
    std::vector<std::uint8_t> buffer(256 * 1024);
    ULONG returnLength = 0;

    for (;;) {
        const NtStatus status = queryFn(
            SystemInformationClass::ProcessInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &returnLength);

        if (status >= 0) {
            return buffer;
        }

        if (status != kStatusInfoLengthMismatch || returnLength == 0) {
            return {};
        }

        buffer.resize(returnLength + 4096);
    }
}

std::vector<Process::Info> parseProcessList(const std::vector<std::uint8_t>& buffer)
{
    std::vector<Process::Info> processes;
    if (buffer.empty()) {
        return processes;
    }

    const auto* entry = reinterpret_cast<const SystemProcessInformation*>(buffer.data());
    while (entry != nullptr) {
        Process::Info info;
        info.pid = static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(entry->UniqueProcessId));
        info.path = resolveProcessPath(info.pid, imageNameFromEntry(entry));
        processes.push_back(std::move(info));

        if (entry->NextEntryOffset == 0) {
            break;
        }

        entry = reinterpret_cast<const SystemProcessInformation*>(
            reinterpret_cast<const std::uint8_t*>(entry) + entry->NextEntryOffset);
    }

    return processes;
}

Process::VisibleProcessThreads parseVisibleProcessThreads(const std::vector<std::uint8_t>& buffer)
{
    Process::VisibleProcessThreads visible;
    if (buffer.empty()) {
        return visible;
    }

    std::set<std::uint32_t> pidSet;
    std::set<std::uint32_t> tidSet;

    const auto* entry = reinterpret_cast<const SystemProcessInformationWithThreads*>(buffer.data());
    while (entry != nullptr) {
        const std::uint32_t pid = static_cast<std::uint32_t>(
            reinterpret_cast<ULONG_PTR>(entry->UniqueProcessId));
        if (pid < MAX_SAMPLE_TID) {
            pidSet.insert(pid);
        }

        for (ULONG threadIndex = 0; threadIndex < entry->NumberOfThreads; ++threadIndex) {
            const std::uint32_t tid = static_cast<std::uint32_t>(
                reinterpret_cast<ULONG_PTR>(entry->Threads[threadIndex].ClientId.UniqueThread));
            if (tid < MAX_SAMPLE_TID) {
                tidSet.insert(tid);
            }
        }

        if (entry->NextEntryOffset == 0) {
            break;
        }

        entry = reinterpret_cast<const SystemProcessInformationWithThreads*>(
            reinterpret_cast<const std::uint8_t*>(entry) + entry->NextEntryOffset);
    }

    visible.pids.assign(pidSet.begin(), pidSet.end());
    visible.tids.assign(tidSet.begin(), tidSet.end());
    return visible;
}

std::vector<std::uint8_t> querySystemModuleBuffer(NtQuerySystemInformationFn queryFn)
{
    std::vector<std::uint8_t> buffer(256 * 1024);
    ULONG returnLength = 0;

    for (;;) {
        const NtStatus status = queryFn(
            SystemInformationClass::ModuleInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &returnLength);

        if (status >= 0) {
            return buffer;
        }

        if (status != kStatusInfoLengthMismatch || returnLength == 0) {
            return {};
        }

        buffer.resize(returnLength + 4096);
    }
}

std::vector<Process::ModuleInfo> enumerateKernelModules()
{
    std::vector<Process::ModuleInfo> modules;
    const NtQuerySystemInformationFn queryFn = queryNtSystemInformation();
    if (!queryFn) {
        return modules;
    }

    const std::vector<std::uint8_t> buffer = querySystemModuleBuffer(queryFn);
    if (buffer.size() < sizeof(RTL_PROCESS_MODULES)) {
        return modules;
    }

    const auto* moduleList = reinterpret_cast<const RTL_PROCESS_MODULES*>(buffer.data());
    modules.reserve(moduleList->NumberOfModules);

    for (ULONG i = 0; i < moduleList->NumberOfModules; ++i) {
        const RTL_PROCESS_MODULE_INFORMATION& module = moduleList->Modules[i];
        const std::uint64_t imageBase = reinterpret_cast<std::uint64_t>(module.ImageBase);
        if (imageBase < kMinKernelModuleBase) {
            break;
        }

        Process::ModuleInfo info;
        info.base = imageBase;
        info.size = module.ImageSize;

        const char* modulePath = reinterpret_cast<const char*>(module.FullPathName);
        info.path = convertSystemRootPathW(ansiToWide(modulePath).c_str());
        modules.push_back(std::move(info));
    }

    return modules;
}

std::vector<Process::ModuleInfo> enumerateUserImageModules(std::uint32_t pid)
{
    std::vector<Process::ModuleInfo> modules;
    const ZwQueryVirtualMemoryFn queryVirtualMemoryFn = queryVirtualMemory();
    if (!queryVirtualMemoryFn) {
        return modules;
    }

    if (!Process::isPlausiblePid(pid) || pid == 4) {
        return modules;
    }

    OPEN_PROCESS_HANDLE inout = { 0 };
    inout.pid = pid;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return modules;
    }

    const HANDLE processHandle = (HANDLE)inout.processHandle;
    if (processHandle == NULL || processHandle == INVALID_HANDLE_VALUE) {
        return modules;
    }

    const auto closer = [](HANDLE handle) { CloseHandle(handle); };
    std::unique_ptr<void, decltype(closer)> processGuard(processHandle, closer);

    std::set<std::uint64_t> seenBases;
    PVOID address = nullptr;
    MemoryBasicInformation64 regionInfo{};

    while (NT_SUCCESS(queryVirtualMemoryFn(
        processHandle,
        address,
        MemoryInformationClass::BasicInformation,
        &regionInfo,
        sizeof(regionInfo),
        nullptr)))
    {
        if (regionInfo.State == MEM_COMMIT && regionInfo.Type == MEM_IMAGE) {
            const std::uint64_t moduleBase = regionInfo.AllocationBase;
            if (moduleBase != 0 && seenBases.insert(moduleBase).second) {
                Process::ModuleInfo info;
                info.base = moduleBase;

                MODULEINFO moduleInfo{};
                if (GetModuleInformation(
                        processHandle,
                        reinterpret_cast<HMODULE>(moduleBase),
                        &moduleInfo,
                        sizeof(moduleInfo)))
                {
                    info.size = moduleInfo.SizeOfImage;
                }

                GET_MODULE_PATH modulePathQuery = { 0 };
                modulePathQuery.pid = pid;
                modulePathQuery.va = moduleBase;
                GetModulePathByPid(&modulePathQuery);
                if (modulePathQuery.image == 1 && modulePathQuery.path[0] != L'\0') {
                    info.path = convertSystemRootPathW(modulePathQuery.path);
                } else {
                    wchar_t mappedPath[MAX_PATH + 256] = {};
                    if (GetMappedFileNameW(
                            processHandle,
                            reinterpret_cast<PVOID>(moduleBase),
                            mappedPath,
                            static_cast<DWORD>(sizeof(mappedPath) / sizeof(mappedPath[0]))) > 0)
                    {
                        info.path = ensureDosPath(mappedPath);
                    } else {
                        wchar_t modulePath[MAX_PATH] = {};
                        if (GetModuleFileNameExW(
                                processHandle,
                                reinterpret_cast<HMODULE>(moduleBase),
                                modulePath,
                                MAX_PATH) > 0)
                        {
                            info.path = modulePath;
                        }
                    }
                }

                modules.push_back(std::move(info));
            }
        }

        const ULONGLONG nextAddress = regionInfo.BaseAddress + regionInfo.RegionSize;
        if (nextAddress <= reinterpret_cast<ULONGLONG>(address)) {
            break;
        }

        address = reinterpret_cast<PVOID>(nextAddress);
    }

    return modules;
}

Process::VisibleProcessThreads collectVisibleProcessThreads()
{
    Process::VisibleProcessThreads visible;
    const NtQuerySystemInformationFn queryFn = queryNtSystemInformation();
    if (!queryFn) {
        return visible;
    }

    const std::vector<std::uint8_t> buffer = queryProcessInformationBuffer(queryFn);
    if (buffer.empty()) {
        return visible;
    }

    std::set<std::uint32_t> pidSet;
    std::set<std::uint32_t> tidSet;

    const auto* entry = reinterpret_cast<const SystemProcessInformationWithThreads*>(buffer.data());
    while (entry != nullptr) {
        const std::uint32_t pid = static_cast<std::uint32_t>(
            reinterpret_cast<ULONG_PTR>(entry->UniqueProcessId));
        if (pid < MAX_SAMPLE_TID) {
            pidSet.insert(pid);
        }

        for (ULONG threadIndex = 0; threadIndex < entry->NumberOfThreads; ++threadIndex) {
            const std::uint32_t tid = static_cast<std::uint32_t>(
                reinterpret_cast<ULONG_PTR>(entry->Threads[threadIndex].ClientId.UniqueThread));
            if (tid < MAX_SAMPLE_TID) {
                tidSet.insert(tid);
            }
        }

        if (entry->NextEntryOffset == 0) {
            break;
        }

        entry = reinterpret_cast<const SystemProcessInformationWithThreads*>(
            reinterpret_cast<const std::uint8_t*>(entry) + entry->NextEntryOffset);
    }

    visible.pids.assign(pidSet.begin(), pidSet.end());
    visible.tids.assign(tidSet.begin(), tidSet.end());
    return visible;
}

constexpr ULONG kThreadQuerySetWin32StartAddress = 9;

bool queryThreadWin32StartAddress(std::uint32_t tid, std::uint64_t* outAddress)
{
    if (outAddress == nullptr || tid == 0) {
        return false;
    }

    HANDLE threadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (threadHandle == nullptr) {
        threadHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    }
    if (threadHandle == nullptr) {
        return false;
    }

    using NtQueryInformationThreadFn = NtStatus(NTAPI*)(
        HANDLE threadHandle,
        ULONG threadInformationClass,
        PVOID threadInformation,
        ULONG threadInformationLength,
        PULONG returnLength);

    static const NtQueryInformationThreadFn ntQueryInformationThread =
        reinterpret_cast<NtQueryInformationThreadFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    if (ntQueryInformationThread == nullptr) {
        CloseHandle(threadHandle);
        return false;
    }

    PVOID startAddress = nullptr;
    const NtStatus status = ntQueryInformationThread(
        threadHandle,
        kThreadQuerySetWin32StartAddress,
        &startAddress,
        sizeof(startAddress),
        nullptr);
    CloseHandle(threadHandle);
    if (!NT_SUCCESS(status) || startAddress == nullptr) {
        return false;
    }

    *outAddress = reinterpret_cast<std::uint64_t>(startAddress);
    return true;
}

std::vector<Process::ThreadInfo> collectThreadsForProcess(
    const std::vector<std::uint8_t>& buffer,
    std::uint32_t pid)
{
    std::vector<Process::ThreadInfo> threads;
    const auto* entry = reinterpret_cast<const SystemProcessInformationWithThreads*>(buffer.data());
    while (entry != nullptr) {
        const std::uint32_t entryPid = static_cast<std::uint32_t>(
            reinterpret_cast<ULONG_PTR>(entry->UniqueProcessId));
        if (entryPid == pid) {
            threads.reserve(entry->NumberOfThreads);
            for (ULONG threadIndex = 0; threadIndex < entry->NumberOfThreads; ++threadIndex) {
                const SystemThreadInformation& thread = entry->Threads[threadIndex];
                const std::uint32_t tid = static_cast<std::uint32_t>(
                    reinterpret_cast<ULONG_PTR>(thread.ClientId.UniqueThread));
                if (tid == 0) {
                    continue;
                }

                Process::ThreadInfo info;
                info.tid = tid;

                if (queryThreadWin32StartAddress(tid, &info.oep)) {
                    info.oepAvailable = true;
                } else if (thread.StartAddress != nullptr) {
                    info.oep = reinterpret_cast<std::uint64_t>(thread.StartAddress);
                    info.oepAvailable = true;
                }

                threads.push_back(info);
            }
            break;
        }

        if (entry->NextEntryOffset == 0) {
            break;
        }

        entry = reinterpret_cast<const SystemProcessInformationWithThreads*>(
            reinterpret_cast<const std::uint8_t*>(entry) + entry->NextEntryOffset);
    }

    return threads;
}

} // namespace

std::vector<Process::ThreadInfo> Process::enumerateThreads(std::uint32_t pid)
{
    if (!isPlausiblePid(pid)) {
        return {};
    }

    const NtQuerySystemInformationFn queryFn = queryNtSystemInformation();
    if (!queryFn) {
        return {};
    }

    const std::vector<std::uint8_t> buffer = queryProcessInformationBuffer(queryFn);
    if (buffer.empty()) {
        return {};
    }

    return collectThreadsForProcess(buffer, pid);
}

std::wstring Process::getPath(std::uint32_t pid)
{
    return resolveProcessPath(pid, L"");
}

HANDLE Process::openForQuery(std::uint32_t pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process) {
        return process;
    }

    OPEN_PROCESS_HANDLE inout = { 0 };
    inout.pid = pid;
    inout.desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return nullptr;
    }

    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(inout.processHandle));
}

HANDLE Process::openForRemotePatch(std::uint32_t pid)
{
    const DWORD access =
        PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ;

    HANDLE process = OpenProcess(access, FALSE, pid);
    if (process != NULL) {
        return process;
    }

    OPEN_PROCESS_HANDLE inout = { 0 };
    inout.pid = pid;
    inout.desiredAccess = 0;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return nullptr;
    }

    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(inout.processHandle));
}

std::vector<std::uint32_t> Process::findPidsByName(const std::wstring& name)
{
    std::vector<std::uint32_t> pids;
    if (name.empty()) {
        return pids;
    }

    const auto processes = Process::enumerate();
    for (const auto& proc : processes) {
        const std::size_t pos = proc.path.find_last_of(L"\\/");
        const std::wstring fileName = (pos == std::wstring::npos) ? proc.path : proc.path.substr(pos + 1);
        if (_wcsicmp(fileName.c_str(), name.c_str()) == 0) {
            pids.push_back(proc.pid);
        }
    }

    return pids;
}

std::vector<Process::Info> Process::enumerate()
{
    const NtQuerySystemInformationFn queryFn = queryNtSystemInformation();
    if (!queryFn) {
        return {};
    }

    const std::vector<std::uint8_t> buffer = queryProcessInformationBuffer(queryFn);
    if (buffer.empty()) {
        return {};
    }

    return parseProcessList(buffer);
}

Process::VisibleProcessThreads Process::enumerateVisibleProcessThreads()
{
    return collectVisibleProcessThreads();
}

bool Process::isPlausiblePid(std::uint32_t pid)
{
    if (pid == 0) {
        return false;
    }

    if (pid == 4) {
        return true;
    }

    return pid > 4
        && pid < MAX_SAMPLE_TID
        && (pid % 4) == 0;
}

std::vector<Process::ModuleInfo> Process::enumerateModules(std::uint32_t pid)
{
    if (pid == 4) {
        return enumerateKernelModules();
    }

    if (Process::isPlausiblePid(pid) && pid > 4) {
        return enumerateUserImageModules(pid);
    }

    return {};
}
