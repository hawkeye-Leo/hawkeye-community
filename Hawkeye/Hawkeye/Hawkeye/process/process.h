#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

class Process
{
public:
    struct Info
    {
        std::uint32_t pid = 0;
        std::wstring path;
    };

    struct ModuleInfo
    {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        std::wstring path;
    };

    struct VisibleProcessThreads
    {
        std::vector<std::uint32_t> pids;
        std::vector<std::uint32_t> tids;
    };

    struct ThreadInfo
    {
        std::uint32_t tid = 0;
        std::uint64_t oep = 0;
        bool oepAvailable = false;
    };

    static std::vector<Info> enumerate();
    static VisibleProcessThreads enumerateVisibleProcessThreads();
    static std::vector<ThreadInfo> enumerateThreads(std::uint32_t pid);
    static std::vector<ModuleInfo> enumerateModules(std::uint32_t pid);
    static std::wstring getPath(std::uint32_t pid);
    static std::vector<std::uint32_t> findPidsByName(const std::wstring& name);
    static HANDLE openForQuery(std::uint32_t pid);
    static HANDLE openForRemotePatch(std::uint32_t pid);

    /* Windows PIDs are typically 4-byte aligned; pid 4 is the kernel pseudo-process. */
    static bool isPlausiblePid(std::uint32_t pid);
};

void enableDebugPrivilege();
