#pragma once

#include <QString>
#include <cstdint>

struct InjectSimState
{
    bool active = false;
    std::uint32_t pid = 0;
    std::uintptr_t remoteModule = 0;
    QString dllPath;
};

struct InjectSimOutcome
{
    bool ok = false;
    QString error;
    std::uint32_t pid = 0;
    std::uintptr_t remoteModule = 0;
    QString dllPath;
};

bool InjectSimResolveStubPath(QString* dllPathOut, QString* errorOut);
InjectSimOutcome InjectSimLoad(std::uint32_t pid);
InjectSimOutcome InjectSimUnload(const InjectSimState& state);
std::uintptr_t InjectSimFindRemoteModuleBase(std::uint32_t pid);
