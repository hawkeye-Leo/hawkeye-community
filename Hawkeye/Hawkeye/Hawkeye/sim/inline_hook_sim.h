#pragma once

#include <QString>
#include <cstdint>
#include <vector>

struct InlineHookSimState
{
    bool active = false;
    std::uint32_t pid = 0;
    std::uintptr_t remoteModule = 0;
    std::vector<std::uintptr_t> patchedAddresses;
};

struct InlineHookSimOutcome
{
    bool ok = false;
    QString error;
    std::uint32_t pid = 0;
    std::uintptr_t remoteModule = 0;
    std::vector<std::uintptr_t> patchedAddresses;
};

InlineHookSimOutcome InlineHookSimStart(std::uint32_t pid, const InlineHookSimState& currentState);
InlineHookSimOutcome InlineHookSimStop(const InlineHookSimState& state);
