#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct InlineHookHit
{
    static constexpr std::size_t kMemorySnippetBytes = 16;

    std::uint64_t address = 0;
    std::uint64_t moduleBase = 0;
    std::uint32_t rva = 0;
    std::uint8_t memoryByte = 0;
    std::uint8_t fileByte = 0;
    bool moduleIsPe32 = false;
    std::uint8_t memorySnippetSize = 0;
    std::uint8_t memorySnippet[kMemorySnippetBytes] = {};
    std::uint32_t diffByteCount = 0;
    std::wstring modulePath;
};

struct InlineHookScanResult
{
    std::uint32_t pid = 0;
    std::uint32_t modulesScanned = 0;
    std::uint32_t modulesSkipped = 0;
    std::vector<InlineHookHit> hits;
    std::wstring error;
};

/* Scan all MEM_IMAGE modules in a user process for inline hooks (memory vs on-disk .text). */
InlineHookScanResult DetectGlobalInlineHookEx(std::uint32_t pid);
