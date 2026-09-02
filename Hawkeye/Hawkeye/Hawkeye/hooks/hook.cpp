#include "hook.h"

#include "Driver.h"
#include "PathConvert.h"
#include "process.h"

#include <Windows.h>
#include <winnt.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>

namespace {

constexpr std::uint32_t kMaxInlineHookHits = 4096;

struct PeModuleLayout
{
    bool valid = false;
    bool isPe32 = false;
    std::uint32_t sizeOfImage = 0;
    std::uint64_t preferredBase = 0;
    std::vector<std::uint8_t> image;
};

bool isPlausibleUserPid(std::uint32_t pid)
{
    return Process::isPlausiblePid(pid) && pid > 4;
}

HANDLE openProcessForInlineScan(std::uint32_t pid)
{
    OPEN_PROCESS_HANDLE inout = { 0 };
    inout.pid = pid;
    inout.desiredAccess = 0;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return nullptr;
    }

    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(inout.processHandle));
}

bool readExact(HANDLE processHandle, std::uint64_t address, void* buffer, std::size_t size)
{
    if (buffer == nullptr || size == 0) {
        return false;
    }

    SIZE_T bytesRead = 0;
    return ReadProcessMemory(
               processHandle,
               reinterpret_cast<LPCVOID>(address),
               buffer,
               size,
               &bytesRead) == TRUE
        && bytesRead == size;
}

HANDLE createFileReadOnly(const wchar_t* path)
{
    Wow64EnableWow64FsRedirection(FALSE);
    const HANDLE fileHandle = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    Wow64EnableWow64FsRedirection(TRUE);
    return fileHandle;
}

bool readWholeFile(const wchar_t* path, std::vector<std::uint8_t>& outBuffer)
{
    outBuffer.clear();

    const HANDLE fileHandle = createFileReadOnly(path);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    const auto fileCloser = [](HANDLE handle) { CloseHandle(handle); };
    std::unique_ptr<void, decltype(fileCloser)> fileGuard(fileHandle, fileCloser);

    LARGE_INTEGER fileSize = { 0 };
    if (!GetFileSizeEx(fileHandle, &fileSize) || fileSize.QuadPart <= 0) {
        return false;
    }

    if (fileSize.QuadPart > static_cast<LONGLONG>(512 * 1024 * 1024)) {
        return false;
    }

    outBuffer.resize(static_cast<std::size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, outBuffer.data(), static_cast<DWORD>(outBuffer.size()), &bytesRead, nullptr)) {
        outBuffer.clear();
        return false;
    }

    if (bytesRead != outBuffer.size()) {
        outBuffer.resize(bytesRead);
    }

    return !outBuffer.empty();
}

template <typename NtHeadersT>
bool mapDiskImageToMemoryLayout(
    const std::vector<std::uint8_t>& rawData,
    PeModuleLayout& outLayout,
    std::size_t ntHeaderSize)
{
    if (rawData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) {
        return false;
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dosHeader->e_lfanew);
    if (ntOffset + ntHeaderSize > rawData.size()) {
        return false;
    }

    const auto* ntHeaders = reinterpret_cast<const NtHeadersT*>(rawData.data() + ntOffset);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const std::uint32_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    if (sizeOfImage == 0) {
        return false;
    }

    outLayout.sizeOfImage = sizeOfImage;
    outLayout.preferredBase = ntHeaders->OptionalHeader.ImageBase;
    outLayout.image.assign(sizeOfImage, 0);

    const std::uint32_t sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    const std::size_t headerCopySize = std::min<std::size_t>(sizeOfHeaders, rawData.size());
    std::memcpy(outLayout.image.data(), rawData.data(), headerCopySize);

    const auto* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    const std::uint16_t sectionCount = ntHeaders->FileHeader.NumberOfSections;
    for (std::uint16_t i = 0; i < sectionCount; ++i) {
        const IMAGE_SECTION_HEADER& section = sectionHeaders[i];
        if (section.SizeOfRawData == 0) {
            continue;
        }

        const std::size_t srcOffset = section.PointerToRawData;
        if (srcOffset >= rawData.size()) {
            continue;
        }

        std::size_t copySize = section.SizeOfRawData;
        if (srcOffset + copySize > rawData.size()) {
            copySize = rawData.size() - srcOffset;
        }

        const std::size_t destOffset = section.VirtualAddress;
        if (destOffset >= outLayout.image.size()) {
            continue;
        }

        if (destOffset + copySize > outLayout.image.size()) {
            copySize = outLayout.image.size() - destOffset;
        }

        std::memcpy(outLayout.image.data() + destOffset, rawData.data() + srcOffset, copySize);
    }

    return true;
}

void relocateImageInPlace(
    PeModuleLayout& layout,
    std::uint64_t targetBase)
{
    if (layout.image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(layout.image.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) {
        return;
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dosHeader->e_lfanew);
    if (targetBase == layout.preferredBase) {
        return;
    }

    std::uint32_t relocRva = 0;
    std::uint32_t relocSize = 0;

    if (layout.isPe32) {
        if (ntOffset + sizeof(IMAGE_NT_HEADERS32) > layout.image.size()) {
            return;
        }
        const auto* ntHeaders =
            reinterpret_cast<const IMAGE_NT_HEADERS32*>(layout.image.data() + ntOffset);
        relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    else {
        if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > layout.image.size()) {
            return;
        }
        const auto* ntHeaders =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(layout.image.data() + ntOffset);
        relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }

    if (relocRva == 0 || relocSize == 0 || relocRva + relocSize > layout.image.size()) {
        return;
    }

    const auto* relocEnd = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
        layout.image.data() + relocRva + relocSize);
    auto* relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(layout.image.data() + relocRva);

    while (relocBlock < relocEnd && relocBlock->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        if (relocBlock->VirtualAddress == 0) {
            break;
        }

        const std::uint32_t pageRva = relocBlock->VirtualAddress;
        const std::uint32_t entryCount =
            (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* entries = reinterpret_cast<WORD*>(relocBlock + 1);

        for (std::uint32_t i = 0; i < entryCount; ++i) {
            const WORD entry = entries[i];
            const std::uint32_t type = entry >> 12;
            const std::uint32_t offset = entry & 0x0FFF;
            const std::size_t patchOffset = static_cast<std::size_t>(pageRva) + offset;

            if (layout.isPe32) {
                if (type != IMAGE_REL_BASED_HIGHLOW) {
                    continue;
                }
                if (patchOffset + sizeof(DWORD) > layout.image.size()) {
                    continue;
                }

                auto* patchSite = reinterpret_cast<DWORD*>(layout.image.data() + patchOffset);
                *patchSite = static_cast<DWORD>(*patchSite - layout.preferredBase + targetBase);
            }
            else {
                if (type != IMAGE_REL_BASED_DIR64) {
                    continue;
                }
                if (patchOffset + sizeof(ULONGLONG) > layout.image.size()) {
                    continue;
                }

                auto* patchSite = reinterpret_cast<ULONGLONG*>(layout.image.data() + patchOffset);
                *patchSite = static_cast<ULONGLONG>(*patchSite - layout.preferredBase + targetBase);
            }
        }

        relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(relocBlock) + relocBlock->SizeOfBlock);
    }
}

bool buildMappedDiskImage(
    const std::wstring& dosPath,
    PeModuleLayout& outLayout)
{
    outLayout = PeModuleLayout();

    std::vector<std::uint8_t> rawData;
    if (!readWholeFile(dosPath.c_str(), rawData)) {
        return false;
    }

    if (rawData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) {
        return false;
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dosHeader->e_lfanew);
    if (ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > rawData.size()) {
        return false;
    }

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        rawData.data() + ntOffset + sizeof(DWORD));

    bool mapped = false;
    if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
        outLayout.isPe32 = true;
        mapped = mapDiskImageToMemoryLayout<IMAGE_NT_HEADERS32>(
            rawData,
            outLayout,
            sizeof(IMAGE_NT_HEADERS32));
    }
    else if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
        outLayout.isPe32 = false;
        mapped = mapDiskImageToMemoryLayout<IMAGE_NT_HEADERS64>(
            rawData,
            outLayout,
            sizeof(IMAGE_NT_HEADERS64));
    }

    if (!mapped || outLayout.image.empty()) {
        outLayout = PeModuleLayout();
        return false;
    }

    outLayout.valid = true;
    return true;
}

bool peSectionNameEquals(const IMAGE_SECTION_HEADER& section, const char* name)
{
    return std::strncmp(
               reinterpret_cast<const char*>(section.Name),
               name,
               IMAGE_SIZEOF_SHORT_NAME) == 0;
}

std::int16_t findPeSectionIndex(
    const IMAGE_SECTION_HEADER* sectionHeaders,
    std::uint16_t sectionCount,
    const char* name)
{
    for (std::uint16_t i = 0; i < sectionCount; ++i) {
        if (peSectionNameEquals(sectionHeaders[i], name)) {
            return static_cast<std::int16_t>(i);
        }
    }

    return -1;
}

bool isFothkSectionAfterText(
    const IMAGE_SECTION_HEADER* sectionHeaders,
    std::uint16_t sectionCount,
    std::uint16_t sectionIndex)
{
    const std::int16_t textSectionIndex =
        findPeSectionIndex(sectionHeaders, sectionCount, ".text");
    if (textSectionIndex < 0 || sectionIndex <= static_cast<std::uint16_t>(textSectionIndex)) {
        return false;
    }

    return peSectionNameEquals(sectionHeaders[sectionIndex], "fothk");
}

template <typename NtHeadersT>
void compareExecutableSections(
    const NtHeadersT* ntHeaders,
    const std::uint8_t* diskImage,
    const std::uint8_t* memImage,
    std::uint64_t moduleBase,
    bool moduleIsPe32,
    const std::wstring& modulePath,
    std::vector<InlineHookHit>& hits)
{
    const auto* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    const std::uint16_t sectionCount = ntHeaders->FileHeader.NumberOfSections;

    for (std::uint16_t i = 0; i < sectionCount; ++i) {
        if (hits.size() >= kMaxInlineHookHits) {
            break;
        }

        const IMAGE_SECTION_HEADER& section = sectionHeaders[i];
        if (isFothkSectionAfterText(sectionHeaders, sectionCount, i)) {
            continue;
        }
        if (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            continue;
        }
        if (section.Characteristics & IMAGE_SCN_MEM_WRITE) {
            continue;
        }
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }

        const std::uint32_t secSize = section.SizeOfRawData;
        if (secSize == 0) {
            continue;
        }
        if (section.VirtualAddress >= ntHeaders->OptionalHeader.SizeOfImage) {
            continue;
        }
        if (section.VirtualAddress + secSize > ntHeaders->OptionalHeader.SizeOfImage) {
            continue;
        }

        const std::uint8_t* diskBytes = diskImage + section.VirtualAddress;
        const std::uint8_t* memBytes = memImage + section.VirtualAddress;
        if (std::memcmp(diskBytes, memBytes, secSize) == 0) {
            continue;
        }

        for (std::uint32_t j = 0; j < secSize && hits.size() < kMaxInlineHookHits;) {
            if (diskBytes[j] == memBytes[j]) {
                ++j;
                continue;
            }

            const std::uint32_t rangeStart = j;
            while (j < secSize && diskBytes[j] != memBytes[j]) {
                ++j;
            }
            const std::uint32_t rangeSize = j - rangeStart;

            InlineHookHit hit;
            hit.rva = section.VirtualAddress + rangeStart;
            hit.address = moduleBase + hit.rva;
            hit.moduleBase = moduleBase;
            hit.memoryByte = memBytes[rangeStart];
            hit.fileByte = diskBytes[rangeStart];
            hit.diffByteCount = rangeSize;
            hit.moduleIsPe32 = moduleIsPe32;
            hit.modulePath = modulePath;

            const std::uint32_t snippetSize = std::min<std::uint32_t>(
                InlineHookHit::kMemorySnippetBytes,
                secSize - rangeStart);
            if (snippetSize > 0) {
                std::memcpy(hit.memorySnippet, memBytes + rangeStart, snippetSize);
                hit.memorySnippetSize = static_cast<std::uint8_t>(snippetSize);
            }

            hits.push_back(std::move(hit));
        }
    }
}

void compareSections(
    const PeModuleLayout& diskLayout,
    const std::vector<std::uint8_t>& memImage,
    std::uint64_t moduleBase,
    const std::wstring& modulePath,
    std::vector<InlineHookHit>& hits)
{
    if (diskLayout.image.empty() || memImage.empty()) {
        return;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(diskLayout.image.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) {
        return;
    }

    const std::size_t ntOffset = static_cast<std::size_t>(dosHeader->e_lfanew);
    if (diskLayout.isPe32) {
        if (ntOffset + sizeof(IMAGE_NT_HEADERS32) > diskLayout.image.size()) {
            return;
        }
        const auto* ntHeaders =
            reinterpret_cast<const IMAGE_NT_HEADERS32*>(diskLayout.image.data() + ntOffset);
        compareExecutableSections(
            ntHeaders,
            diskLayout.image.data(),
            memImage.data(),
            moduleBase,
            true,
            modulePath,
            hits);
    }
    else {
        if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > diskLayout.image.size()) {
            return;
        }
        const auto* ntHeaders =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(diskLayout.image.data() + ntOffset);
        compareExecutableSections(
            ntHeaders,
            diskLayout.image.data(),
            memImage.data(),
            moduleBase,
            false,
            modulePath,
            hits);
    }
}

void analyzeModuleInlineHook(
    HANDLE processHandle,
    const Process::ModuleInfo& module,
    std::vector<InlineHookHit>& hits,
    std::uint32_t& modulesSkipped)
{
    if (hits.size() >= kMaxInlineHookHits || module.base == 0 || module.path.empty()) {
        return;
    }

    const std::wstring dosPath = convertSystemRootPathW(module.path.c_str());
    if (dosPath.empty()) {
        ++modulesSkipped;
        return;
    }

    PeModuleLayout diskLayout;
    if (!buildMappedDiskImage(dosPath, diskLayout)) {
        ++modulesSkipped;
        return;
    }

    if (module.base + diskLayout.sizeOfImage <= module.base) {
        ++modulesSkipped;
        return;
    }

    std::vector<std::uint8_t> memImage(diskLayout.sizeOfImage, 0);
    if (!readExact(processHandle, module.base, memImage.data(), memImage.size())) {
        ++modulesSkipped;
        return;
    }

    relocateImageInPlace(diskLayout, module.base);
    compareSections(diskLayout, memImage, module.base, module.path, hits);
}

} // namespace

InlineHookScanResult DetectGlobalInlineHookEx(std::uint32_t pid)
{
    InlineHookScanResult result;
    result.pid = pid;

    if (!isPlausibleUserPid(pid)) {
        result.error = L"Invalid pid. Use pid>4 aligned to 4.";
        return result;
    }

    const HANDLE processHandle = openProcessForInlineScan(pid);
    if (processHandle == nullptr) {
        result.error = L"Unable to open target process.";
        return result;
    }

    const auto processGuard = [](HANDLE handle) {
        if (handle != nullptr) {
            CloseHandle(handle);
        }
    };
    std::unique_ptr<void, decltype(processGuard)> guard(processHandle, processGuard);

    const std::vector<Process::ModuleInfo> modules = Process::enumerateModules(pid);
    if (modules.empty()) {
        result.error = L"No modules enumerated for target process.";
        return result;
    }

    result.hits.reserve(64);
    for (const Process::ModuleInfo& module : modules) {
        analyzeModuleInlineHook(
            processHandle,
            module,
            result.hits,
            result.modulesSkipped);
        ++result.modulesScanned;

        if (result.hits.size() >= kMaxInlineHookHits) {
            break;
        }
    }

    return result;
}
