#include "probe.h"
#include "Driver.h"
#include "PathConvert.h"

#include <Windows.h>
#include <Shlwapi.h>

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")

namespace {

// PDB/DIA SymTag values (SYMBOL_INFO::Tag); stable across DbgHelp versions.
constexpr ULONG kSymTagFunction = 5;
constexpr ULONG kSymTagData = 7;
constexpr ULONG kSymTagPublicSymbol = 10;
constexpr ULONG kSymTagUDT = 11;
constexpr ULONG kSymTagEnum = 12;
constexpr ULONG kSymTagFunctionType = 13;
constexpr ULONG kSymTagPointerType = 14;
constexpr ULONG kSymTagArrayType = 15;
constexpr ULONG kSymTagBaseClass = 16;
constexpr ULONG kSymTagTypedef = 17;
constexpr ULONG kSymTagVTableShape = 18;
constexpr ULONG kSymTagVTable = 19;
constexpr ULONG kSymTagThunk = 21;

std::wstring ExtractFileName(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? path : path.substr(slash + 1);
}

std::wstring ToLowerCopy(std::wstring value)
{
    for (wchar_t& ch : value) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return value;
}

bool ContainsCaseInsensitive(const std::wstring& haystack, const std::wstring& needleLower)
{
    if (needleLower.empty()) {
        return true;
    }

    if (haystack.size() < needleLower.size()) {
        return false;
    }

    const std::size_t needleLen = needleLower.size();
    const std::size_t lastStart = haystack.size() - needleLen;
    for (std::size_t start = 0; start <= lastStart; ++start) {
        bool matched = true;
        for (std::size_t index = 0; index < needleLen; ++index) {
            const wint_t hayChar = towlower(static_cast<wint_t>(haystack[start + index]));
            if (hayChar != static_cast<wint_t>(needleLower[index])) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return true;
        }
    }

    return false;
}

bool SymbolNameMatchesKeyword(const ProbeSymbolHit& entry, const std::wstring& needleLower)
{
    if (ContainsCaseInsensitive(entry.decoratedName, needleLower)) {
        return true;
    }
    if (!entry.friendlyName.empty() && ContainsCaseInsensitive(entry.friendlyName, needleLower)) {
        return true;
    }
    if (!entry.displayName.empty()
        && entry.displayName != entry.friendlyName
        && ContainsCaseInsensitive(entry.displayName, needleLower)) {
        return true;
    }
    return false;
}

bool SymbolNameMatchesAllKeywords(const ProbeSymbolHit& entry,
                                  const std::vector<std::wstring>& keywordTokens)
{
    if (keywordTokens.empty()) {
        return false;
    }

    for (const std::wstring& token : keywordTokens) {
        if (!SymbolNameMatchesKeyword(entry, token)) {
            return false;
        }
    }
    return true;
}

bool IsImportThunkSymbol(const ProbeSymbolHit& entry)
{
    const auto hasImportPrefix = [](const std::wstring& name) {
        return name.rfind(L"__imp_", 0) == 0 || name.rfind(L"__imp_load_", 0) == 0;
    };

    return hasImportPrefix(entry.decoratedName) || hasImportPrefix(entry.displayName);
}

bool StartsWithDecorated(const std::wstring& name, const wchar_t* prefix)
{
    const std::size_t prefixLen = wcslen(prefix);
    return name.size() >= prefixLen && wcsncmp(name.c_str(), prefix, prefixLen) == 0;
}

bool LooksLikeCompilerDataPublic(const std::wstring& decorated, const std::wstring& friendly)
{
    if (StartsWithDecorated(decorated, L"??_7")
        || StartsWithDecorated(decorated, L"??_8")
        || StartsWithDecorated(decorated, L"??_C")
        || StartsWithDecorated(decorated, L"??_K")
        || StartsWithDecorated(decorated, L"??_R")
        || StartsWithDecorated(decorated, L"??_S")) {
        return true;
    }
    if (friendly.find(L"vftable") != std::wstring::npos
        || friendly.find(L"vbtable") != std::wstring::npos
        || friendly.find(L"RTTI") != std::wstring::npos) {
        return true;
    }
    return false;
}

bool LooksLikeFunctionSignature(const std::wstring& decorated, const std::wstring& friendly)
{
    if (friendly.find(L'(') != std::wstring::npos) {
        return true;
    }
    return !decorated.empty()
        && decorated[0] == L'?'
        && !LooksLikeCompilerDataPublic(decorated, friendly);
}

enum class ProbeKindBucket
{
    Func,
    Data,
    Type,
    Public
};

bool IsTypeSymTag(ULONG tag)
{
    switch (tag) {
    case kSymTagUDT:
    case kSymTagEnum:
    case kSymTagFunctionType:
    case kSymTagPointerType:
    case kSymTagArrayType:
    case kSymTagBaseClass:
    case kSymTagTypedef:
    case kSymTagVTableShape:
    case kSymTagVTable:
        return true;
    default:
        return false;
    }
}

ProbeKindBucket ClassifyProbeKind(const ProbeSymbolHit& entry)
{
    const ULONG tag = entry.symTag;
    if (IsTypeSymTag(tag)) {
        return ProbeKindBucket::Type;
    }
    if (tag == kSymTagFunction || tag == kSymTagThunk) {
        return ProbeKindBucket::Func;
    }
    if (tag == kSymTagData) {
        return ProbeKindBucket::Data;
    }
    if ((entry.flags & SYMFLAG_FUNCTION) != 0 || (entry.flags & SYMFLAG_THUNK) != 0) {
        return ProbeKindBucket::Func;
    }
    if (LooksLikeCompilerDataPublic(entry.decoratedName, entry.friendlyName)
        || LooksLikeCompilerDataPublic(entry.decoratedName, entry.displayName)) {
        return ProbeKindBucket::Data;
    }
    if (LooksLikeFunctionSignature(entry.decoratedName, entry.friendlyName)
        || LooksLikeFunctionSignature(entry.decoratedName, entry.displayName)) {
        return ProbeKindBucket::Func;
    }
    if (tag == kSymTagPublicSymbol) {
        return ProbeKindBucket::Data;
    }
    return ProbeKindBucket::Public;
}

bool MatchesFindKind(const ProbeSymbolHit& entry, ProbeFindKind kind)
{
    const ProbeKindBucket bucket = ClassifyProbeKind(entry);
    switch (kind) {
    case ProbeFindKind::Function:
        return bucket == ProbeKindBucket::Func;
    case ProbeFindKind::Data:
        return bucket == ProbeKindBucket::Data;
    case ProbeFindKind::Type:
        return bucket == ProbeKindBucket::Type;
    case ProbeFindKind::All:
        return true;
    default:
        return bucket == ProbeKindBucket::Func;
    }
}

std::wstring FormatProbeSymKind(const ProbeSymbolHit& entry)
{
    if (entry.executeAttr == 1) {
        return L"func";
    }
    if (entry.executeAttr == 2) {
        return L"data";
    }
    switch (ClassifyProbeKind(entry)) {
    case ProbeKindBucket::Func:
        return L"func";
    case ProbeKindBucket::Data:
        return L"data";
    case ProbeKindBucket::Type:
        return L"type";
    default:
        return L"public";
    }
}

std::uint64_t GetDirectorySizeRecursive(const std::wstring& directoryPath);

} // namespace

ProbeFindKind ProbeParseFindKind(const std::wstring& kindText)
{
    const auto equalsIgnoreCase = [](const std::wstring& value, const wchar_t* literal) {
        if (value.size() != wcslen(literal)) {
            return false;
        }
        return _wcsicmp(value.c_str(), literal) == 0;
    };

    if (equalsIgnoreCase(kindText, L"func")
        || equalsIgnoreCase(kindText, L"function")
        || equalsIgnoreCase(kindText, L"functions")) {
        return ProbeFindKind::Function;
    }
    if (equalsIgnoreCase(kindText, L"data")
        || equalsIgnoreCase(kindText, L"var")
        || equalsIgnoreCase(kindText, L"vars")
        || equalsIgnoreCase(kindText, L"variable")) {
        return ProbeFindKind::Data;
    }
    if (equalsIgnoreCase(kindText, L"type") || equalsIgnoreCase(kindText, L"types")) {
        return ProbeFindKind::Type;
    }
    if (equalsIgnoreCase(kindText, L"all")) {
        return ProbeFindKind::All;
    }
    return ProbeFindKind::All;
}

std::wstring ProbeFormatBytes(std::uint64_t bytes)
{
    wchar_t buf[64] = {};
    if (bytes < 1024ULL) {
        swprintf_s(buf, L"%llu B", static_cast<unsigned long long>(bytes));
    } else if (bytes < 1024ULL * 1024ULL) {
        swprintf_s(buf, L"%.1f KB", static_cast<double>(bytes) / 1024.0);
    } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
        swprintf_s(buf, L"%.2f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    } else {
        swprintf_s(buf, L"%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    }
    return buf;
}

std::uint64_t ProbeMeasureDirectoryBytes(const std::wstring& directoryPath)
{
    return GetDirectorySizeRecursive(directoryPath);
}

std::wstring ProbeFormatModuleShortName(const std::wstring& moduleFileName)
{
    if (moduleFileName.empty()) {
        return moduleFileName;
    }

    std::wstring shortName = moduleFileName;
    const auto stripExtension = [&shortName](const wchar_t* ext) {
        const std::size_t extLen = wcslen(ext);
        if (shortName.size() > extLen
            && _wcsicmp(shortName.c_str() + shortName.size() - extLen, ext) == 0) {
            shortName.resize(shortName.size() - extLen);
        }
    };

    stripExtension(L".exe");
    stripExtension(L".dll");
    stripExtension(L".sys");
    return shortName;
}

std::wstring ProbePickSymbolLabel(const ProbeSymbolHit& hit)
{
    if (!hit.friendlyName.empty()
        && !hit.decoratedName.empty()
        && hit.decoratedName[0] == L'?') {
        return hit.friendlyName;
    }
    if (!hit.decoratedName.empty()) {
        return hit.decoratedName;
    }
    if (!hit.displayName.empty()) {
        return hit.displayName;
    }
    return hit.friendlyName;
}

std::wstring ProbeFormatHitLine(const ProbeSymbolHit& hit, bool showKind)
{
    const std::wstring moduleShort = ProbeFormatModuleShortName(hit.moduleName);
    const std::wstring copyName = !hit.decoratedName.empty()
        ? hit.decoratedName
        : ProbePickSymbolLabel(hit);
    std::wstring readable = hit.friendlyName;
    if (readable.empty()) {
        readable = hit.displayName.empty() ? copyName : hit.displayName;
    }

    wchar_t vaBuf[32] = {};
    swprintf_s(vaBuf, L"0x%llX", static_cast<unsigned long long>(hit.va));
    std::wstring line = L"[" + copyName + L"] " + moduleShort + L"!" + readable
        + L"    VA:" + vaBuf;
    if (showKind) {
        line += L"  kind:" + FormatProbeSymKind(hit);
    }
    return line;
}

namespace {

constexpr std::uint64_t kProbeKernelVaMin = 0xFFFF000000000000ULL;
constexpr std::uint64_t kProbePtePresent = 0x1ull;
constexpr std::uint64_t kProbePteLargePage = 0x80ull;
constexpr std::uint64_t kProbePteNx = 0x8000000000000000ull;

bool ProbeProtectHasExecute(ULONG protect)
{
    return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

std::uint8_t QueryKernelVaExecuteAttr(std::uint64_t va)
{
    GET_VIRTUAL_ADDRESS_PTE req = {};
    req.pid = 4;
    req.va = va;
    GetVirtualAddressPte(&req);
    if (req.errCode != 1) {
        return 0;
    }
    if ((req.pteData & kProbePtePresent) == 0) {
        return 2;
    }
    if (req.entryType == VA_PTE_ENTRY_TYPE_PDE && (req.pteData & kProbePteLargePage) == 0) {
        return 2;
    }
    return ((req.pteData & kProbePteNx) == 0) ? 1 : 2;
}

enum class ProbeMemoryInformationClass : ULONG
{
    BasicInformation = 0,
};

using ProbeZwQueryVirtualMemoryFn = LONG(NTAPI*)(
    HANDLE processHandle,
    PVOID baseAddress,
    ProbeMemoryInformationClass memoryInformationClass,
    PVOID buffer,
    SIZE_T length,
    PSIZE_T resultLength);

struct ProbeMemoryBasicInformation64
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

ProbeZwQueryVirtualMemoryFn GetProbeZwQueryVirtualMemory()
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return nullptr;
    }
    return reinterpret_cast<ProbeZwQueryVirtualMemoryFn>(
        GetProcAddress(ntdll, "ZwQueryVirtualMemory"));
}

HANDLE OpenProbeTargetProcess(std::uint32_t pid)
{
    OPEN_PROCESS_HANDLE inout = {};
    inout.pid = pid;
    inout.desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return nullptr;
    }
    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(inout.processHandle));
}

std::uint8_t QueryUserVaExecuteAttr(
    HANDLE processHandle,
    ProbeZwQueryVirtualMemoryFn queryFn,
    std::uint64_t va)
{
    ProbeMemoryBasicInformation64 info = {};
    const LONG status = queryFn(
        processHandle,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(va)),
        ProbeMemoryInformationClass::BasicInformation,
        &info,
        sizeof(info),
        nullptr);
    if (status < 0) {
        return 0;
    }
    if (info.State == MEM_COMMIT && ProbeProtectHasExecute(info.Protect)) {
        return 1;
    }
    return 2;
}

} // namespace

void ProbeAnnotateExecuteKind(std::vector<ProbeSymbolHit>& hits, std::uint32_t pid)
{
    std::unordered_map<std::uint64_t, std::uint8_t> pageCache;
    pageCache.reserve(hits.size());

    HANDLE userProcess = nullptr;
    const ProbeZwQueryVirtualMemoryFn queryFn = (pid > 4) ? GetProbeZwQueryVirtualMemory() : nullptr;
    if (pid > 4 && queryFn != nullptr) {
        userProcess = OpenProbeTargetProcess(pid);
    }

    for (ProbeSymbolHit& hit : hits) {
        if (hit.va == 0 || pid == 0) {
            hit.executeAttr = 0;
            continue;
        }

        const std::uint64_t page = hit.va & ~0xFFFULL;
        auto it = pageCache.find(page);
        if (it == pageCache.end()) {
            std::uint8_t attr = 0;
            if (pid == 4 || hit.va > kProbeKernelVaMin) {
                attr = QueryKernelVaExecuteAttr(hit.va);
            } else if (userProcess != nullptr && queryFn != nullptr) {
                attr = QueryUserVaExecuteAttr(userProcess, queryFn, hit.va);
            }
            it = pageCache.emplace(page, attr).first;
        }
        hit.executeAttr = it->second;
    }

    if (userProcess != nullptr) {
        CloseHandle(userProcess);
    }
}

void ProbeFilterHitsByExecuteKind(std::vector<ProbeSymbolHit>& hits, ProbeFindKind kind)
{
    if (kind != ProbeFindKind::Function && kind != ProbeFindKind::Data) {
        return;
    }

    const std::uint8_t want = (kind == ProbeFindKind::Function) ? 1 : 2;
    hits.erase(std::remove_if(hits.begin(), hits.end(), [want](const ProbeSymbolHit& hit) {
        return hit.executeAttr != want;
    }), hits.end());
}

namespace {

std::uint64_t GetDirectorySizeRecursive(const std::wstring& directoryPath)
{
    if (directoryPath.empty() || !PathFileExistsW(directoryPath.c_str())) {
        return 0;
    }

    std::uint64_t total = 0;
    const std::wstring searchPattern = directoryPath + L"\\*";
    WIN32_FIND_DATAW findData = {};
    HANDLE findHandle = FindFirstFileW(searchPattern.c_str(), &findData);
    if (findHandle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        const std::wstring itemName = findData.cFileName;
        if (itemName == L"." || itemName == L"..") {
            continue;
        }

        const std::wstring fullPath = directoryPath + L"\\" + itemName;
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            total += GetDirectorySizeRecursive(fullPath);
            continue;
        }

        ULARGE_INTEGER fileSize = {};
        fileSize.LowPart = findData.nFileSizeLow;
        fileSize.HighPart = findData.nFileSizeHigh;
        total += fileSize.QuadPart;
    } while (FindNextFileW(findHandle, &findData));

    FindClose(findHandle);
    return total;
}

std::wstring TrimWhitespaceCopy(std::wstring value)
{
    const auto isSpace = [](wchar_t ch) {
        return ch == L' ' || ch == L'\t';
    };

    while (!value.empty() && isSpace(value.front())) {
        value.erase(value.begin());
    }
    while (!value.empty() && isSpace(value.back())) {
        value.pop_back();
    }
    return value;
}

std::vector<std::wstring> ParseCommaSeparatedTokens(const std::wstring& text)
{
    std::vector<std::wstring> tokens;
    if (text.empty()) {
        return tokens;
    }

    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t comma = text.find(L',', start);
        const std::size_t count = (comma == std::wstring::npos)
            ? text.size() - start
            : comma - start;
        std::wstring piece = TrimWhitespaceCopy(text.substr(start, count));
        piece = ToLowerCopy(std::move(piece));
        if (!piece.empty()) {
            tokens.push_back(std::move(piece));
        }
        if (comma == std::wstring::npos) {
            break;
        }
        start = comma + 1;
    }
    return tokens;
}

std::vector<std::wstring> ParseModuleFilterTokens(const std::wstring& filterText)
{
    return ParseCommaSeparatedTokens(filterText);
}

bool ModuleFilterIncludesAll(const std::vector<std::wstring>& filterTokens)
{
    for (const std::wstring& token : filterTokens) {
        if (token == L"all") {
            return true;
        }
    }
    return false;
}

void LogProbeModuleLine(const ProbeLogFn& log,
                        const std::wstring& fileName,
                        std::uint64_t moduleBase,
                        const std::wstring& detail,
                        const wchar_t* prefix = L"")
{
    if (!log) {
        return;
    }

    wchar_t line[512] = {};
    if (moduleBase != 0) {
        swprintf_s(line,
                   L"%s%s @ 0x%llX  -> %s",
                   prefix,
                   fileName.c_str(),
                   static_cast<unsigned long long>(moduleBase),
                   detail.c_str());
    } else {
        swprintf_s(line, L"%s%s  -> %s", prefix, fileName.c_str(), detail.c_str());
    }
    log(line);
}

bool EndsWithIgnoreCase(const std::wstring& value, const wchar_t* suffix)
{
    const std::size_t suffixLen = wcslen(suffix);
    if (value.size() < suffixLen) {
        return false;
    }
    return _wcsicmp(value.c_str() + value.size() - suffixLen, suffix) == 0;
}

bool ModuleFileNameEqualsIgnoreCase(const std::wstring& moduleFileName, const std::wstring& candidate)
{
    if (candidate.empty()) {
        return false;
    }
    return _wcsicmp(moduleFileName.c_str(), candidate.c_str()) == 0;
}

bool ModuleBaseNameEqualsIgnoreCase(const std::wstring& moduleFileName, const std::wstring& candidate)
{
    if (candidate.empty()) {
        return false;
    }
    return _wcsicmp(ProbeFormatModuleShortName(moduleFileName).c_str(),
                    ProbeFormatModuleShortName(candidate).c_str()) == 0;
}

bool ModFilterTokenMatches(const std::wstring& moduleFileName,
                           const std::wstring& token,
                           bool isKernel)
{
    if (token == L"nt" || token == L"ntos" || token == L"ntoskrnl") {
        const std::wstring lower = ToLowerCopy(moduleFileName);
        if (lower.find(L"ntoskrnl") != std::wstring::npos) {
            return true;
        }
        if (lower.size() >= 6 && lower.compare(0, 6, L"ntkrnl") == 0) {
            return true;
        }
        return false;
    }

    const wchar_t* defaultExt = isKernel ? L".sys" : L".dll";

    if (!EndsWithIgnoreCase(token, defaultExt)) {
        const std::wstring withExt = token + defaultExt;
        if (ModuleFileNameEqualsIgnoreCase(moduleFileName, withExt)) {
            return true;
        }
    } else if (ModuleFileNameEqualsIgnoreCase(moduleFileName, token)) {
        return true;
    }

    if (ModuleFileNameEqualsIgnoreCase(moduleFileName, token)) {
        return true;
    }
    return ModuleBaseNameEqualsIgnoreCase(moduleFileName, token);
}

bool ModuleFilterMatches(const std::wstring& moduleFileName,
                         const std::vector<std::wstring>& filterTokens,
                         bool isKernel)
{
    if (filterTokens.empty()) {
        return true;
    }

    if (ModuleFilterIncludesAll(filterTokens)) {
        return true;
    }

    for (const std::wstring& token : filterTokens) {
        if (ModFilterTokenMatches(moduleFileName, token, isKernel)) {
            return true;
        }
    }
    return false;
}

std::wstring SummarizeLoadError(const std::wstring& error)
{
    if (error.empty()) {
        return L"No PDB symbols";
    }

    const std::wstring lower = ToLowerCopy(error);
    if (lower.find(L"export") != std::wstring::npos) {
        return L"No PDB (export symbols only)";
    }
    if (lower.find(L"pdb not found") != std::wstring::npos
        || lower.find(L"could not be downloaded") != std::wstring::npos
        || lower.find(L"no pdb") != std::wstring::npos) {
        return L"No PDB symbols available";
    }
    if (lower.find(L"not in local cache") != std::wstring::npos) {
        return L"No local PDB (skipped)";
    }
    if (lower.find(L"module not found") != std::wstring::npos) {
        return L"Module not found on disk";
    }

    return error;
}

bool NamesMatchExactly(const std::wstring& left, const std::wstring& right)
{
    if (left.empty() || right.empty()) {
        return false;
    }
    if (left == right) {
        return true;
    }
    return ToLowerCopy(left) == ToLowerCopy(right);
}

} // namespace

std::vector<std::wstring> ProbeParseModuleFilter(const std::wstring& filterText)
{
    return ParseModuleFilterTokens(filterText);
}

void ProbeSession::Detach(SymbolManager& symbols, const ProbeLogFn& log)
{
    if (m_targetPid == 0) {
        return;
    }

    if (log) {
        log(L"Detaching probe session from PID " + std::to_wstring(m_targetPid) + L"...");
    }

    for (const std::wstring& path : m_loadedPaths) {
        bool symBusy = false;
        symbols.UnloadSymbol(path, &symBusy);
    }

    m_targetPid = 0;
    m_modules.clear();
    m_index.clear();
    m_loadedPaths.clear();

    if (log) {
        log(L"Probe session detached. Symbols unloaded and in-memory index released.");
    }
}

bool ProbeSession::Attach(std::uint32_t pid,
                          SymbolManager& symbols,
                          const ProbeLogFn& log,
                          const ProbeCancelFn& shouldCancel)
{
    Detach(symbols, ProbeLogFn{});

    if (!Process::isPlausiblePid(pid)) {
        if (log) {
            log(L"Error: invalid PID.");
        }
        return false;
    }

    const std::vector<Process::ModuleInfo> modules = Process::enumerateModules(pid);
    if (modules.empty()) {
        if (log) {
            log(L"Error: no modules found for PID " + std::to_wstring(pid) + L".");
        }
        return false;
    }

    m_targetPid = pid;
    m_modules.clear();
    m_index.clear();
    m_loadedPaths.clear();
    m_modules.reserve(modules.size());

    bool symBusy = false;
    const std::wstring cacheDirectory = symbols.GetSymbolCacheDirectory(&symBusy);
    if (symBusy) {
        if (log) {
            log(L"Error: symbol manager is busy.");
        }
        m_targetPid = 0;
        return false;
    }

    if (log) {
        const bool isKernelAttach = (pid == 4);
        const std::wstring targetPath = Process::getPath(pid);

        std::wstring targetLine = L"Target: ";
        if (isKernelAttach) {
            targetLine += L"System";
        } else if (!targetPath.empty()) {
            targetLine += targetPath;
        } else {
            targetLine += L"PID " + std::to_wstring(pid);
        }
        targetLine += L"  --->" + std::to_wstring(modules.size()) + L" module(s) to scan";
        log(targetLine);

        if (!cacheDirectory.empty()) {
            log(L"Symbol cache: " + cacheDirectory);
        }
        log(L"Loading local cached PDBs only (no download).");
    }

    const std::size_t totalModules = modules.size();
    std::size_t loadedCount = 0;
    std::size_t failedCount = 0;
    std::size_t indexedSymbols = 0;

    for (std::size_t index = 0; index < modules.size(); ++index) {
        if (shouldCancel && shouldCancel()) {
            if (log) {
                log(L"Probe attach cancelled. Unloading symbols loaded so far...");
            }
            Detach(symbols, log);
            return false;
        }

        const Process::ModuleInfo& module = modules[index];
        ProbeModuleRecord record;
        record.base = module.base;
        record.path = module.path;
        record.fileName = ExtractFileName(module.path);

        if (module.path.empty()) {
            record.statusMessage = L"Skipped (empty module path)";
            failedCount++;
            m_modules.push_back(record);
            continue;
        }

        const std::wstring dosPath = convertSystemRootPathW(module.path.c_str());
        if (dosPath.empty()) {
            record.statusMessage = L"Skipped (invalid path)";
            failedCount++;
            m_modules.push_back(record);
            continue;
        }

        record.path = dosPath;
        record.fileName = ExtractFileName(dosPath);

        std::size_t moduleIndexed = 0;
        if (LoadAndIndexModule(record, symbols, false, ProbeLogFn{}, moduleIndexed)) {
            if (record.symbolsLoaded) {
                loadedCount++;
                indexedSymbols += moduleIndexed;
                if (log) {
                    if (moduleIndexed > 0) {
                        LogProbeModuleLine(log,
                                           record.fileName,
                                           module.base,
                                           std::to_wstring(moduleIndexed) + L" symbol(s)",
                                           L"\t");
                    } else {
                        LogProbeModuleLine(log,
                                           record.fileName,
                                           module.base,
                                           L"PDB loaded, 0 symbols indexed",
                                           L"\t");
                    }
                }
            } else {
                failedCount++;
            }
        } else {
            failedCount++;
        }

        m_modules.push_back(record);
    }

    if (log) {
        const bool isKernelAttach = (pid == 4);
        log(L"Probe ready: PID " + std::to_wstring(pid)
            + L", local PDB loaded " + std::to_wstring(loadedCount)
            + L", indexed symbols " + std::to_wstring(indexedSymbols));
        if (failedCount > 0) {
            log(L"(" + std::to_wstring(failedCount) + L" module(s) skipped -- no local PDB)");
        }
        if (isKernelAttach) {
            log(L"Next: !probe -find:<keyword> -mod:nt,win32k,win32kbase,win32kfull");
        } else {
            log(L"Next: !probe -find:<keyword> -mod:kernel32,ntdll");
        }
    }

    return true;
}

bool ProbeSession::LoadAndIndexModule(ProbeModuleRecord& record,
                                      SymbolManager& symbols,
                                      bool allowDownload,
                                      const ProbeLogFn& log,
                                      std::size_t& outIndexedCount)
{
    outIndexedCount = 0;
    if (record.path.empty()) {
        return false;
    }

    const std::wstring& dosPath = record.path;
    bool symBusy = false;

    SymbolLoadOptions loadOptions;
    loadOptions.logFn = log;
    loadOptions.allowDownload = allowDownload;
    loadOptions.maxLoadAttempts = allowDownload ? 4 : 1;

    const DWORD symbolLoadPid = (m_targetPid == 4) ? 0u : m_targetPid;

    std::wstring loadError;
    if (!symbols.LoadSymbol(dosPath, loadError, symbolLoadPid, &loadOptions)) {
        record.symbolsLoaded = false;
        record.statusMessage = SummarizeLoadError(loadError);
        if (log) {
            LogProbeModuleLine(log, record.fileName, record.base, record.statusMessage);
        }
        return false;
    }

    const std::wstring normalizedPath = SymbolManager::NormalizeFilePathKey(dosPath);
    if (std::find(m_loadedPaths.begin(), m_loadedPaths.end(), normalizedPath) == m_loadedPaths.end()) {
        m_loadedPaths.push_back(normalizedPath);
    }

    DWORD64 loadedModuleBase = 0;
    if (!symbols.GetLoadedModuleBase(dosPath, loadedModuleBase, &symBusy) || loadedModuleBase == 0) {
        record.symbolsLoaded = false;
        record.statusMessage = L"Loaded but module base unavailable";
        if (log) {
            LogProbeModuleLine(log, record.fileName, record.base, record.statusMessage);
        }
        return false;
    }

    std::vector<CollectedSymbol> collected;
    if (!symbols.CollectModuleSymbols(loadedModuleBase, collected, &symBusy) || collected.empty()) {
        record.symbolsLoaded = true;
        record.symbolCount = 0;
        record.statusMessage = L"PDB loaded but no symbols indexed";
        if (log) {
            LogProbeModuleLine(log, record.fileName, loadedModuleBase, L"PDB loaded, 0 symbols indexed");
        }
        return true;
    }

    record.symbolsLoaded = true;
    record.symbolCount = collected.size();
    record.statusMessage = L"OK";
    outIndexedCount = collected.size();

    for (const CollectedSymbol& symbol : collected) {
        ProbeSymbolHit hit;
        hit.moduleName = record.fileName;
        hit.modulePath = record.path;
        hit.moduleBase = loadedModuleBase;
        hit.decoratedName = symbol.decoratedName;
        hit.friendlyName = symbol.friendlyName;
        hit.symTag = symbol.symTag;
        hit.flags = symbol.flags;
        if (!symbol.friendlyName.empty()) {
            hit.displayName = symbol.friendlyName;
        } else {
            hit.displayName = symbol.decoratedName;
        }

        if (loadedModuleBase != 0 && symbol.address >= loadedModuleBase) {
            hit.va = symbol.address;
            hit.rva = symbol.address - loadedModuleBase;
        } else if (loadedModuleBase != 0) {
            hit.rva = symbol.address;
            hit.va = loadedModuleBase + symbol.address;
        } else {
            hit.va = symbol.address;
            hit.rva = 0;
        }

        m_index.push_back(std::move(hit));
    }

    if (log) {
        LogProbeModuleLine(log,
                           record.fileName,
                           loadedModuleBase,
                           std::to_wstring(collected.size()) + L" symbol(s)");
    }
    return true;
}

ProbeEnsureModulesResult ProbeSession::EnsureModulesForFilter(SymbolManager& symbols,
                                                              const std::wstring& moduleFilter,
                                                              const ProbeLogFn& log,
                                                              const ProbeCancelFn& shouldCancel)
{
    ProbeEnsureModulesResult result;
    if (m_targetPid == 0 || moduleFilter.empty()) {
        return result;
    }

    const std::vector<std::wstring> filterTokens = ParseModuleFilterTokens(moduleFilter);
    if (filterTokens.empty()) {
        return result;
    }

    const bool loadAll = ModuleFilterIncludesAll(filterTokens);
    if (log) {
        log(loadAll
                ? L"Probe: -mod:all -- loading/downloading all modules not yet indexed..."
                : L"Probe: -mod specified -- loading/downloading matching modules if needed...");
    }

    for (ProbeModuleRecord& record : m_modules) {
        if (shouldCancel && shouldCancel()) {
            if (log) {
                log(L"Probe: -mod ensure cancelled.");
            }
            break;
        }

        if (record.path.empty()) {
            continue;
        }

        if (!loadAll && !ModuleFilterMatches(record.fileName, filterTokens, m_targetPid == 4)) {
            continue;
        }

        if (record.symbolsLoaded) {
            result.alreadyLoaded++;
            continue;
        }

        result.attempted++;

        std::size_t indexed = 0;
        if (LoadAndIndexModule(record, symbols, true, log, indexed)) {
            result.loaded++;
        } else {
            result.failed++;
        }
    }

    if (log && result.attempted > 0) {
        log(L"Probe: -mod ensure: loaded " + std::to_wstring(result.loaded)
            + L"/" + std::to_wstring(result.attempted)
            + L", failed " + std::to_wstring(result.failed)
            + L", already indexed " + std::to_wstring(result.alreadyLoaded));
    }

    return result;
}

void ProbeSession::GetStatus(std::uint32_t& outPid,
                             std::size_t& outTotalSymbols,
                             std::size_t& outLoadedModules,
                             std::size_t& outFailedModules,
                             std::vector<ProbeModuleRecord>& outModules) const
{
    outPid = m_targetPid;
    outTotalSymbols = m_index.size();
    outLoadedModules = 0;
    outFailedModules = 0;
    outModules = m_modules;

    for (const ProbeModuleRecord& module : m_modules) {
        if (module.symbolsLoaded) {
            outLoadedModules++;
        } else {
            outFailedModules++;
        }
    }
}

std::vector<ProbeSymbolHit> ProbeSession::Find(const std::wstring& keyword,
                                               const std::wstring& moduleFilter,
                                               ProbeFindKind kind) const
{
    std::vector<ProbeSymbolHit> hits;
    if (m_targetPid == 0 || keyword.empty()) {
        return hits;
    }

    const std::vector<std::wstring> keywordTokens = ParseCommaSeparatedTokens(keyword);
    if (keywordTokens.empty()) {
        return hits;
    }

    const bool isKernel = (m_targetPid == 4);
    const std::vector<std::wstring> filterTokens = ParseModuleFilterTokens(moduleFilter);

    hits.reserve(256);
    for (const ProbeSymbolHit& entry : m_index) {
        if (!ModuleFilterMatches(entry.moduleName, filterTokens, isKernel)) {
            continue;
        }

        if (!SymbolNameMatchesAllKeywords(entry, keywordTokens)) {
            continue;
        }

        if (IsImportThunkSymbol(entry)) {
            continue;
        }

        if (kind == ProbeFindKind::Type) {
            if (!MatchesFindKind(entry, kind)) {
                continue;
            }
        } else if (kind == ProbeFindKind::Function || kind == ProbeFindKind::Data) {
            if (MatchesFindKind(entry, ProbeFindKind::Type)) {
                continue;
            }
        }

        hits.push_back(entry);
    }

    return hits;
}

std::vector<ProbeSymbolHit> ProbeSession::Resolve(const std::wstring& symbolQuery,
                                                  const std::wstring& moduleFilter) const
{
    std::vector<ProbeSymbolHit> hits;
    if (m_targetPid == 0 || symbolQuery.empty()) {
        return hits;
    }

    const bool isKernel = (m_targetPid == 4);
    const std::vector<std::wstring> filterTokens = ParseModuleFilterTokens(moduleFilter);

    hits.reserve(4);
    for (const ProbeSymbolHit& entry : m_index) {
        if (!ModuleFilterMatches(entry.moduleName, filterTokens, isKernel)) {
            continue;
        }

        const bool decoratedMatch = entry.decoratedName == symbolQuery;
        const bool friendlyMatch = NamesMatchExactly(entry.friendlyName, symbolQuery)
            || NamesMatchExactly(entry.displayName, symbolQuery);

        if (!decoratedMatch && !friendlyMatch) {
            continue;
        }

        hits.push_back(entry);
    }

    return hits;
}
