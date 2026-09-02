#include "symmanager.h"
#include "PathConvert.h"
#include "process.h"
#include <Psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Psapi.lib")

namespace {

const wchar_t* SYMBOL_SERVER_URL = L"https://msdl.microsoft.com/download/symbols";

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

using NtQuerySystemInformationFn = NTSTATUS (NTAPI *)(ULONG, PVOID, ULONG, PULONG);

std::wstring ExtractFileName(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? path : path.substr(slash + 1);
}

bool KernelModuleNamesMatch(const std::wstring& requestedFileName, const std::wstring& loadedFileName)
{
    if (_wcsicmp(requestedFileName.c_str(), loadedFileName.c_str()) == 0) {
        return true;
    }

    if (_wcsicmp(requestedFileName.c_str(), L"ntoskrnl.exe") == 0) {
        return _wcsnicmp(loadedFileName.c_str(), L"ntkrnl", 6) == 0;
    }

    return false;
}

std::string WideToAnsi(const std::wstring& value)
{
    if (value.empty()) {
        return {};
    }

    const int len = WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_ACP, 0, value.c_str(), -1, &result[0], len, nullptr, nullptr);
    if (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }
    return result;
}

std::wstring AnsiToWide(const char* value)
{
    if (!value || !value[0]) {
        return {};
    }

    const int len = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }

    std::wstring result(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, &result[0], len);
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

DWORD64 FindKernelModuleBase(const std::wstring& normalizedPath)
{
    const NtQuerySystemInformationFn ntQuerySystemInformation =
        reinterpret_cast<NtQuerySystemInformationFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!ntQuerySystemInformation) {
        return 0;
    }

    constexpr ULONG kSystemModuleInformation = 11;
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

    ULONG bufferSize = 0;
    ntQuerySystemInformation(kSystemModuleInformation, nullptr, 0, &bufferSize);

    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status = ntQuerySystemInformation(kSystemModuleInformation,
                                               buffer.data(),
                                               bufferSize,
                                               &bufferSize);
    while (status == kStatusInfoLengthMismatch) {
        buffer.resize(bufferSize);
        status = ntQuerySystemInformation(kSystemModuleInformation,
                                          buffer.data(),
                                          bufferSize,
                                          &bufferSize);
    }
    if (status < 0 || bufferSize < sizeof(RTL_PROCESS_MODULES)) {
        return 0;
    }

    const auto* modules = reinterpret_cast<const RTL_PROCESS_MODULES*>(buffer.data());
    const std::wstring requestedFileName = ExtractFileName(normalizedPath);

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        const RTL_PROCESS_MODULE_INFORMATION& module = modules->Modules[i];
        const char* modulePath = reinterpret_cast<const char*>(module.FullPathName);
        std::wstring fullPath = convertSystemRootPathW(AnsiToWide(modulePath).c_str());

        WCHAR normalizedModulePath[MAX_PATH] = {};
        if (GetFullPathNameW(fullPath.c_str(), MAX_PATH, normalizedModulePath, nullptr) == 0) {
            continue;
        }
        CharLowerBuffW(normalizedModulePath, static_cast<DWORD>(wcslen(normalizedModulePath)));

        if (_wcsicmp(normalizedModulePath, normalizedPath.c_str()) == 0) {
            return reinterpret_cast<DWORD64>(module.ImageBase);
        }

        const std::wstring loadedFileName = ExtractFileName(normalizedModulePath);
        if (KernelModuleNamesMatch(requestedFileName, loadedFileName)) {
            return reinterpret_cast<DWORD64>(module.ImageBase);
        }
    }

    return 0;
}

std::wstring ExtractPdbFileName(const std::wstring& pdbPath)
{
    const size_t slash = pdbPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return pdbPath;
    }
    return pdbPath.substr(slash + 1);
}

void FillSymbolInfoFromModule(const std::wstring& filePath,
                              const IMAGEHLP_MODULE64& moduleInfo,
                              DWORD64 baseAddr,
                              bool loadedInDbgHelp,
                              DWORD targetPid,
                              SYMBOL_FILE_INFO& info)
{
    info.filePath = filePath;
    info.timestamp = moduleInfo.TimeDateStamp;
    info.checksum = moduleInfo.CheckSum;
    info.baseAddr = baseAddr;
    info.loadedInDbgHelp = loadedInDbgHelp;
    info.targetPid = targetPid;
    info.localPdbPath = AnsiToWide(moduleInfo.LoadedPdbName);
    info.pdbName = ExtractPdbFileName(info.localPdbPath);
}

bool HasPdbSymbolsLoaded(const IMAGEHLP_MODULE64& moduleInfo)
{
    if (moduleInfo.SymType == SymNone
        || moduleInfo.SymType == SymDeferred
        || moduleInfo.SymType == SymExport) {
        return false;
    }

    if (moduleInfo.LoadedPdbName[0] == '\0') {
        return false;
    }

    switch (moduleInfo.SymType) {
    case SymPdb:
    case SymDia:
    case SymCv:
        return true;
    default:
        return false;
    }
}

std::wstring DescribeMissingPdbError(const IMAGEHLP_MODULE64& moduleInfo, bool keepLoaded)
{
    if (moduleInfo.SymType == SymExport) {
        return keepLoaded
            ? L"PDB not available; DbgHelp fell back to export symbols only"
            : L"PDB not available on symbol server (export symbols only)";
    }

    return keepLoaded
        ? L"PDB not found or could not be downloaded for this module"
        : L"PDB download finished but no PDB symbols were resolved";
}

DWORD64 FindModuleBaseInRemoteProcess(DWORD pid, const std::wstring& normalizedPath)
{
    HANDLE processHandle = Process::openForQuery(pid);
    if (!processHandle) {
        return 0;
    }

    const std::wstring moduleName = ExtractFileName(normalizedPath);
    DWORD bytesNeeded = 0;
    EnumProcessModulesEx(processHandle, nullptr, 0, &bytesNeeded, LIST_MODULES_ALL);
    if (bytesNeeded == 0) {
        CloseHandle(processHandle);
        return 0;
    }

    std::vector<HMODULE> modules(bytesNeeded / sizeof(HMODULE));
    if (!EnumProcessModulesEx(processHandle,
                               modules.data(),
                               bytesNeeded,
                               &bytesNeeded,
                               LIST_MODULES_ALL)) {
        CloseHandle(processHandle);
        return 0;
    }

    DWORD64 resolvedBase = 0;
    const DWORD moduleCount = bytesNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < moduleCount; ++i) {
        WCHAR modulePath[MAX_PATH] = {};
        if (GetModuleFileNameExW(processHandle, modules[i], modulePath, MAX_PATH) == 0) {
            continue;
        }

        WCHAR normalizedModulePath[MAX_PATH] = {};
        if (GetFullPathNameW(modulePath, MAX_PATH, normalizedModulePath, nullptr) == 0) {
            continue;
        }
        CharLowerBuffW(normalizedModulePath, static_cast<DWORD>(wcslen(normalizedModulePath)));

        if (_wcsicmp(normalizedModulePath, normalizedPath.c_str()) == 0) {
            resolvedBase = reinterpret_cast<DWORD64>(modules[i]);
            break;
        }

        const std::wstring loadedName = ExtractFileName(normalizedModulePath);
        if (_wcsicmp(loadedName.c_str(), moduleName.c_str()) == 0) {
            resolvedBase = reinterpret_cast<DWORD64>(modules[i]);
            break;
        }
    }

    CloseHandle(processHandle);
    return resolvedBase;
}

bool TryLoadDeferredSymbols(HANDLE processHandle, const char* filePathAnsi, DWORD64 baseAddr);

bool EnsureModuleSymbolsLoaded(HANDLE processHandle, const char* filePathAnsi, DWORD64 baseAddr)
{
    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (!SymGetModuleInfo64(processHandle, baseAddr, &moduleInfo)) {
        return false;
    }

    if (HasPdbSymbolsLoaded(moduleInfo)) {
        return true;
    }

    if (!TryLoadDeferredSymbols(processHandle, filePathAnsi, baseAddr)) {
        return false;
    }

    ZeroMemory(&moduleInfo, sizeof(moduleInfo));
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (!SymGetModuleInfo64(processHandle, baseAddr, &moduleInfo)) {
        return false;
    }

    return HasPdbSymbolsLoaded(moduleInfo);
}

std::wstring NormalizePathLocal(const std::wstring& filePath)
{
    WCHAR fullPath[MAX_PATH] = {};
    if (GetFullPathNameW(filePath.c_str(), MAX_PATH, fullPath, nullptr) == 0) {
        return filePath;
    }
    return fullPath;
}

// Resolves base address for modules already mapped in the current (Hawkeye) process.
DWORD64 FindModuleBaseInProcess(const std::wstring& normalizedPath)
{
    const size_t slash = normalizedPath.find_last_of(L"\\/");
    const std::wstring moduleName = (slash == std::wstring::npos)
        ? normalizedPath
        : normalizedPath.substr(slash + 1);

    HMODULE module = GetModuleHandleW(moduleName.c_str());
    if (!module) {
        return 0;
    }

    WCHAR modulePath[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(module, modulePath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return 0;
    }

    const std::wstring normalizedModulePath = NormalizePathLocal(modulePath);
    if (_wcsicmp(normalizedModulePath.c_str(), normalizedPath.c_str()) == 0) {
        return reinterpret_cast<DWORD64>(module);
    }

    const size_t loadedSlash = normalizedModulePath.find_last_of(L"\\/");
    const std::wstring loadedName = (loadedSlash == std::wstring::npos)
        ? normalizedModulePath
        : normalizedModulePath.substr(loadedSlash + 1);
    if (_wcsicmp(loadedName.c_str(), moduleName.c_str()) == 0) {
        return reinterpret_cast<DWORD64>(module);
    }

    return 0;
}

bool TryLoadDeferredSymbols(HANDLE processHandle, const char* filePathAnsi, DWORD64 baseAddr)
{
    const DWORD oldOptions = SymGetOptions();
    SymSetOptions(oldOptions & ~SYMOPT_DEFERRED_LOADS);

    if (filePathAnsi && filePathAnsi[0]) {
        SymLoadModuleEx(processHandle, nullptr, const_cast<PSTR>(filePathAnsi), nullptr, baseAddr, 0, nullptr, 0);
    }

    SymEnumSymbols(processHandle,
                   baseAddr,
                   nullptr,
                   [](PSYMBOL_INFO, ULONG, PVOID) -> BOOL { return FALSE; },
                   nullptr);

    SymSetOptions(oldOptions);

    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (!SymGetModuleInfo64(processHandle, baseAddr, &moduleInfo)) {
        return false;
    }

    return HasPdbSymbolsLoaded(moduleInfo);
}

bool TryRegisterModuleAtBase(HANDLE processHandle,
                             const std::wstring& key,
                             const std::string& filePathAnsi,
                             DWORD64 baseAddr,
                             bool useFileHandle,
                             DWORD64& outBaseAddr,
                             std::wstring& outError)
{
    IMAGEHLP_MODULE64 existingModuleInfo = {};
    existingModuleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(processHandle, baseAddr, &existingModuleInfo)) {
        if (HasPdbSymbolsLoaded(existingModuleInfo)) {
            outBaseAddr = baseAddr;
            return true;
        }
        SymUnloadModule64(processHandle, baseAddr);
    }

    if (useFileHandle) {
        HANDLE fileHandle = CreateFileW(key.c_str(),
                                        GENERIC_READ,
                                        FILE_SHARE_READ,
                                        nullptr,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        nullptr);
        if (fileHandle != INVALID_HANDLE_VALUE) {
            outBaseAddr = SymLoadModuleEx(processHandle,
                                          fileHandle,
                                          const_cast<PSTR>(filePathAnsi.c_str()),
                                          nullptr,
                                          baseAddr,
                                          0,
                                          nullptr,
                                          0);
            CloseHandle(fileHandle);
            if (outBaseAddr != 0) {
                return true;
            }
        }
    }

    outBaseAddr = SymLoadModuleEx(processHandle,
                                  nullptr,
                                  const_cast<PSTR>(filePathAnsi.c_str()),
                                  nullptr,
                                  baseAddr,
                                  0,
                                  nullptr,
                                  0);
    if (outBaseAddr != 0) {
        return true;
    }

    const DWORD lastError = GetLastError();
    if (SymGetModuleInfo64(processHandle, baseAddr, &existingModuleInfo)
        && HasPdbSymbolsLoaded(existingModuleInfo)) {
        outBaseAddr = baseAddr;
        return true;
    }

    wchar_t buf[256] = {};
    swprintf_s(buf,
               256,
               L"Failed to register module at base 0x%llX (error=%lu)",
               static_cast<unsigned long long>(baseAddr),
               lastError);
    outError = buf;
    return false;
}

void LogSymbolMessage(const SymbolLoadOptions* options, const std::wstring& message)
{
    if (options && options->logFn) {
        options->logFn(message);
    }
}

bool SymLoadModuleWithRetry(HANDLE hProcess,
                            const char* filePath,
                            DWORD64 preferredBase,
                            DWORD64& outBaseAddr,
                            std::wstring& outError,
                            int maxAttempts)
{
    if (maxAttempts < 1) {
        maxAttempts = 1;
    }

    DWORD lastError = 0;

    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        outBaseAddr = SymLoadModuleEx(hProcess, nullptr, const_cast<PSTR>(filePath), nullptr, preferredBase, 0, nullptr, 0);
        if (outBaseAddr != 0) {
            return true;
        }

        lastError = GetLastError();
        if (attempt + 1 < maxAttempts) {
            Sleep((attempt + 1) * 1000);
        }
    }

    wchar_t buf[256] = {};
    swprintf_s(buf, 256, L"SymLoadModuleEx failed after %d attempts (last error=%lu)", maxAttempts, lastError);
    outError = buf;
    return false;
}

struct DbgHelpModuleMatch {
    HANDLE processHandle = nullptr;
    const std::wstring* key = nullptr;
    DWORD64 matchBase = 0;
    bool hasPdb = false;
};

BOOL CALLBACK FindDbgHelpModuleByPath(PCSTR moduleName, DWORD64 baseOfDll, PVOID userContext)
{
    auto* ctx = static_cast<DbgHelpModuleMatch*>(userContext);
    IMAGEHLP_MODULE64 info = {};
    info.SizeOfStruct = sizeof(info);
    if (!SymGetModuleInfo64(ctx->processHandle, baseOfDll, &info)) {
        return TRUE;
    }

    const char* loaded = info.LoadedImageName[0] ? info.LoadedImageName : info.ImageName;
    const std::wstring loadedPath = AnsiToWide(loaded);
    bool pathMatch = false;
    if (!loadedPath.empty()
        && _wcsicmp(SymbolManager::NormalizeFilePathKey(loadedPath).c_str(), ctx->key->c_str()) == 0) {
        pathMatch = true;
    } else {
        const std::wstring wantName = ExtractFileName(*ctx->key);
        const std::wstring haveName = ExtractFileName(
            loadedPath.empty() ? AnsiToWide(moduleName) : loadedPath);
        pathMatch = !wantName.empty() && _wcsicmp(wantName.c_str(), haveName.c_str()) == 0;
    }
    if (!pathMatch) {
        return TRUE;
    }

    const bool pdb = HasPdbSymbolsLoaded(info);
    if (pdb) {
        ctx->matchBase = baseOfDll;
        ctx->hasPdb = true;
        return FALSE;
    }
    if (ctx->matchBase == 0) {
        ctx->matchBase = baseOfDll;
        ctx->hasPdb = false;
    }
    return TRUE;
}

bool CachePdbFromImageFile(HANDLE processHandle,
                           const std::wstring& key,
                           const std::string& filePathAnsi,
                           int maxLoadAttempts,
                           SYMBOL_FILE_INFO& outInfo,
                           bool& outAlreadyLoaded,
                           std::wstring& outError)
{
    outAlreadyLoaded = false;
    outInfo = {};

    DbgHelpModuleMatch ctx;
    ctx.processHandle = processHandle;
    ctx.key = &key;
    SymEnumerateModules64(processHandle, FindDbgHelpModuleByPath, &ctx);
    if (ctx.matchBase != 0) {
        if (ctx.hasPdb) {
            IMAGEHLP_MODULE64 moduleInfo = {};
            moduleInfo.SizeOfStruct = sizeof(moduleInfo);
            if (!SymGetModuleInfo64(processHandle, ctx.matchBase, &moduleInfo)) {
                outError = L"SymGetModuleInfo64 failed for already-loaded PDB";
                return false;
            }
            FillSymbolInfoFromModule(key, moduleInfo, ctx.matchBase, true, 0, outInfo);
            outAlreadyLoaded = true;
            return true;
        }
        SymUnloadModule64(processHandle, ctx.matchBase);
    }

    DWORD64 baseAddr = 0;
    if (!SymLoadModuleWithRetry(processHandle, filePathAnsi.c_str(), 0, baseAddr, outError, maxLoadAttempts)) {
        return false;
    }

    if (!EnsureModuleSymbolsLoaded(processHandle, filePathAnsi.c_str(), baseAddr)) {
        IMAGEHLP_MODULE64 failedModuleInfo = {};
        failedModuleInfo.SizeOfStruct = sizeof(failedModuleInfo);
        if (SymGetModuleInfo64(processHandle, baseAddr, &failedModuleInfo)) {
            outError = DescribeMissingPdbError(failedModuleInfo, false);
        } else {
            outError = L"PDB download finished but no PDB symbols were resolved";
        }
        SymUnloadModule64(processHandle, baseAddr);
        return false;
    }

    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(moduleInfo);
    if (!SymGetModuleInfo64(processHandle, baseAddr, &moduleInfo)) {
        SymUnloadModule64(processHandle, baseAddr);
        outError = L"SymGetModuleInfo64 failed after download";
        return false;
    }

    FillSymbolInfoFromModule(key, moduleInfo, 0, false, 0, outInfo);
    SymUnloadModule64(processHandle, baseAddr);
    return true;
}

bool LoadModuleSymbols(HANDLE processHandle,
                       const std::wstring& key,
                       const std::string& filePathAnsi,
                       bool keepLoaded,
                       DWORD targetPid,
                       int maxLoadAttempts,
                       bool allowDownload,
                       DWORD64& outBaseAddr,
                       SYMBOL_FILE_INFO& outInfo,
                       std::wstring& outError)
{
    constexpr wchar_t kModuleNotFoundError[] = L"Module not found";

    DWORD64 loadBase = 0;
    bool dbgHelpOwnedMapping = false;

    if (targetPid != 0) {
        loadBase = FindModuleBaseInRemoteProcess(targetPid, key);
        if (loadBase == 0) {
            outError = kModuleNotFoundError;
            return false;
        }
        dbgHelpOwnedMapping = true;
    } else {
        loadBase = FindModuleBaseInProcess(key);
        if (loadBase == 0) {
            loadBase = FindKernelModuleBase(key);
        }
        dbgHelpOwnedMapping = (loadBase == 0);

        if (loadBase == 0 && keepLoaded) {
            outError = kModuleNotFoundError;
            return false;
        }
    }

    if (loadBase != 0) {
        const bool useFileHandle = (FindModuleBaseInProcess(key) == 0);
        if (!TryRegisterModuleAtBase(processHandle, key, filePathAnsi, loadBase, useFileHandle, outBaseAddr, outError)) {
            return false;
        }
    } else if (!SymLoadModuleWithRetry(processHandle, filePathAnsi.c_str(), 0, outBaseAddr, outError, maxLoadAttempts)) {
        return false;
    }

    if (!EnsureModuleSymbolsLoaded(processHandle, filePathAnsi.c_str(), outBaseAddr)) {
        IMAGEHLP_MODULE64 failedModuleInfo = {};
        failedModuleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        if (SymGetModuleInfo64(processHandle, outBaseAddr, &failedModuleInfo)) {
            outError = DescribeMissingPdbError(failedModuleInfo, keepLoaded);
        } else if (!allowDownload) {
            outError = L"PDB not in local cache";
        } else {
            outError = keepLoaded
                ? L"PDB not found or could not be downloaded for this module"
                : L"PDB download finished but no PDB symbols were resolved";
        }

        if (keepLoaded || dbgHelpOwnedMapping) {
            SymUnloadModule64(processHandle, outBaseAddr);
        }
        return false;
    }

    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (!SymGetModuleInfo64(processHandle, outBaseAddr, &moduleInfo)) {
        if (keepLoaded || dbgHelpOwnedMapping) {
            SymUnloadModule64(processHandle, outBaseAddr);
        }
        outError = keepLoaded
            ? L"SymGetModuleInfo64 failed after load"
            : L"SymGetModuleInfo64 failed after download";
        return false;
    }

    FillSymbolInfoFromModule(key, moduleInfo, keepLoaded ? outBaseAddr : 0, keepLoaded, targetPid, outInfo);
    if (!keepLoaded) {
        SymUnloadModule64(processHandle, outBaseAddr);
        outBaseAddr = 0;
    }

    return true;
}

} // namespace

SymbolManager::SymbolManager()
    : m_initialized(false)
    , m_processHandle(nullptr)
{
}

void SymbolManager::InvalidateNameIndex()
{
    m_nameIndex.clear();
    m_nameIndexBuilt = false;
    m_nameIndexModuleBase = 0;
}

std::wstring SymbolManager::DemangleSymbolName(const std::wstring& symbolName)
{
    if (symbolName.empty()) {
        return {};
    }

    const std::string nameAnsi = WideToAnsi(symbolName);
    if (nameAnsi.empty()) {
        return {};
    }

    char undecorated[1024] = {};
    if (!UnDecorateSymbolName(
            nameAnsi.c_str(),
            undecorated,
            sizeof(undecorated),
            UNDNAME_COMPLETE | UNDNAME_NO_ACCESS_SPECIFIERS)) {
        return {};
    }

    const std::wstring friendly = AnsiToWide(undecorated);
    if (friendly.empty() || friendly == symbolName) {
        return {};
    }

    return friendly;
}

SymbolManager::~SymbolManager()
{
    Cleanup();
}

bool SymbolManager::Initialize()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        return true;
    }

    m_processHandle = GetCurrentProcess();

    if (!CreateSymbolDirectory()) {
        return false;
    }

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);

    m_symbolSearchPath = L"srv*" + m_symbolPath + L"*" + SYMBOL_SERVER_URL;
    m_symbolSearchPathLocal = L"srv*" + m_symbolPath + L"*";
    const std::string symbolSearchPathAnsi = WideToAnsi(m_symbolSearchPath);
    if (symbolSearchPathAnsi.empty()) {
        return false;
    }

    if (!SymInitialize(m_processHandle, symbolSearchPathAnsi.c_str(), FALSE)) {
        return false;
    }

    m_initialized = true;
    return true;
}

void SymbolManager::Cleanup()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        return;
    }

    SymCleanup(m_processHandle);
    m_initialized = false;
    m_processHandle = nullptr;
    m_symbols.clear();
    InvalidateNameIndex();
}

bool SymbolManager::CreateSymbolDirectory()
{
    WCHAR exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    WCHAR* lastSlash = wcsrchr(exePath, L'\\');
    if (lastSlash) {
        *lastSlash = L'\0';
    }

    m_symbolPath = std::wstring(exePath) + L"\\symbols";

    if (!PathFileExistsW(m_symbolPath.c_str())) {
        if (!CreateDirectoryW(m_symbolPath.c_str(), nullptr)) {
            return false;
        }
    }

    return true;
}

std::wstring SymbolManager::NormalizeFilePathKey(const std::wstring& filePath)
{
    WCHAR fullPath[MAX_PATH] = {};
    const DWORD length = GetFullPathNameW(filePath.c_str(), MAX_PATH, fullPath, nullptr);
    if (length == 0 || length >= MAX_PATH) {
        std::wstring fallback = filePath;
        if (!fallback.empty()) {
            CharLowerBuffW(&fallback[0], static_cast<DWORD>(fallback.size()));
        }
        return fallback;
    }

    CharLowerBuffW(fullPath, static_cast<DWORD>(wcslen(fullPath)));
    return fullPath;
}

bool SymbolManager::DownloadSymbol(const std::wstring& filePath, std::wstring& outPdbPath, std::wstring& outError)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        outError = L"Symbol manager not initialized";
        return false;
    }

    const std::wstring key = NormalizeFilePathKey(filePath);
    const std::string filePathAnsi = WideToAnsi(key);
    if (filePathAnsi.empty()) {
        outError = L"Invalid file path";
        return false;
    }

    const auto existing = m_symbols.find(key);
    if (existing != m_symbols.end() && existing->second.loadedInDbgHelp
        && !existing->second.localPdbPath.empty()) {
        outPdbPath = existing->second.localPdbPath;
        return true;
    }

    SYMBOL_FILE_INFO info;
    bool alreadyLoaded = false;
    if (!CachePdbFromImageFile(m_processHandle, key, filePathAnsi, 4, info, alreadyLoaded, outError)) {
        return false;
    }

    outPdbPath = info.localPdbPath;
    if (alreadyLoaded) {
        if (existing == m_symbols.end() || !existing->second.loadedInDbgHelp) {
            m_symbols[key] = info;
            InvalidateNameIndex();
        }
        return true;
    }

    m_symbols[key] = info;
    return true;
}

bool SymbolManager::LoadSymbol(const std::wstring& filePath,
                               std::wstring& outError,
                               DWORD targetPid,
                               const SymbolLoadOptions* options)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        outError = L"Symbol manager not initialized";
        return false;
    }

    const std::wstring normalizedPath = NormalizeFilePathKey(filePath);
    const auto existing = m_symbols.find(normalizedPath);
    if (existing != m_symbols.end() && existing->second.loadedInDbgHelp) {
        LogSymbolMessage(options, L"[sym] Already loaded: " + normalizedPath);
        return true;
    }

    const std::string filePathAnsi = WideToAnsi(normalizedPath);
    if (filePathAnsi.empty()) {
        outError = L"Invalid file path";
        return false;
    }

    const int maxLoadAttempts = (options && options->maxLoadAttempts > 0) ? options->maxLoadAttempts : 4;
    const bool allowDownload = !(options && !options->allowDownload);
    const int effectiveAttempts = allowDownload ? maxLoadAttempts : 1;
    LogSymbolMessage(options, L"[sym] Loading: " + normalizedPath
                               + (targetPid != 0 ? L" (PID " + std::to_wstring(targetPid) + L")" : L"")
                               + (allowDownload ? L"" : L" [local cache only]"));

    std::string searchPathToRestore;
    if (!allowDownload) {
        searchPathToRestore = WideToAnsi(m_symbolSearchPath);
        const std::string localSearchPathAnsi = WideToAnsi(m_symbolSearchPathLocal);
        if (!localSearchPathAnsi.empty()) {
            SymSetSearchPath(m_processHandle, localSearchPathAnsi.c_str());
        }
    }

    if (allowDownload) {
        SYMBOL_FILE_INFO cacheInfo;
        bool alreadyLoaded = false;
        if (!CachePdbFromImageFile(m_processHandle,
                                   normalizedPath,
                                   filePathAnsi,
                                   effectiveAttempts,
                                   cacheInfo,
                                   alreadyLoaded,
                                   outError)) {
            LogSymbolMessage(options, L"[sym] Failed: " + normalizedPath + L" - " + outError);
            return false;
        }
        if (alreadyLoaded) {
            m_symbols[normalizedPath] = cacheInfo;
            InvalidateNameIndex();
            LogSymbolMessage(options, L"[sym] Already loaded: " + normalizedPath);
            return true;
        }
        m_symbols[normalizedPath] = cacheInfo;
    }

    SYMBOL_FILE_INFO info;
    DWORD64 baseAddr = 0;
    if (!LoadModuleSymbols(m_processHandle,
                           normalizedPath,
                           filePathAnsi,
                           true,
                           targetPid,
                           effectiveAttempts,
                           allowDownload,
                           baseAddr,
                           info,
                           outError)) {
        if (!allowDownload && !searchPathToRestore.empty()) {
            SymSetSearchPath(m_processHandle, searchPathToRestore.c_str());
        }
        LogSymbolMessage(options, L"[sym] Failed: " + normalizedPath + L" - " + outError);
        return false;
    }

    if (!allowDownload && !searchPathToRestore.empty()) {
        SymSetSearchPath(m_processHandle, searchPathToRestore.c_str());
    }

    m_symbols[normalizedPath] = info;
    InvalidateNameIndex();
    const std::wstring pdbLabel = info.pdbName.empty() ? info.localPdbPath : info.pdbName;
    LogSymbolMessage(options, L"[sym] OK: " + normalizedPath
                               + (pdbLabel.empty() ? L"" : L" -> " + pdbLabel));
    return true;
}

bool SymbolManager::UnloadSymbol(const std::wstring& filePath, bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    if (!m_initialized) {
        return false;
    }

    const std::wstring normalizedPath = NormalizeFilePathKey(filePath);
    const auto it = m_symbols.find(normalizedPath);
    if (it == m_symbols.end()) {
        return false;
    }

    if (!it->second.loadedInDbgHelp || it->second.baseAddr == 0) {
        return false;
    }

    SymUnloadModule64(m_processHandle, it->second.baseAddr);
    it->second.loadedInDbgHelp = false;
    it->second.baseAddr = 0;

    InvalidateNameIndex();

    return true;
}

bool SymbolManager::IsSymbolLoaded(const std::wstring& filePath, bool* outBusy) const
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    const std::wstring normalizedPath = NormalizeFilePathKey(filePath);
    const auto it = m_symbols.find(normalizedPath);
    return it != m_symbols.end() && it->second.loadedInDbgHelp;
}

bool SymbolManager::IsSymbolCached(const std::wstring& filePath, bool* outBusy) const
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    const std::wstring normalizedPath = NormalizeFilePathKey(filePath);
    return m_symbols.find(normalizedPath) != m_symbols.end();
}

bool SymbolManager::GetSymbolName(DWORD64 address, std::wstring& outSymbolName, bool* outBusy)
{
    DWORD64 displacement = 0;
    std::wstring moduleName;
    DWORD64 moduleBase = 0;
    if (!ResolveAddress(address, outSymbolName, displacement, moduleName, moduleBase, outBusy)) {
        return false;
    }
    return !outSymbolName.empty();
}

bool SymbolManager::ResolveAddress(DWORD64 address,
                                   std::wstring& outSymbolName,
                                   DWORD64& outDisplacement,
                                   std::wstring& outModuleName,
                                   DWORD64& outModuleBase,
                                   bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    outSymbolName.clear();
    outDisplacement = 0;
    outModuleName.clear();
    outModuleBase = 0;

    if (!m_initialized) {
        return false;
    }

    outModuleBase = SymGetModuleBase64(m_processHandle, address);
    if (outModuleBase == 0) {
        return false;
    }

    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(m_processHandle, address, &moduleInfo)) {
        outModuleName = AnsiToWide(moduleInfo.ModuleName);
    }

    constexpr DWORD kMaxSymbolNameLen = 1024;
    BYTE buffer[sizeof(SYMBOL_INFO) + kMaxSymbolNameLen] = {};
    auto* symbolInfo = reinterpret_cast<SYMBOL_INFO*>(buffer);
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo->MaxNameLen = kMaxSymbolNameLen - 1;

    if (!SymFromAddr(m_processHandle, address, &outDisplacement, symbolInfo)) {
        return false;
    }

    outSymbolName = AnsiToWide(symbolInfo->Name);
    return !outSymbolName.empty();
}

// ============================================================================

// ============================================================================

bool SymbolManager::GetSymbolAddress(const std::wstring& decoratedName,
                                     DWORD64& outAddress,
                                     bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) *outBusy = true;
        return false;
    }
    if (outBusy) *outBusy = false;

    outAddress = 0;
    if (!m_initialized || decoratedName.empty()) {
        return false;
    }

    const std::string nameAnsi = WideToAnsi(decoratedName);

    SYMBOL_INFO symbolInfo = {};
    symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.MaxNameLen = 0;

    if (!SymFromName(m_processHandle, nameAnsi.c_str(), &symbolInfo)) {
        return false;
    }

    outAddress = symbolInfo.Address;
    return true;
}

bool SymbolManager::BuildNameIndex(DWORD64 moduleBase, bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) *outBusy = true;
        return false;
    }
    if (outBusy) *outBusy = false;

    if (!m_initialized) {
        return false;
    }

    InvalidateNameIndex();

    struct EnumContext {
        std::map<std::wstring, DWORD64>* index;
    } ctx{ &m_nameIndex };

    SymEnumSymbols(m_processHandle,
                   moduleBase,
                   nullptr,
                   [](PSYMBOL_INFO pSym, ULONG /*SymbolSize*/, PVOID userCtx) -> BOOL {
                       auto* context = static_cast<EnumContext*>(userCtx);

                       if (!pSym->Name[0]) {
                           return TRUE;
                       }

                       (*context->index)[AnsiToWide(pSym->Name)] = pSym->Address;

                       char undecorated[1024] = {};
                       if (UnDecorateSymbolName(pSym->Name,
                                                undecorated,
                                                sizeof(undecorated),
                                                UNDNAME_COMPLETE | UNDNAME_NO_ACCESS_SPECIFIERS)) {
                           const std::wstring friendly = AnsiToWide(undecorated);
                           if (!friendly.empty()) {
                               (*context->index)[friendly] = pSym->Address;
                           }
                       }

                       return TRUE;
                   },
                   &ctx);

    m_nameIndexModuleBase = moduleBase;
    m_nameIndexBuilt = !m_nameIndex.empty();
    return m_nameIndexBuilt;
}

bool SymbolManager::GetSymbolAddressByName(const std::wstring& friendlyName,
                                           DWORD64& outAddress,
                                           bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) *outBusy = true;
        return false;
    }
    if (outBusy) *outBusy = false;

    outAddress = 0;
    if (!m_initialized || friendlyName.empty()) {
        return false;
    }

    if (!m_nameIndexBuilt) {
        return false;
    }

    const auto it = m_nameIndex.find(friendlyName);
    if (it != m_nameIndex.end()) {
        outAddress = it->second;
        return true;
    }

    return false;
}

bool SymbolManager::GetLoadedModuleBase(const std::wstring& filePath,
                                        DWORD64& outBaseAddr,
                                        bool* outBusy) const
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    outBaseAddr = 0;
    const std::wstring normalizedPath = NormalizeFilePathKey(filePath);
    const auto it = m_symbols.find(normalizedPath);
    if (it == m_symbols.end() || !it->second.loadedInDbgHelp || it->second.baseAddr == 0) {
        return false;
    }

    outBaseAddr = it->second.baseAddr;
    return true;
}

bool SymbolManager::GetModuleAtAddress(DWORD64 address,
                                       DWORD64& outModuleBase,
                                       std::wstring& outModuleName,
                                       bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    outModuleBase = 0;
    outModuleName.clear();

    if (!m_initialized) {
        return false;
    }

    outModuleBase = SymGetModuleBase64(m_processHandle, address);
    if (outModuleBase == 0 || address < outModuleBase) {
        outModuleBase = 0;
        return false;
    }

    IMAGEHLP_MODULE64 moduleInfo = {};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(m_processHandle, address, &moduleInfo)) {
        outModuleName = AnsiToWide(moduleInfo.ModuleName);
    }

    return true;
}

bool SymbolManager::GetModuleInfo(DWORD64 address, IMAGEHLP_MODULE64& outModule)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        return false;
    }

    ZeroMemory(&outModule, sizeof(outModule));
    outModule.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    return SymGetModuleInfo64(m_processHandle, address, &outModule) == TRUE;
}

bool SymbolManager::GetSymbolEntries(std::vector<SYMBOL_FILE_INFO>& outEntries, bool* outBusy) const
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    outEntries.clear();
    outEntries.reserve(m_symbols.size());
    for (const auto& pair : m_symbols) {
        outEntries.push_back(pair.second);
    }
    return true;
}

std::wstring SymbolManager::GetSymbolCacheDirectory(bool* outBusy) const
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return {};
    }
    if (outBusy) {
        *outBusy = false;
    }

    return m_symbolPath;
}

bool SymbolManager::CollectModuleSymbols(DWORD64 moduleBase,
                                         std::vector<CollectedSymbol>& outSymbols,
                                         bool* outBusy)
{
    std::unique_lock<std::mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        if (outBusy) {
            *outBusy = true;
        }
        return false;
    }
    if (outBusy) {
        *outBusy = false;
    }

    outSymbols.clear();
    if (!m_initialized) {
        return false;
    }

    struct EnumContext {
        std::vector<CollectedSymbol>* symbols;
    } ctx{ &outSymbols };

    SymEnumSymbols(m_processHandle,
                   moduleBase,
                   nullptr,
                   [](PSYMBOL_INFO pSym, ULONG /*SymbolSize*/, PVOID userCtx) -> BOOL {
                       if (!pSym || !pSym->Name[0]) {
                           return TRUE;
                       }

                       auto* context = static_cast<EnumContext*>(userCtx);
                       CollectedSymbol entry;
                       entry.decoratedName = AnsiToWide(pSym->Name);
                       entry.address = pSym->Address;
                       entry.symTag = pSym->Tag;
                       entry.flags = pSym->Flags;

                       char undecorated[1024] = {};
                       if (UnDecorateSymbolName(pSym->Name,
                                                undecorated,
                                                sizeof(undecorated),
                                                UNDNAME_COMPLETE | UNDNAME_NO_ACCESS_SPECIFIERS)) {
                           entry.friendlyName = AnsiToWide(undecorated);
                       }

                       context->symbols->push_back(std::move(entry));
                       return TRUE;
                   },
                   &ctx);

    return !outSymbols.empty();
}
