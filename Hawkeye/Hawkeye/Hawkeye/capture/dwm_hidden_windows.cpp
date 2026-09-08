#include "dwm_hidden_windows.h"

#include "Driver.h"
#include "PathConvert.h"
#include "process.h"
#include "symmanager.h"

#include "common.h"

#include <cwctype>
#include <memory>
#include <sstream>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace {

constexpr ULONG kVtableAlign = 8;
constexpr ULONG kFieldAlign = 4;
constexpr ULONG kKindSearchEnd = 0x200;
constexpr ULONG kHwndPidSearchSpan = 0x100;

enum class MemoryInformationClass : ULONG
{
    BasicInformation = 0,
};

using ZwQueryVirtualMemoryFn = NTSTATUS(NTAPI*)(
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

struct HiddenWindowObjectLayout
{
    ULONGLONG vtableAddress = 0;
    ULONGLONG sampleObjectAddress = 0;
    ULONG flagsOffset = 0;
    ULONG kindOffset = 0;
    ULONG hwndOffset = 0;
    ULONG pidOffset = 0;
};

struct HandleCloser
{
    void operator()(HANDLE handle) const
    {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using ScopedHandle = std::unique_ptr<void, HandleCloser>;

HiddenWindowOffsetState g_offsetState = HiddenWindowOffsetState::NotInitialized;
HiddenWindowObjectLayout g_layout;

void logLine(const HiddenWindowLogFn& logFn, const std::wstring& line)
{
    if (logFn) {
        logFn(line);
    }
}

template<typename T>
void appendLogStream(std::wostringstream& stream, T&& value)
{
    stream << std::forward<T>(value);
}

template<typename T, typename... Rest>
void appendLogStream(std::wostringstream& stream, T&& value, Rest&&... rest)
{
    stream << std::forward<T>(value);
    appendLogStream(stream, std::forward<Rest>(rest)...);
}

template<typename... Args>
void logf(const HiddenWindowLogFn& logFn, Args&&... args)
{
    std::wostringstream stream;
    appendLogStream(stream, std::forward<Args>(args)...);
    logLine(logFn, stream.str());
}

ULONG readU32(const void* base, ULONG offset)
{
    return *reinterpret_cast<const ULONG*>(static_cast<const UCHAR*>(base) + offset);
}

const UCHAR* regionBytes(const void* region, ULONG offset)
{
    return static_cast<const UCHAR*>(region) + offset;
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

bool hasProtectionBit6(ULONG flags)
{
    return (flags & 0x40u) != 0;
}

bool matchesWindowKind(ULONG kind)
{
    return kind == 0x2 || kind == 0x4;
}

bool isPlausibleProcessId(ULONG pid)
{
    return pid > 0 && pid < MAX_SAMPLE_TID && (pid % 4 == 0);
}

bool layoutReady()
{
    return g_layout.vtableAddress != 0
        && g_layout.flagsOffset != 0
        && g_layout.kindOffset != 0
        && g_layout.hwndOffset != 0
        && g_layout.pidOffset != 0
        && g_layout.hwndOffset < g_layout.pidOffset;
}

std::wstring findDwmredirModulePath(DWORD dwmPid)
{
    for (const Process::ModuleInfo& module : Process::enumerateModules(dwmPid)) {
        const size_t slash = module.path.find_last_of(L"\\/");
        const std::wstring fileName = (slash == std::wstring::npos)
            ? module.path
            : module.path.substr(slash + 1);
        if (_wcsicmp(fileName.c_str(), L"dwmredir.dll") == 0) {
            return module.path;
        }
    }
    return {};
}

bool containsInsensitive(const std::wstring& haystack, const wchar_t* needle)
{
    if (!needle || !needle[0]) {
        return false;
    }

    std::wstring lowerHaystack = haystack;
    std::wstring lowerNeedle = needle;
    for (wchar_t& ch : lowerHaystack) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    for (wchar_t& ch : lowerNeedle) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return lowerHaystack.find(lowerNeedle) != std::wstring::npos;
}

bool loadDwmredirSymbols(
    DWORD dwmPid,
    SymbolManager* symbolManager,
    const HiddenWindowLogFn& logFn,
    std::wstring& moduleKeyOut,
    DWORD64& moduleBaseOut,
    std::wstring& errorOut)
{
    moduleKeyOut.clear();
    moduleBaseOut = 0;
    errorOut.clear();

    if (!symbolManager) {
        errorOut = L"Symbol manager is not available.";
        return false;
    }

    const std::wstring modulePath = findDwmredirModulePath(dwmPid);
    if (modulePath.empty()) {
        errorOut = L"dwmredir.dll was not found in dwm.exe module list.";
        return false;
    }

    logf(logFn, L"[hidden_windows] dwmredir.dll path: ", modulePath);

    const std::wstring dosPath = convertSystemRootPathW(modulePath.c_str());
    if (dosPath.empty()) {
        errorOut = L"Failed to normalize dwmredir.dll path.";
        return false;
    }

    moduleKeyOut = SymbolManager::NormalizeFilePathKey(dosPath);

    bool symBusy = false;
    if (!symbolManager->IsSymbolLoaded(moduleKeyOut, &symBusy)) {
        if (symBusy) {
            errorOut = L"Symbol manager is busy.";
            return false;
        }

        logLine(logFn, L"[hidden_windows] Loading dwmredir.dll symbols (PDB download allowed)...");
        SymbolLoadOptions loadOptions;
        loadOptions.allowDownload = true;
        loadOptions.maxLoadAttempts = 4;
        loadOptions.logFn = logFn;

        std::wstring loadError;
        if (!symbolManager->LoadSymbol(dosPath, loadError, dwmPid, &loadOptions)) {
            errorOut = loadError.empty() ? L"Failed to load dwmredir.dll symbols." : loadError;
            return false;
        }

        logLine(logFn, L"[hidden_windows] dwmredir.dll symbols loaded.");
    } else {
        logLine(logFn, L"[hidden_windows] dwmredir.dll symbols already loaded.");
    }

    if (!symbolManager->GetLoadedModuleBase(moduleKeyOut, moduleBaseOut, &symBusy) || moduleBaseOut == 0) {
        errorOut = symBusy ? L"Symbol manager is busy." : L"Could not resolve dwmredir.dll module base.";
        return false;
    }

    logf(logFn, L"[hidden_windows] dwmredir.dll base in dwm.exe: 0x", std::hex, moduleBaseOut, std::dec);
    return true;
}

bool resolveCWindowContextVtable(
    SymbolManager* symbolManager,
    DWORD64 moduleBase,
    const HiddenWindowLogFn& logFn,
    ULONGLONG& vtableOut,
    std::wstring& symbolNameOut,
    std::wstring& errorOut)
{
    vtableOut = 0;
    symbolNameOut.clear();
    errorOut.clear();

    bool symBusy = false;
    if (!symbolManager->BuildNameIndex(moduleBase, &symBusy)) {
        errorOut = symBusy ? L"Symbol manager is busy." : L"Failed to build dwmredir name index.";
        return false;
    }

    std::vector<CollectedSymbol> symbols;
    if (!symbolManager->CollectModuleSymbols(moduleBase, symbols, &symBusy) || symbols.empty()) {
        errorOut = symBusy ? L"Symbol manager is busy." : L"No symbols collected from dwmredir.dll.";
        return false;
    }

    logf(logFn, L"[hidden_windows] Scanning ", symbols.size(), L" dwmredir symbols for CWindowContext vftable...");

    const CollectedSymbol* idwmCandidate = nullptr;
    const CollectedSymbol* genericCandidate = nullptr;

    for (const CollectedSymbol& symbol : symbols) {
        const bool mentionsContext = containsInsensitive(symbol.decoratedName, L"cwindowcontext")
            || containsInsensitive(symbol.friendlyName, L"cwindowcontext");
        const bool mentionsVftable = containsInsensitive(symbol.decoratedName, L"vftable")
            || containsInsensitive(symbol.friendlyName, L"vftable");
        if (!mentionsContext || !mentionsVftable) {
            continue;
        }

        const bool mentionsIdwm = containsInsensitive(symbol.decoratedName, L"idwmwindow")
            || containsInsensitive(symbol.friendlyName, L"idwmwindow");

        logf(logFn,
            L"[hidden_windows]   candidate: 0x",
            std::hex,
            symbol.address,
            std::dec,
            L"  ",
            symbol.friendlyName.empty() ? symbol.decoratedName : symbol.friendlyName);

        if (mentionsIdwm) {
            idwmCandidate = &symbol;
            break;
        }

        if (!genericCandidate) {
            genericCandidate = &symbol;
        }
    }

    const CollectedSymbol* chosen = idwmCandidate ? idwmCandidate : genericCandidate;
    if (!chosen) {
        errorOut = L"CWindowContext vftable symbol not found in dwmredir.dll.";
        return false;
    }

    vtableOut = static_cast<ULONGLONG>(chosen->address);
    symbolNameOut = chosen->friendlyName.empty() ? chosen->decoratedName : chosen->friendlyName;

    if (!idwmCandidate && genericCandidate) {
        logLine(logFn, L"[hidden_windows] Warning: IDwmWindow vftable not found; using first CWindowContext vftable match.");
    }

    logf(logFn, L"[hidden_windows] Selected vftable: 0x", std::hex, vtableOut, std::dec, L"  (", symbolNameOut, L")");
    return true;
}

bool tryResolveLayoutFromObject(
    const void* objectBytes,
    ULONG objectBytesSize,
    ULONGLONG objectAddress,
    ULONGLONG vtableAddress,
    ULONG calibrateHwnd,
    ULONG calibratePid,
    HiddenWindowObjectLayout& layoutOut,
    const HiddenWindowLogFn& logFn)
{
    if (objectBytesSize < sizeof(ULONGLONG)) {
        return false;
    }

    const ULONGLONG objectVtable = *reinterpret_cast<const ULONGLONG*>(objectBytes);
    if (objectVtable != vtableAddress) {
        return false;
    }

    const ULONG searchLimit = objectBytesSize - sizeof(ULONG);
    if (searchLimit < kFieldAlign) {
        return false;
    }

    for (ULONG kindOffset = kFieldAlign; kindOffset < kKindSearchEnd && kindOffset <= searchLimit; kindOffset += kFieldAlign) {
        const ULONG kind = readU32(objectBytes, kindOffset);
        if (!matchesWindowKind(kind)) {
            continue;
        }

        if (kindOffset < kFieldAlign) {
            continue;
        }

        const ULONG flagsOffset = kindOffset - kFieldAlign;
        const ULONG flags = readU32(objectBytes, flagsOffset);
        if (!hasProtectionBit6(flags)) {
            continue;
        }

        ULONG hwndOffset = 0;
        ULONG pidOffset = 0;
        const ULONG tailLimit = kindOffset + kHwndPidSearchSpan;
        const ULONG hwndPidSearchEnd = tailLimit <= searchLimit ? tailLimit : searchLimit;

        for (ULONG fieldOffset = kindOffset + kFieldAlign; fieldOffset <= hwndPidSearchEnd; fieldOffset += kFieldAlign) {
            const ULONG value = readU32(objectBytes, fieldOffset);
            if (hwndOffset == 0) {
                if (value == calibrateHwnd) {
                    hwndOffset = fieldOffset;
                }
                continue;
            }

            if (pidOffset == 0 && fieldOffset > hwndOffset && value == calibratePid) {
                pidOffset = fieldOffset;
                break;
            }
        }

        if (hwndOffset == 0 || pidOffset == 0) {
            continue;
        }

        layoutOut = {};
        layoutOut.vtableAddress = vtableAddress;
        layoutOut.sampleObjectAddress = objectAddress;
        layoutOut.flagsOffset = flagsOffset;
        layoutOut.kindOffset = kindOffset;
        layoutOut.hwndOffset = hwndOffset;
        layoutOut.pidOffset = pidOffset;

        logf(logFn, L"[hidden_windows] Matched CWindowContext candidate at 0x", std::hex, objectAddress, std::dec);
        logf(logFn, L"[hidden_windows]   vftable @ +0x00000000 = 0x", std::hex, objectVtable, std::dec);
        logf(logFn, L"[hidden_windows]   protection flags @ +0x", std::hex, flagsOffset, std::dec, L" = 0x", std::hex, flags, std::dec, L" (bit6 set)");
        logf(logFn, L"[hidden_windows]   window kind @ +0x", std::hex, kindOffset, std::dec, L" = 0x", std::hex, kind, std::dec);
        logf(logFn, L"[hidden_windows]   hwnd @ +0x", std::hex, hwndOffset, std::dec, L" = 0x", std::hex, calibrateHwnd, std::dec);
        logf(logFn, L"[hidden_windows]   pid  @ +0x", std::hex, pidOffset, std::dec, L" = ", std::dec, calibratePid);
        return true;
    }

    return false;
}

bool scanRegionForCalibration(
    const void* region,
    ULONGLONG regionBase,
    ULONG regionSize,
    ULONGLONG vtableAddress,
    ULONG calibrateHwnd,
    ULONG calibratePid,
    HiddenWindowObjectLayout& layoutOut,
    const HiddenWindowLogFn& logFn,
    ULONG& vtableHitsOut)
{
    if (!region || regionSize < sizeof(ULONGLONG)) {
        return false;
    }

    const ULONG scanLimit = regionSize - sizeof(ULONGLONG);
    for (ULONG offset = 0; offset <= scanLimit; offset += kVtableAlign) {
        const ULONGLONG value = *reinterpret_cast<const ULONGLONG*>(regionBytes(region, offset));
        if (value != vtableAddress) {
            continue;
        }

        ++vtableHitsOut;
        const ULONGLONG objectAddress = regionBase + offset;
        const ULONG tailBytes = regionSize - offset;
        if (tryResolveLayoutFromObject(
                regionBytes(region, offset),
                tailBytes,
                objectAddress,
                vtableAddress,
                calibrateHwnd,
                calibratePid,
                layoutOut,
                logFn)) {
            return true;
        }
    }

    return false;
}

bool shouldScanRegion(const MemoryBasicInformation64& regionInfo)
{
    return (regionInfo.Type & MEM_IMAGE) == 0 && (regionInfo.Protect & PAGE_READWRITE) != 0;
}

HANDLE openDwmProcessWithFallback(DWORD pid, DWORD desiredAccess)
{
    HANDLE processHandle = OpenProcess(desiredAccess, FALSE, pid);
    if (processHandle) {
        return processHandle;
    }

    OPEN_PROCESS_HANDLE inout = { 0 };
    inout.pid = pid;
    inout.desiredAccess = desiredAccess;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return nullptr;
    }

    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(inout.processHandle));
}

bool calibrateHiddenWindowLayout(
    DWORD dwmPid,
    ULONGLONG vtableAddress,
    HWND calibrateHwnd,
    ULONG calibratePid,
    HiddenWindowObjectLayout& layoutOut,
    const HiddenWindowLogFn& logFn,
    std::wstring& errorOut)
{
    layoutOut = {};
    errorOut.clear();

    const ZwQueryVirtualMemoryFn queryVirtualMemoryFn = queryVirtualMemory();
    if (!queryVirtualMemoryFn) {
        errorOut = L"ZwQueryVirtualMemory is unavailable.";
        return false;
    }

    ScopedHandle processHandle(openDwmProcessWithFallback(
        dwmPid,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ));
    if (!processHandle) {
        errorOut = L"Failed to open dwm.exe for memory read.";
        return false;
    }

    logf(logFn,
        L"[hidden_windows] Scanning dwm.exe memory for vftable 0x",
        std::hex,
        vtableAddress,
        std::dec,
        L" with calibration hwnd=0x",
        std::hex,
        HandleToUlong(calibrateHwnd),
        std::dec,
        L" pid=",
        calibratePid);

    ULONG regionsScanned = 0;
    ULONG vtableHits = 0;
    PVOID address = nullptr;
    MemoryBasicInformation64 regionInfo{};

    while (NT_SUCCESS(queryVirtualMemoryFn(
        processHandle.get(),
        address,
        MemoryInformationClass::BasicInformation,
        &regionInfo,
        sizeof(regionInfo),
        nullptr)))
    {
        if (shouldScanRegion(regionInfo)) {
            ++regionsScanned;
            std::vector<UCHAR> buffer(static_cast<size_t>(regionInfo.RegionSize));
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(
                    processHandle.get(),
                    reinterpret_cast<LPCVOID>(regionInfo.BaseAddress),
                    buffer.data(),
                    buffer.size(),
                    &bytesRead)
                && bytesRead >= sizeof(ULONGLONG))
            {
                if (scanRegionForCalibration(
                        buffer.data(),
                        regionInfo.BaseAddress,
                        static_cast<ULONG>(bytesRead),
                        vtableAddress,
                        HandleToUlong(calibrateHwnd),
                        calibratePid,
                        layoutOut,
                        logFn,
                        vtableHits)) {
                    logf(logFn,
                        L"[hidden_windows] Calibration succeeded after scanning ",
                        regionsScanned,
                        L" RW region(s), ",
                        vtableHits,
                        L" vftable hit(s).");
                    return true;
                }
            }
        }

        address = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(address) + regionInfo.RegionSize);
    }

    logf(logFn,
        L"[hidden_windows] Calibration failed: scanned ",
        regionsScanned,
        L" RW region(s), ",
        vtableHits,
        L" vftable hit(s), no full match (bit6 + kind 2/4 + hwnd + pid).");
    errorOut = L"No CWindowContext object matched calibration criteria in dwm.exe.";
    return false;
}

void collectHiddenWindowsFromRegion(
    const void* region,
    ULONG regionSize,
    std::vector<WndInfo>& windows)
{
    if (!layoutReady()) {
        return;
    }

    const ULONG scanLimit = regionSize - g_layout.pidOffset - sizeof(ULONG);
    if (scanLimit < sizeof(ULONGLONG)) {
        return;
    }

    for (ULONG offset = 0; offset <= scanLimit; offset += kVtableAlign) {
        const void* entry = regionBytes(region, offset);

        if (*reinterpret_cast<const ULONGLONG*>(entry) != g_layout.vtableAddress) {
            continue;
        }

        const ULONG flags = readU32(entry, g_layout.flagsOffset);
        if (!hasProtectionBit6(flags)) {
            continue;
        }

        const ULONG kind = readU32(entry, g_layout.kindOffset);
        if (!matchesWindowKind(kind)) {
            continue;
        }

        WndInfo window{};
        window.hwnd = readU32(entry, g_layout.hwndOffset);
        window.pid = readU32(entry, g_layout.pidOffset);

        if (window.hwnd > 0 && isPlausibleProcessId(window.pid)) {
            windows.push_back(window);
        }
    }
}

void scanDwmProcessMemoryForHiddenWindows(ULONG dwmPid, std::vector<WndInfo>& windows)
{
    const ZwQueryVirtualMemoryFn queryVirtualMemoryFn = queryVirtualMemory();
    if (!queryVirtualMemoryFn) {
        return;
    }

    ScopedHandle processHandle(openDwmProcessWithFallback(
        dwmPid,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ));
    if (!processHandle) {
        return;
    }

    PVOID address = nullptr;
    MemoryBasicInformation64 regionInfo{};

    while (NT_SUCCESS(queryVirtualMemoryFn(
        processHandle.get(),
        address,
        MemoryInformationClass::BasicInformation,
        &regionInfo,
        sizeof(regionInfo),
        nullptr)))
    {
        if (shouldScanRegion(regionInfo)) {
            std::vector<UCHAR> buffer(static_cast<size_t>(regionInfo.RegionSize));
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(
                    processHandle.get(),
                    reinterpret_cast<LPCVOID>(regionInfo.BaseAddress),
                    buffer.data(),
                    buffer.size(),
                    &bytesRead)
                && bytesRead > 0)
            {
                collectHiddenWindowsFromRegion(buffer.data(), static_cast<ULONG>(bytesRead), windows);
            }
        }

        address = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(address) + regionInfo.RegionSize);
    }
}

#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

using SetWindowDisplayAffinityFn = BOOL(WINAPI*)(HWND, DWORD);
using GetWindowDisplayAffinityFn = BOOL(WINAPI*)(HWND, PDWORD);

SetWindowDisplayAffinityFn getSetWindowDisplayAffinityFn()
{
    static const SetWindowDisplayAffinityFn fn = []() -> SetWindowDisplayAffinityFn {
        const HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (!user32) {
            return nullptr;
        }

        return reinterpret_cast<SetWindowDisplayAffinityFn>(
            GetProcAddress(user32, "SetWindowDisplayAffinity"));
    }();
    return fn;
}

GetWindowDisplayAffinityFn getGetWindowDisplayAffinityFn()
{
    static const GetWindowDisplayAffinityFn fn = []() -> GetWindowDisplayAffinityFn {
        const HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (!user32) {
            return nullptr;
        }

        return reinterpret_cast<GetWindowDisplayAffinityFn>(
            GetProcAddress(user32, "GetWindowDisplayAffinity"));
    }();
    return fn;
}

void prepareWindowForDisplayAffinity(HWND hwnd)
{
    if (!IsWindow(hwnd)) {
        return;
    }

    const LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_LAYERED) != 0) {
        SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);
    }
}

BOOL trySetDisplayAffinity(HWND hwnd, DWORD affinity)
{
    const SetWindowDisplayAffinityFn setWindowDisplayAffinity = getSetWindowDisplayAffinityFn();
    if (!setWindowDisplayAffinity) {
        return FALSE;
    }

    prepareWindowForDisplayAffinity(hwnd);
    if (setWindowDisplayAffinity(hwnd, affinity)) {
        return TRUE;
    }

    if (affinity != WDA_EXCLUDEFROMCAPTURE) {
        return FALSE;
    }

    setWindowDisplayAffinity(hwnd, WDA_MONITOR);
    if (setWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
        return TRUE;
    }

    Sleep(0);
    prepareWindowForDisplayAffinity(hwnd);
    return setWindowDisplayAffinity(hwnd, affinity);
}

BOOL queryDisplayAffinity(HWND hwnd, DWORD& affinityOut)
{
    affinityOut = WDA_NONE;

    const GetWindowDisplayAffinityFn getWindowDisplayAffinity = getGetWindowDisplayAffinityFn();
    if (!getWindowDisplayAffinity) {
        return FALSE;
    }

    return getWindowDisplayAffinity(hwnd, &affinityOut) == TRUE;
}

} // namespace

DWORD GetDwmProcessId()
{
    HWND dwmWindow = FindWindowW(L"Dwm", L"DWM Notification Window");
    if (!dwmWindow) {
        return 0;
    }

    DWORD dwmPid = 0;
    GetWindowThreadProcessId(dwmWindow, &dwmPid);
    return dwmPid;
}

BOOL SetWindowAntiCapture(HWND hwnd, BOOL enable)
{
    if (!hwnd || !IsWindow(hwnd)) {
        return FALSE;
    }

    const DWORD targetAffinity = enable ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE;

    DWORD currentAffinity = WDA_NONE;
    if (queryDisplayAffinity(hwnd, currentAffinity) && currentAffinity == targetAffinity) {
        return TRUE;
    }

    return trySetDisplayAffinity(hwnd, targetAffinity);
}

HiddenWindowOffsetState GetHiddenWindowOffsetState()
{
    return g_offsetState;
}

HiddenWindowOffsetInitResult InitHiddenWindowOffsets(
    HWND mainWindow,
    SymbolManager* symbolManager,
    const HiddenWindowLogFn& logFn,
    const HiddenWindowAffinityFn& affinityFn)
{
    const auto applyAntiCapture = [&](HWND hwnd, BOOL enable) -> bool {
        if (affinityFn) {
            return affinityFn(hwnd, enable);
        }
        return SetWindowAntiCapture(hwnd, enable);
    };

    HiddenWindowOffsetInitResult result;
    result.state = g_offsetState;
    result.flagsOffset = g_layout.flagsOffset;
    result.kindOffset = g_layout.kindOffset;
    result.hwndOffset = g_layout.hwndOffset;
    result.pidOffset = g_layout.pidOffset;
    result.vtableAddress = g_layout.vtableAddress;
    result.sampleObjectAddress = g_layout.sampleObjectAddress;
    result.ranCalibration = FALSE;

    if (g_offsetState == HiddenWindowOffsetState::Ready) {
        logLine(logFn, L"[hidden_windows] Already initialized; skipping calibration.");
        return result;
    }

    if (g_offsetState == HiddenWindowOffsetState::Failed) {
        logLine(logFn, L"[hidden_windows] Previous initialization failed; retrying calibration.");
        g_offsetState = HiddenWindowOffsetState::NotInitialized;
        g_layout = {};
    }

    if (!mainWindow || !IsWindow(mainWindow)) {
        result.state = HiddenWindowOffsetState::Failed;
        result.message = L"Main window handle is not available.";
        g_offsetState = result.state;
        logLine(logFn, L"[hidden_windows] Error: main window handle is not available.");
        return result;
    }

    const ULONG calibrateHwnd = HandleToUlong(mainWindow);
    const ULONG calibratePid = GetCurrentProcessId();
    result.ranCalibration = TRUE;

    logLine(logFn, L"[hidden_windows] Initialization started.");
    logf(logFn, L"[hidden_windows] Calibration hwnd=0x", std::hex, calibrateHwnd, std::dec, L" pid=", calibratePid);

    const DWORD dwmPid = GetDwmProcessId();
    if (!dwmPid) {
        result.state = HiddenWindowOffsetState::Failed;
        result.message = L"dwm.exe was not found.";
        g_offsetState = result.state;
        logLine(logFn, L"[hidden_windows] Error: dwm.exe was not found.");
        return result;
    }

    logf(logFn, L"[hidden_windows] dwm.exe pid=", dwmPid);

    std::wstring moduleKey;
    DWORD64 moduleBase = 0;
    std::wstring symbolError;
    if (!loadDwmredirSymbols(dwmPid, symbolManager, logFn, moduleKey, moduleBase, symbolError)) {
        result.state = HiddenWindowOffsetState::Failed;
        result.message = symbolError;
        g_offsetState = result.state;
        logf(logFn, L"[hidden_windows] Error: ", symbolError);
        return result;
    }

    std::wstring vtableSymbolName;
    ULONGLONG vtableAddress = 0;
    if (!resolveCWindowContextVtable(symbolManager, moduleBase, logFn, vtableAddress, vtableSymbolName, symbolError)) {
        result.state = HiddenWindowOffsetState::Failed;
        result.message = symbolError;
        g_offsetState = result.state;
        logf(logFn, L"[hidden_windows] Error: ", symbolError);
        return result;
    }

    logLine(logFn, L"[hidden_windows] Enabling anti-capture on main window for calibration...");
    if (!applyAntiCapture(mainWindow, TRUE)) {
        result.state = HiddenWindowOffsetState::Failed;
        result.message = L"SetWindowDisplayAffinity failed during calibration.";
        g_offsetState = result.state;
        logLine(logFn, L"[hidden_windows] Error: SetWindowDisplayAffinity failed during calibration.");
        return result;
    }

    Sleep(200);

    HiddenWindowObjectLayout calibratedLayout;
    const bool calibrated = calibrateHiddenWindowLayout(
        dwmPid,
        vtableAddress,
        mainWindow,
        calibratePid,
        calibratedLayout,
        logFn,
        symbolError);

    logLine(logFn, L"[hidden_windows] Restoring main window capture visibility...");
    applyAntiCapture(mainWindow, FALSE);

    if (!calibrated) {
        result.state = HiddenWindowOffsetState::Failed;
        result.message = symbolError;
        g_offsetState = result.state;
        logf(logFn, L"[hidden_windows] Error: ", symbolError);
        return result;
    }

    g_layout = calibratedLayout;
    g_offsetState = HiddenWindowOffsetState::Ready;

    result.state = g_offsetState;
    result.flagsOffset = g_layout.flagsOffset;
    result.kindOffset = g_layout.kindOffset;
    result.hwndOffset = g_layout.hwndOffset;
    result.pidOffset = g_layout.pidOffset;
    result.vtableAddress = g_layout.vtableAddress;
    result.sampleObjectAddress = g_layout.sampleObjectAddress;
    result.message = L"Initialization succeeded.";

    logLine(logFn, L"[hidden_windows] Recorded object-relative offsets:");
    logf(logFn, L"[hidden_windows]   +0x", std::hex, g_layout.flagsOffset, std::dec, L"  protection flags (bit6)");
    logf(logFn, L"[hidden_windows]   +0x", std::hex, g_layout.kindOffset, std::dec, L"  window kind (0x2 / 0x4)");
    logf(logFn, L"[hidden_windows]   +0x", std::hex, g_layout.hwndOffset, std::dec, L"  hwnd");
    logf(logFn, L"[hidden_windows]   +0x", std::hex, g_layout.pidOffset, std::dec, L"  pid");
    logLine(logFn, L"[hidden_windows] Initialization succeeded.");
    return result;
}

VOID DetectHiddenWindows(std::vector<WndInfo>& windows, HWND mainWindow)
{
    windows.clear();
    UNREFERENCED_PARAMETER(mainWindow);

    if (g_offsetState != HiddenWindowOffsetState::Ready || !layoutReady()) {
        return;
    }

    const ULONG dwmPid = GetDwmProcessId();
    if (!dwmPid) {
        return;
    }

    scanDwmProcessMemoryForHiddenWindows(dwmPid, windows);
}
