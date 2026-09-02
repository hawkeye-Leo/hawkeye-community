#include "etw.h"
#include "process.h"
#include "Driver.h"
#include "PathConvert.h"
#include "symmanager.h"
#include "common.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>

namespace {

static const WCHAR kEtwSessionName[] = L"HawkeyeEtwSession";

static const GUID kEtwSessionGuid =
{ 0x4f2c8a11, 0x6b7d, 0x4e93, { 0x9a, 0x12, 0x3c, 0x45, 0x67, 0x89, 0xab, 0xcd } };

static const GUID kPerfInfoGuid =
{ 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };

static const GUID kStackWalkGuid =
{ 0xdef2fe46, 0x7bd6, 0x4b80, { 0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3 } };

static const UCHAR kProfileEventType = 46;
static const UCHAR kStackWalkOpcode = 32;
static const UINT64 kKernelAddressThreshold = 0xFFFF000000000000ULL;

struct EtwRawProfileRecord64
{
    UINT64 instructionPointer;
    DWORD threadId;
};

typedef struct _TraceThreadParam
{
    TRACEHANDLE* loggerHandle;
    ULONG* status;
} TraceThreadParam;

BOOL enableProfilePrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(nullptr, SE_SYSTEM_PROFILE_NAME, &privileges.Privileges[0].Luid)) {
        CloseHandle(token);
        return FALSE;
    }

    const BOOL ok = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    CloseHandle(token);
    return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

template<typename T>
BOOL getEventProperty(PEVENT_RECORD eventRecord, LPCWSTR name, T& value)
{
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
    desc.ArrayIndex = ULONG_MAX;

    return TdhGetProperty(eventRecord, 0, nullptr, 1, &desc, sizeof(value),
                          reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS;
}

BOOL getEventThreadId(PEVENT_RECORD eventRecord, DWORD& threadId)
{
    threadId = 0;
    if (getEventProperty(eventRecord, L"ThreadId", threadId)) {
        return TRUE;
    }

    UINT64 threadId64 = 0;
    if (getEventProperty(eventRecord, L"ThreadId", threadId64)) {
        threadId = static_cast<DWORD>(threadId64);
        return TRUE;
    }

    const auto* rawData = reinterpret_cast<const EtwRawProfileRecord64*>(eventRecord->UserData);
    if (eventRecord->UserDataLength >= sizeof(EtwRawProfileRecord64) && rawData->threadId) {
        threadId = rawData->threadId;
        return TRUE;
    }

    threadId = eventRecord->EventHeader.ThreadId;
    return threadId != 0;
}

BOOL isPlausibleRip(UINT64 rip)
{
    if (rip == 0) {
        return FALSE;
    }

    if (rip <= ETW_MAX_USER_ADDRESS) {
        return TRUE;
    }

    if (rip >= kKernelAddressThreshold) {
        return TRUE;
    }

    return FALSE;
}

BOOL getEventInstructionPointer(PEVENT_RECORD eventRecord, UINT64& instructionPointer)
{
    instructionPointer = 0;

    if (eventRecord->UserDataLength >= sizeof(EtwRawProfileRecord64)) {
        const auto* rawData = reinterpret_cast<const EtwRawProfileRecord64*>(eventRecord->UserData);
        if (rawData->instructionPointer != 0 && isPlausibleRip(rawData->instructionPointer)) {
            instructionPointer = rawData->instructionPointer;
            return TRUE;
        }
    }

    if (getEventProperty(eventRecord, L"InstructionPointer", instructionPointer)
        && isPlausibleRip(instructionPointer)) {
        return TRUE;
    }

    instructionPointer = 0;
    if (getEventProperty(eventRecord, L"InstructionPointer64", instructionPointer)
        && isPlausibleRip(instructionPointer)) {
        return TRUE;
    }

    return FALSE;
}

BOOL getEventStackFrames(PEVENT_RECORD eventRecord, std::vector<UINT64>& stackFrames)
{
    stackFrames.clear();

    for (USHORT i = 0; i < eventRecord->ExtendedDataCount; ++i) {
        const EVENT_HEADER_EXTENDED_DATA_ITEM& extData = eventRecord->ExtendedData[i];
        if (extData.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            if (extData.DataSize <= FIELD_OFFSET(EVENT_EXTENDED_ITEM_STACK_TRACE64, Address) || !extData.DataPtr) {
                continue;
            }

            const auto* stackTrace = reinterpret_cast<PEVENT_EXTENDED_ITEM_STACK_TRACE64>(extData.DataPtr);
            const USHORT frameCount = static_cast<USHORT>(
                (extData.DataSize - FIELD_OFFSET(EVENT_EXTENDED_ITEM_STACK_TRACE64, Address)) / sizeof(UINT64));
            for (USHORT j = 0; j < frameCount; ++j) {
                if (stackTrace->Address[j] != 0) {
                    stackFrames.push_back(stackTrace->Address[j]);
                }
            }
        } else if (extData.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
            if (extData.DataSize <= FIELD_OFFSET(EVENT_EXTENDED_ITEM_STACK_TRACE32, Address) || !extData.DataPtr) {
                continue;
            }

            const auto* stackTrace = reinterpret_cast<PEVENT_EXTENDED_ITEM_STACK_TRACE32>(extData.DataPtr);
            const USHORT frameCount = static_cast<USHORT>(
                (extData.DataSize - FIELD_OFFSET(EVENT_EXTENDED_ITEM_STACK_TRACE32, Address)) / sizeof(ULONG));
            for (USHORT j = 0; j < frameCount; ++j) {
                if (stackTrace->Address[j] != 0) {
                    stackFrames.push_back(stackTrace->Address[j]);
                }
            }
        }
    }

    return !stackFrames.empty();
}

BOOL isProfileEvent(PEVENT_RECORD eventRecord)
{
    if (!IsEqualGUID(eventRecord->EventHeader.ProviderId, kPerfInfoGuid)) {
        return FALSE;
    }

    const EVENT_DESCRIPTOR& desc = eventRecord->EventHeader.EventDescriptor;
    return desc.Opcode == kProfileEventType || desc.Id == kProfileEventType;
}

BOOL isStackWalkEvent(PEVENT_RECORD eventRecord)
{
    if (!IsEqualGUID(eventRecord->EventHeader.ProviderId, kStackWalkGuid)) {
        return FALSE;
    }

    const EVENT_DESCRIPTOR& desc = eventRecord->EventHeader.EventDescriptor;
    return desc.Opcode == kStackWalkOpcode || desc.Id == kStackWalkOpcode;
}

BOOL parseStackWalkEvent(PEVENT_RECORD eventRecord,
                         DWORD& outPid,
                         DWORD& outTid,
                         std::vector<UINT64>& frames)
{
    frames.clear();
    outPid = 0;
    outTid = 0;

    if (!getEventProperty(eventRecord, L"StackThread", outTid)) {
        UINT64 stackThread64 = 0;
        if (getEventProperty(eventRecord, L"StackThread", stackThread64)) {
            outTid = static_cast<DWORD>(stackThread64);
        }
    }

    if (!getEventProperty(eventRecord, L"StackProcess", outPid)) {
        UINT64 stackProcess64 = 0;
        if (getEventProperty(eventRecord, L"StackProcess", stackProcess64)) {
            outPid = static_cast<DWORD>(stackProcess64);
        }
    }

    if (outTid == 0) {
        outTid = eventRecord->EventHeader.ThreadId;
    }
    if (outPid == 0) {
        outPid = eventRecord->EventHeader.ProcessId;
    }

    for (int stackIndex = 1; stackIndex <= 192; ++stackIndex) {
        wchar_t propName[16] = {};
        swprintf_s(propName, 16, L"Stack%d", stackIndex);

        UINT64 address = 0;
        if (!getEventProperty(eventRecord, propName, address)) {
            if (stackIndex == 1 && eventRecord->UserData && eventRecord->UserDataLength > 16) {
                break;
            }
            break;
        }

        if (address == 0 || !isPlausibleRip(address)) {
            break;
        }

        frames.push_back(address);
    }

    if (frames.empty() && eventRecord->UserData && eventRecord->UserDataLength > 16) {
        const auto* data = static_cast<const BYTE*>(eventRecord->UserData);
        const size_t addrCount = (eventRecord->UserDataLength - 16) / sizeof(UINT64);
        const auto* addrs = reinterpret_cast<const UINT64*>(data + 16);
        for (size_t index = 0; index < addrCount; ++index) {
            if (addrs[index] == 0 || !isPlausibleRip(addrs[index])) {
                break;
            }
            frames.push_back(addrs[index]);
        }
    }

    if (frames.empty()) {
        getEventStackFrames(eventRecord, frames);
    }

    constexpr size_t kMaxStackFrames = 32;
    if (frames.size() > kMaxStackFrames) {
        frames.resize(kMaxStackFrames);
    }

    return !frames.empty();
}

DWORD getProcessIdFromThread(EtwSampleContext* sampleCtx, DWORD threadId)
{
    {
        std::lock_guard<std::mutex> lock(sampleCtx->counterMutex);
        const auto it = sampleCtx->threadPidCache.find(threadId);
        if (it != sampleCtx->threadPidCache.end()) {
            return it->second;
        }
    }

    DWORD pid = 0;
    const HANDLE threadHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
    if (threadHandle) {
        pid = GetProcessIdOfThread(threadHandle);
        CloseHandle(threadHandle);
    }

    std::lock_guard<std::mutex> lock(sampleCtx->counterMutex);
    if (pid != 0) {
        sampleCtx->threadPidCache[threadId] = pid;
    }
    return pid;
}

DWORD WINAPI traceProcessingThread(LPVOID param)
{
    const auto* threadParam = static_cast<TraceThreadParam*>(param);
    *threadParam->status = ProcessTrace(threadParam->loggerHandle, 1, nullptr, nullptr);
    delete threadParam;
    return 0;
}

std::wstring formatKernelRegionName(UINT64 va)
{
    KERNEL_VA_REGION in{};
    KERNEL_VA_REGION out{};
    in.va = va;
    GetKernelVaRegion(&in, &out);
    if (!out.va) {
        return L"[unknown region]";
    }

    switch (out.mRegion) {
    case 0:  return L"[unknown region]";
    case 1:  return L"[section region]";
    case 4:  return L"[pte pfn region]";
    case 5:  return L"[nonpaged region]";
    case 6:  return L"[pagedpool]";
    case 9:  return L"[system region]";
    case 12: return L"[image region]";
    case 14: return L"[stack region]";
    default: return L"[region(" + std::to_wstring(out.mRegion) + L")]";
    }
}

std::wstring formatProcessPathLabel(DWORD pid, std::map<DWORD, std::wstring>& cache)
{
    const auto cached = cache.find(pid);
    if (cached != cache.end()) {
        return cached->second;
    }

    std::wstring label;
    if (pid == 0) {
        label = L"  [System Idle Process]";
    } else {
        const std::wstring path = Process::getPath(pid);
        if (path.empty()) {
            label = L"  [process exited or access denied]";
        } else if (path == L"path unavailable") {
            label = L"  [path unavailable]";
        } else if (path == L"System") {
            label = L"  System";
        } else {
            label = L"  " + path;
        }
    }

    cache.emplace(pid, label);
    return label;
}

std::wstring formatHexOffset(DWORD64 value)
{
    std::wstringstream stream;
    stream << L"0x" << std::hex << value;
    return stream.str();
}

std::wstring extractFileName(const std::wstring& modulePath)
{
    const size_t slash = modulePath.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? modulePath : modulePath.substr(slash + 1);
}

bool isHeapMemoryPath(const std::wstring& modulePath)
{
    return _wcsicmp(modulePath.c_str(), L"HEAP MEMORY") == 0;
}

bool isEtwAutoLoadModulePath(const std::wstring& modulePath)
{
    static const wchar_t* kAutoLoadModules[] = {
        L"ntoskrnl.exe",
        L"user32.dll",
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"dxgi.dll",
        L"win32k.sys",
        L"win32kbase.sys",
        L"win32kfull.sys",
    };

    const std::wstring fileName = extractFileName(modulePath);
    for (const wchar_t* allowedName : kAutoLoadModules) {
        if (_wcsicmp(fileName.c_str(), allowedName) == 0) {
            return true;
        }
    }
    return false;
}

std::wstring formatRipAnnotation(DWORD pid,
                                 UINT64 rip,
                                 const EtwFormatOptions* formatOptions,
                                 std::set<std::wstring>& loadedModuleAttempts,
                                 std::set<std::wstring>& failedModuleKeys,
                                 std::map<DWORD, std::map<UINT64, std::wstring>>& cache)
{
    SymbolManager* symbolManager = (formatOptions && formatOptions->enableSymbols)
        ? formatOptions->symbolManager
        : nullptr;
    const bool isKernelRip = rip >= kKernelAddressThreshold;
    const DWORD moduleLookupPid = isKernelRip ? 4u : pid;

    auto& ripCache = cache[moduleLookupPid];
    const auto cached = ripCache.find(rip);
    if (cached != ripCache.end()) {
        return cached->second;
    }

    const auto tryResolveSymbol = [&](std::wstring& outAnnotation) -> bool {
        if (!symbolManager) {
            return false;
        }

        std::wstring symbolName;
        DWORD64 displacement = 0;
        std::wstring moduleName;
        DWORD64 moduleBase = 0;
        if (!symbolManager->ResolveAddress(rip, symbolName, displacement, moduleName, moduleBase)) {
            return false;
        }

        outAnnotation = L"  ";
        if (!moduleName.empty()) {
            outAnnotation += moduleName + L"!";
        }
        outAnnotation += symbolName + L"+" + formatHexOffset(displacement);
        return true;
    };

    std::wstring annotation;
    if (tryResolveSymbol(annotation)) {
        ripCache.emplace(rip, annotation);
        return annotation;
    }

    GET_MODULE_PATH inout{};
    inout.pid = moduleLookupPid;
    inout.va = rip;
    GetModulePathByPid(&inout);

    if (inout.path[0] && _wcsicmp(inout.path, L"HEAP MEMORY") == 0) {
        annotation = L"  HEAP MEMORY";
        ripCache.emplace(rip, annotation);
        return annotation;
    }

    std::wstring modulePath;
    if (inout.path[0]) {
        modulePath = convertSystemRootPathW(inout.path);
    }

    if (isHeapMemoryPath(modulePath)) {
        annotation = L"  HEAP MEMORY";
        ripCache.emplace(rip, annotation);
        return annotation;
    }

    if (symbolManager && !modulePath.empty() && isEtwAutoLoadModulePath(modulePath)) {
        const std::wstring moduleKey = SymbolManager::NormalizeFilePathKey(modulePath);
        const bool loadFailedPreviously = failedModuleKeys.find(moduleKey) != failedModuleKeys.end();
        const bool loadAttemptedPreviously = loadedModuleAttempts.find(moduleKey) != loadedModuleAttempts.end();

        if (!loadFailedPreviously && !loadAttemptedPreviously) {
            loadedModuleAttempts.insert(moduleKey);

            SymbolLoadOptions loadOptions;
            loadOptions.maxLoadAttempts = 1;
            if (formatOptions && formatOptions->logFn) {
                loadOptions.logFn = formatOptions->logFn;
            }

            std::wstring loadError;
            const DWORD loadPid = isKernelRip ? 0u : pid;
            if (!symbolManager->LoadSymbol(modulePath, loadError, loadPid, &loadOptions)) {
                failedModuleKeys.insert(moduleKey);
                if (formatOptions && formatOptions->logFn) {
                    formatOptions->logFn(L"[sym] Fallback to module path for: " + modulePath);
                }
            }
        }

        if (tryResolveSymbol(annotation)) {
            ripCache.emplace(rip, annotation);
            return annotation;
        }
    } else if (symbolManager && !modulePath.empty()) {
        if (tryResolveSymbol(annotation)) {
            ripCache.emplace(rip, annotation);
            return annotation;
        }
    }

    const auto tryFormatModuleOffset = [&](std::wstring& outAnnotation) -> bool {
        if (!symbolManager) {
            return false;
        }

        DWORD64 moduleBase = 0;
        std::wstring moduleName;
        if (!symbolManager->GetModuleAtAddress(rip, moduleBase, moduleName)
            && !modulePath.empty()) {
            symbolManager->GetLoadedModuleBase(modulePath, moduleBase);
        }

        if (moduleBase == 0) {
            return false;
        }

        if (moduleName.empty()) {
            moduleName = extractFileName(modulePath);
            const size_t dot = moduleName.find_last_of(L'.');
            if (dot != std::wstring::npos) {
                moduleName = moduleName.substr(0, dot);
            }
        }

        const DWORD64 rva = rip - moduleBase;
        outAnnotation = L"  " + moduleName + L"+" + formatHexOffset(rva);
        return true;
    };

    if (tryFormatModuleOffset(annotation)) {
        ripCache.emplace(rip, annotation);
        return annotation;
    }

    if (isKernelRip) {
        annotation += L"  " + formatKernelRegionName(rip);
    }

    if (!modulePath.empty()) {
        annotation += L"  " + modulePath;
    } else {
        annotation += isKernelRip
            ? L"  [kernel module path unavailable]"
            : L"  [module path unavailable]";
    }

    ripCache.emplace(rip, annotation);
    return annotation;
}

std::wstring formatAddressAnnotation(DWORD pid,
                                     UINT64 address,
                                     const EtwFormatOptions* formatOptions,
                                     std::set<std::wstring>& loadedModuleAttempts,
                                     std::set<std::wstring>& failedModuleKeys,
                                     std::map<DWORD, std::map<UINT64, std::wstring>>& cache)
{
    std::wstring annotation = formatRipAnnotation(pid,
                                                  address,
                                                  formatOptions,
                                                  loadedModuleAttempts,
                                                  failedModuleKeys,
                                                  cache);
    if (!annotation.empty() && annotation.size() >= 2 && annotation[0] == L' ' && annotation[1] == L' ') {
        annotation.erase(0, 2);
    }
    return annotation;
}

} // namespace

std::wstring EtwError::toString() const
{
    if (!hasError()) {
        return L"Success";
    }

    std::wstringstream ss;
    ss << L"Error " << std::hex << m_errorCode;
    if (!m_message.empty()) {
        ss << L": " << m_message;
    }
    return ss.str();
}

EtwSampler::EtwSampler()
    : m_sessionContext(nullptr)
{
}

EtwSampler::~EtwSampler()
{
    if (m_sessionContext != nullptr) {
        Cleanup();
    }
}

PEVENT_TRACE_PROPERTIES EtwSampler::GetSessionProperties(EtwSessionContext* context, BOOL recordStack)
{
    if (!context) {
        return nullptr;
    }

    const DWORD sessionNameSize = static_cast<DWORD>((context->sessionName.length() + 1) * sizeof(WCHAR));
    const DWORD bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameSize;

    context->propertyBuffer.assign(bufferSize, 0);

    auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(context->propertyBuffer.data());
    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Guid = kEtwSessionGuid;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_PROFILE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    if (recordStack) {
        props->BufferSize = 256;
        props->MinimumBuffers = 8;
        props->MaximumBuffers = 32;
        props->FlushTimer = 1;
    }

    auto* loggerName = reinterpret_cast<WCHAR*>(context->propertyBuffer.data() + props->LoggerNameOffset);
    wcscpy_s(loggerName, context->sessionName.length() + 1, context->sessionName.c_str());

    return props;
}

PEVENT_TRACE_PROPERTIES EtwSampler::GetControlProperties(EtwSessionContext* context)
{
    if (!context) {
        return nullptr;
    }

    const DWORD sessionNameLength = static_cast<DWORD>(std::max<size_t>(context->sessionName.length() + 1, 1024));
    const DWORD sessionNameSize = sessionNameLength * sizeof(WCHAR);
    const DWORD logFileNameSize = 1024 * sizeof(WCHAR);
    const DWORD bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameSize + logFileNameSize;

    context->controlBuffer.assign(bufferSize, 0);

    auto* props = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(context->controlBuffer.data());
    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Guid = kEtwSessionGuid;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameSize;

    auto* loggerName = reinterpret_cast<WCHAR*>(context->controlBuffer.data() + props->LoggerNameOffset);
    wcscpy_s(loggerName, sessionNameLength, context->sessionName.c_str());

    return props;
}

ULONG EtwSampler::StopSession(EtwSessionContext* context, TRACEHANDLE sessionHandle)
{
    if (!context) {
        return ERROR_INVALID_PARAMETER;
    }

    PEVENT_TRACE_PROPERTIES props = GetControlProperties(context);
    if (!props) {
        return ERROR_OUTOFMEMORY;
    }

    return ControlTraceW(sessionHandle,
                          const_cast<LPWSTR>(context->sessionName.c_str()),
                          props,
                          EVENT_TRACE_CONTROL_STOP);
}

BOOL EtwSampler::IsAddressInMode(UINT64 address, EtwSampleMode sampleMode)
{
    switch (sampleMode) {
    case etwSampleModeUser:
        return address <= ETW_MAX_USER_ADDRESS;
    case etwSampleModeKernel:
        return address > ETW_MAX_USER_ADDRESS;
    case etwSampleModeAll:
    default:
        return TRUE;
    }
}

VOID WINAPI EtwSampler::OnEventRecord(PEVENT_RECORD eventRecord)
{
    if (!eventRecord || !eventRecord->UserContext) {
        return;
    }

    auto* sampleCtx = static_cast<EtwSampleContext*>(eventRecord->UserContext);

    if (sampleCtx->recordStack) {
        DWORD eventPid = 0;
        DWORD eventTid = 0;
        std::vector<UINT64> frames;

        if (isStackWalkEvent(eventRecord)) {
            if (!parseStackWalkEvent(eventRecord, eventPid, eventTid, frames)) {
                return;
            }
        } else if (isProfileEvent(eventRecord)) {
            UINT64 instructionPointer = 0;
            const BOOL hasInstructionPointer = getEventInstructionPointer(eventRecord, instructionPointer);

            if (!getEventThreadId(eventRecord, eventTid)) {
                return;
            }

            eventPid = getProcessIdFromThread(sampleCtx, eventTid);
            if (eventPid == 0) {
                eventPid = eventRecord->EventHeader.ProcessId;
            }

            getEventStackFrames(eventRecord, frames);
            if (frames.empty() && hasInstructionPointer && isPlausibleRip(instructionPointer)) {
                frames.push_back(instructionPointer);
            }
        } else {
            return;
        }

        if (eventPid == static_cast<DWORD>(-1) || frames.empty()) {
            return;
        }

        if (sampleCtx->targetPid != 0 && sampleCtx->targetPid != eventPid) {
            return;
        }
        if (sampleCtx->targetTid != 0 && sampleCtx->targetTid != eventTid) {
            return;
        }

        auto acceptedEnd = frames.begin();
        for (const UINT64 address : frames) {
            if (IsAddressInMode(address, sampleCtx->sampleMode)) {
                *acceptedEnd++ = address;
            }
        }
        frames.erase(acceptedEnd, frames.end());
        if (frames.empty()) {
            return;
        }

        constexpr size_t kMaxStackFrames = 32;
        if (frames.size() > kMaxStackFrames) {
            frames.resize(kMaxStackFrames);
        }

        std::lock_guard<std::mutex> lock(sampleCtx->counterMutex);
        sampleCtx->observedPid = eventPid;
        ++sampleCtx->stackSampleTotal;
        ++sampleCtx->stackAggregates[frames];
        return;
    }

    if (!isProfileEvent(eventRecord)) {
        return;
    }

    UINT64 rip = 0;
    if (!getEventInstructionPointer(eventRecord, rip) || !isPlausibleRip(rip)
        || !IsAddressInMode(rip, sampleCtx->sampleMode)) {
        return;
    }

    DWORD threadId = 0;
    if (!getEventThreadId(eventRecord, threadId)) {
        return;
    }

    DWORD pid = getProcessIdFromThread(sampleCtx, threadId);
    if (!pid) {
        pid = eventRecord->EventHeader.ProcessId;
    }
    if (pid == static_cast<DWORD>(-1)) {
        return;
    }

    if (sampleCtx->targetPid != 0 && sampleCtx->targetPid != pid) {
        return;
    }
    if (sampleCtx->targetTid != 0 && sampleCtx->targetTid != threadId) {
        return;
    }

    std::lock_guard<std::mutex> lock(sampleCtx->counterMutex);
    sampleCtx->samples[pid][threadId][rip]++;
}

EtwError EtwSampler::Initialize(DWORD profileInterval, BOOL recordStack)
{
    if (!profileInterval) {
        return EtwError(ERROR_INVALID_PARAMETER, L"Profile interval must be greater than zero");
    }

    if (m_sessionContext && m_sessionContext->initialized) {
        return EtwError();
    }

    if (m_sessionContext != nullptr) {
        Cleanup();
    }

    m_recordStack = recordStack;
    m_sessionContext = new EtwSessionContext();
    m_sessionContext->sessionName = kEtwSessionName;

    enableProfilePrivilege();

    ULONG retSize = 0;
    m_sessionContext->originalInterval.Source = 0;
    if (TraceQueryInformation(0,
                              TraceSampledProfileIntervalInfo,
                              &m_sessionContext->originalInterval,
                              sizeof(m_sessionContext->originalInterval),
                              &retSize) == ERROR_SUCCESS) {
        m_sessionContext->hasOriginalInterval = TRUE;
    }

    TRACE_PROFILE_INTERVAL interval{};
    interval.Source = 0;
    interval.Interval = profileInterval * 10;
    ULONG status = TraceSetInformation(0,
                                       TraceSampledProfileIntervalInfo,
                                       &interval,
                                       sizeof(interval));
    if (status != ERROR_SUCCESS) {
        if (m_sessionContext->hasOriginalInterval) {
            TraceSetInformation(0,
                                TraceSampledProfileIntervalInfo,
                                &m_sessionContext->originalInterval,
                                sizeof(m_sessionContext->originalInterval));
            m_sessionContext->hasOriginalInterval = FALSE;
        }
        delete m_sessionContext;
        m_sessionContext = nullptr;
        return EtwError(status, L"Failed to set sampled profile interval");
    }

    PEVENT_TRACE_PROPERTIES props = GetSessionProperties(m_sessionContext, m_recordStack);
    if (!props) {
        delete m_sessionContext;
        m_sessionContext = nullptr;
        return EtwError(ERROR_OUTOFMEMORY, L"Failed to allocate properties buffer");
    }

    status = StartTraceW(&m_sessionContext->sessionHandle,
                          const_cast<LPWSTR>(m_sessionContext->sessionName.c_str()),
                          props);

    if (status == ERROR_ALREADY_EXISTS) {
        const ULONG stopStatus = StopSession(m_sessionContext, 0);
        if (stopStatus != ERROR_SUCCESS && stopStatus != ERROR_WMI_INSTANCE_NOT_FOUND) {
            delete m_sessionContext;
            m_sessionContext = nullptr;
            return EtwError(stopStatus, L"Failed to stop existing ETW session");
        }

        props = GetSessionProperties(m_sessionContext, m_recordStack);
        if (!props) {
            delete m_sessionContext;
            m_sessionContext = nullptr;
            return EtwError(ERROR_OUTOFMEMORY, L"Failed to reallocate properties buffer");
        }

        status = StartTraceW(&m_sessionContext->sessionHandle,
                              const_cast<LPWSTR>(m_sessionContext->sessionName.c_str()),
                              props);
    }

    if (status != ERROR_SUCCESS) {
        if (m_sessionContext->hasOriginalInterval) {
            TraceSetInformation(0,
                                TraceSampledProfileIntervalInfo,
                                &m_sessionContext->originalInterval,
                                sizeof(m_sessionContext->originalInterval));
            m_sessionContext->hasOriginalInterval = FALSE;
        }
        delete m_sessionContext;
        m_sessionContext = nullptr;
        return EtwError(status, L"Failed to start ETW session");
    }

    if (recordStack) {
        CLASSIC_EVENT_ID stackEvent{};
        stackEvent.EventGuid = kPerfInfoGuid;
        stackEvent.Type = kProfileEventType;
        status = TraceSetInformation(m_sessionContext->sessionHandle,
                                     TraceStackTracingInfo,
                                     &stackEvent,
                                     sizeof(stackEvent));
        if (status != ERROR_SUCCESS) {
            Cleanup();
            return EtwError(status, L"Failed to enable stack tracing");
        }
    }

    m_sessionContext->initialized = TRUE;
    return EtwError();
}

EtwError EtwSampler::Cleanup()
{
    if (!m_sessionContext) {
        return EtwError();
    }

    EtwError result;

    if (m_sessionContext->loggerHandle != 0
        && m_sessionContext->loggerHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_sessionContext->loggerHandle);
        m_sessionContext->loggerHandle = 0;
    }

    if (m_sessionContext->sessionHandle != 0) {
        const ULONG status = StopSession(m_sessionContext, m_sessionContext->sessionHandle);
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            result = EtwError(status, L"Failed to stop ETW session");
        }
        m_sessionContext->sessionHandle = 0;
    }

    if (m_sessionContext->hasOriginalInterval) {
        TraceSetInformation(0,
                            TraceSampledProfileIntervalInfo,
                            &m_sessionContext->originalInterval,
                            sizeof(m_sessionContext->originalInterval));
        m_sessionContext->hasOriginalInterval = FALSE;
    }

    m_sessionContext->initialized = FALSE;
    delete m_sessionContext;
    m_sessionContext = nullptr;

    return result;
}

EtwError EtwSampler::CollectSamples(DWORD pid, DWORD tid, DWORD duration, EtwSampleMode sampleMode,
                                    EtwSampleContext& sampleCtx)
{
    if (!m_sessionContext || !m_sessionContext->initialized) {
        return EtwError(ERROR_INVALID_STATE, L"ETW session not initialized");
    }
    if (!duration || duration > 60000) {
        return EtwError(ERROR_INVALID_PARAMETER, L"Invalid sampling duration");
    }

    sampleCtx.samples.clear();
    sampleCtx.stackAggregates.clear();
    sampleCtx.threadPidCache.clear();
    sampleCtx.sessionCtx = m_sessionContext;
    sampleCtx.targetPid = pid;
    sampleCtx.targetTid = tid;
    sampleCtx.observedPid = 0;
    sampleCtx.sampleMode = sampleMode;
    sampleCtx.recordStack = m_recordStack;
    sampleCtx.stackSampleTotal = 0;
    sampleCtx.stackRipOnlySamples = 0;

    EVENT_TRACE_LOGFILE traceParams{};
    traceParams.LoggerName = const_cast<LPWSTR>(m_sessionContext->sessionName.c_str());
    traceParams.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceParams.EventRecordCallback = OnEventRecord;
    traceParams.Context = &sampleCtx;

    TRACEHANDLE loggerHandle = OpenTraceW(&traceParams);
    if (loggerHandle == INVALID_PROCESSTRACE_HANDLE) {
        return EtwError(GetLastError(), L"Failed to open ETW trace");
    }

    m_sessionContext->loggerHandle = loggerHandle;

    ULONG traceStatus = ERROR_SUCCESS;
    auto* threadParam = new TraceThreadParam();
    threadParam->loggerHandle = &loggerHandle;
    threadParam->status = &traceStatus;

    HANDLE traceThread = CreateThread(nullptr, 0, traceProcessingThread, threadParam, 0, nullptr);
    if (!traceThread) {
        delete threadParam;
        CloseTrace(loggerHandle);
        m_sessionContext->loggerHandle = 0;
        return EtwError(GetLastError(), L"Failed to create trace processing thread");
    }

    Sleep(duration);

    const ULONG closeStatus = CloseTrace(loggerHandle);
    m_sessionContext->loggerHandle = 0;

    if (WaitForSingleObject(traceThread, 5000) == WAIT_TIMEOUT) {
        StopSession(m_sessionContext, m_sessionContext->sessionHandle);
        WaitForSingleObject(traceThread, INFINITE);
        m_sessionContext->sessionHandle = 0;
    }
    CloseHandle(traceThread);

    if (closeStatus != ERROR_SUCCESS
        && closeStatus != ERROR_CTX_CLOSE_PENDING) {
        return EtwError(closeStatus, L"Failed to close ETW trace");
    }

    if (traceStatus != ERROR_SUCCESS
        && traceStatus != ERROR_CANCELLED
        && traceStatus != ERROR_CTX_CLOSE_PENDING) {
        return EtwError(traceStatus, L"ProcessTrace failed");
    }

    return EtwError();
}

EtwError EtwSampler::GetRipSamples(DWORD pid, DWORD tid, DWORD duration,
                                   EtwSampleMode sampleMode,
                                   EtwSampleResult& outResult)
{
    outResult = EtwSampleResult{};

    EtwSampleContext sampleCtx;
    const EtwError collectError = CollectSamples(pid, tid, duration, sampleMode, sampleCtx);
    if (collectError.hasError()) {
        return collectError;
    }

    std::vector<EtwProcessSamples> processes;
    processes.reserve(sampleCtx.samples.size());

    for (const auto& processEntry : sampleCtx.samples) {
        EtwProcessSamples processSamples;
        processSamples.pid = processEntry.first;

        for (const auto& threadEntry : processEntry.second) {
            EtwThreadSamples threadSamples;
            threadSamples.tid = threadEntry.first;

            for (const auto& ripEntry : threadEntry.second) {
                threadSamples.rips.emplace_back(ripEntry.first, ripEntry.second);
                threadSamples.totalCount += ripEntry.second;
                outResult.uniqueRips++;
            }

            std::sort(threadSamples.rips.begin(), threadSamples.rips.end(),
                      [](const EtwRipRecord& left, const EtwRipRecord& right) {
                          return left.second > right.second;
                      });

            processSamples.totalCount += threadSamples.totalCount;
            processSamples.threads.push_back(std::move(threadSamples));
        }

        std::sort(processSamples.threads.begin(), processSamples.threads.end(),
                  [](const EtwThreadSamples& left, const EtwThreadSamples& right) {
                      return left.totalCount > right.totalCount;
                  });

        outResult.totalSamples += processSamples.totalCount;
        processes.push_back(std::move(processSamples));
    }

    std::sort(processes.begin(), processes.end(),
              [](const EtwProcessSamples& left, const EtwProcessSamples& right) {
                  return left.totalCount > right.totalCount;
              });

    outResult.processes = std::move(processes);
    return EtwError();
}

EtwError EtwSampler::GetStackSamples(DWORD pid, DWORD tid, DWORD duration,
                                     EtwSampleMode sampleMode,
                                     EtwStackSampleResult& outResult)
{
    if (!m_recordStack) {
        return EtwError(ERROR_INVALID_PARAMETER, L"Stack tracing not enabled");
    }
    if (tid == 0) {
        return EtwError(ERROR_INVALID_PARAMETER, L"Stack sampling requires -tid");
    }

    outResult = EtwStackSampleResult{};
    outResult.tid = tid;

    EtwSampleContext sampleCtx;
    const EtwError collectError = CollectSamples(pid, tid, duration, sampleMode, sampleCtx);
    if (collectError.hasError()) {
        return collectError;
    }

    outResult.pid = sampleCtx.observedPid;
    outResult.totalSamples = sampleCtx.stackSampleTotal;
    outResult.ripOnlySamples = sampleCtx.stackRipOnlySamples;
    outResult.stacks.reserve(sampleCtx.stackAggregates.size());

    for (const auto& stackEntry : sampleCtx.stackAggregates) {
        EtwStackAggregate aggregate;
        aggregate.frames = stackEntry.first;
        aggregate.count = stackEntry.second;
        outResult.stacks.push_back(std::move(aggregate));
    }

    std::sort(outResult.stacks.begin(), outResult.stacks.end(),
              [](const EtwStackAggregate& left, const EtwStackAggregate& right) {
                  return left.count > right.count;
              });

    outResult.uniqueStacks = outResult.stacks.size();
    return EtwError();
}

void FormatEtwSampleResult(DWORD filterPid, const EtwSampleResult& result, DWORD minCounter,
                           std::vector<std::wstring>& outChunks,
                           const EtwFormatOptions* formatOptions)
{
    outChunks.clear();

    const bool symbolsEnabled = formatOptions && formatOptions->enableSymbols
        && formatOptions->symbolManager;

    {
        std::wstringstream header;
        header << L"ETW RIP Sample Results (PID: "
               << (filterPid == 0 ? L"ALL" : std::to_wstring(filterPid))
               << L")\n";
        header << L"========================================\n";
        header << L"Raw samples: " << result.totalSamples
               << L"  Raw RIPs: " << result.uniqueRips
               << L"  Min count: >" << minCounter << L"\n";
        if (symbolsEnabled) {
            header << L"Symbol resolve: enabled (auto-load whitelist: ntoskrnl/user32/ntdll/kernel32/kernelbase/dxgi/win32k/win32kbase/win32kfull)\n";
        } else {
            header << L"Symbol resolve: disabled (module path only)\n";
        }
        header << L"----------------------------------------";
        outChunks.push_back(header.str());
    }

    UINT64 displayedSamples = 0;
    size_t displayedProcesses = 0;
    size_t displayedThreads = 0;
    size_t displayedRips = 0;

    std::map<DWORD, std::wstring> processPathCache;
    std::map<DWORD, std::map<UINT64, std::wstring>> ripAnnotationCache;
    std::set<std::wstring> loadedModuleAttempts;
    std::set<std::wstring> failedModuleKeys;

    for (const EtwProcessSamples& process : result.processes) {
        EtwProcessSamples filteredProcess;
        filteredProcess.pid = process.pid;

        for (const EtwThreadSamples& thread : process.threads) {
            EtwThreadSamples filteredThread;
            filteredThread.tid = thread.tid;

            for (const EtwRipRecord& rip : thread.rips) {
                if (rip.second > minCounter) {
                    filteredThread.rips.push_back(rip);
                    filteredThread.totalCount += rip.second;
                }
            }

            if (filteredThread.rips.empty()) {
                continue;
            }

            filteredProcess.totalCount += filteredThread.totalCount;
            filteredProcess.threads.push_back(std::move(filteredThread));
        }

        if (filteredProcess.threads.empty()) {
            continue;
        }

        displayedProcesses++;
        displayedSamples += filteredProcess.totalCount;

        const std::wstring pidHeader =
            L"PID " + std::to_wstring(filteredProcess.pid)
            + formatProcessPathLabel(filteredProcess.pid, processPathCache)
            + L"  (" + std::to_wstring(filteredProcess.totalCount) + L" samples, "
            + std::to_wstring(filteredProcess.threads.size()) + L" threads)";

        bool pidHeaderPending = true;
        for (const EtwThreadSamples& thread : filteredProcess.threads) {
            displayedThreads++;
            displayedRips += thread.rips.size();

            std::wstringstream threadBlock;
            if (pidHeaderPending) {
                threadBlock << pidHeader << L"\n";
                pidHeaderPending = false;
            }

            threadBlock << L"  TID " << thread.tid
                        << L"  (" << thread.totalCount << L" samples, "
                        << thread.rips.size() << L" rips)\n";

            for (const EtwRipRecord& rip : thread.rips) {
                threadBlock << L"    0x" << std::hex << std::setw(16) << std::setfill(L'0') << rip.first
                            << L"  " << std::dec << std::setw(8) << std::setfill(L' ') << rip.second
                            << formatRipAnnotation(filteredProcess.pid, rip.first, formatOptions,
                                                   loadedModuleAttempts, failedModuleKeys, ripAnnotationCache)
                            << L"\n";
            }

            outChunks.push_back(threadBlock.str());
        }
    }

    {
        std::wstringstream footer;
        footer << L"----------------------------------------\n";
        footer << L"Displayed: " << displayedSamples << L" samples"
               << L"  " << displayedProcesses << L" processes"
               << L"  " << displayedThreads << L" threads"
               << L"  " << displayedRips << L" rips";

        if (displayedRips == 0) {
            footer << L"\n(no RIPs above min threshold)";
        }

        outChunks.push_back(footer.str());
    }
}

void FormatEtwStackSampleResult(const EtwStackSampleResult& result, DWORD minCounter, DWORD topN,
                                std::vector<std::wstring>& outChunks,
                                const EtwFormatOptions* formatOptions)
{
    outChunks.clear();

    if (topN == 0) {
        topN = 20;
    }

    const bool symbolsEnabled = formatOptions && formatOptions->enableSymbols
        && formatOptions->symbolManager;
    const DWORD symbolPid = result.pid != 0 ? result.pid : 4u;

    {
        std::wstringstream header;
        header << L"ETW Stack Sample Results (TID: " << result.tid << L")";
        if (result.pid != 0) {
            header << L"  PID: " << result.pid;
        }
        header << L"\n========================================\n";
        header << L"Total samples: " << result.totalSamples
               << L"  Unique stacks: " << result.uniqueStacks
               << L"  Min count: >" << minCounter
               << L"  Top: " << topN << L"\n";
        if (symbolsEnabled) {
            header << L"Symbol resolve: enabled\n";
        } else {
            header << L"Symbol resolve: disabled (raw addresses)\n";
        }
        header << L"----------------------------------------";
        outChunks.push_back(header.str());
    }

    std::map<DWORD, std::wstring> processPathCache;
    std::map<DWORD, std::map<UINT64, std::wstring>> ripAnnotationCache;
    std::set<std::wstring> loadedModuleAttempts;
    std::set<std::wstring> failedModuleKeys;

    if (result.pid != 0) {
        std::wstringstream pidLine;
        pidLine << L"Process:" << formatProcessPathLabel(result.pid, processPathCache);
        outChunks.push_back(pidLine.str());
    }

    size_t displayedStacks = 0;
    UINT64 displayedSamples = 0;
    size_t rank = 0;

    for (const EtwStackAggregate& stack : result.stacks) {
        if (stack.count <= minCounter) {
            continue;
        }
        if (displayedStacks >= topN) {
            break;
        }

        ++rank;
        ++displayedStacks;
        displayedSamples += stack.count;

        std::wstringstream block;
        block << L"\n[" << rank << L"] Count: " << stack.count;
        if (!stack.frames.empty()) {
            block << L"  Leaf: 0x" << std::hex << std::setw(16) << std::setfill(L'0')
                  << stack.frames.front() << std::dec;
        }
        block << L"\n";

        for (size_t frameIndex = 0; frameIndex < stack.frames.size(); ++frameIndex) {
            const UINT64 address = stack.frames[frameIndex];
            block << L"    #" << frameIndex << L"  0x"
                  << std::hex << std::setw(16) << std::setfill(L'0') << address << std::dec;

            if (symbolsEnabled) {
                block << L"  "
                      << formatAddressAnnotation(symbolPid,
                                                 address,
                                                 formatOptions,
                                                 loadedModuleAttempts,
                                                 failedModuleKeys,
                                                 ripAnnotationCache);
            }
            block << L"\n";
        }

        outChunks.push_back(block.str());
    }

    {
        std::wstringstream footer;
        footer << L"----------------------------------------\n";
        footer << L"Displayed: " << displayedSamples << L" samples in "
               << displayedStacks << L" stacks";
        if (displayedStacks == 0) {
            footer << L"\n(no stacks above min threshold)";
        } else if (displayedStacks < result.uniqueStacks) {
            footer << L"  (" << result.uniqueStacks << L" unique stacks total)";
        }
        outChunks.push_back(footer.str());
    }
}
