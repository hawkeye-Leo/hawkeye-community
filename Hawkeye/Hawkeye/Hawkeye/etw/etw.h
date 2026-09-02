#pragma once

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

#ifndef MAX_SESSION_NAME_LEN
#define MAX_SESSION_NAME_LEN 1024
#endif

#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000001
#endif

#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x00000010
#endif

#ifdef _WIN64
#define ETW_MAX_USER_ADDRESS 0x000007FFFFFFFFFFFULL
#else
#define ETW_MAX_USER_ADDRESS 0x7FFFFFFFUL
#endif

enum EtwSampleMode
{
    etwSampleModeAll,
    etwSampleModeUser,
    etwSampleModeKernel
};

using EtwRipRecord = std::pair<UINT64, UINT64>;

struct EtwThreadSamples
{
    DWORD tid = 0;
    UINT64 totalCount = 0;
    std::vector<EtwRipRecord> rips;
};

struct EtwProcessSamples
{
    DWORD pid = 0;
    UINT64 totalCount = 0;
    std::vector<EtwThreadSamples> threads;
};

struct EtwSampleResult
{
    UINT64 totalSamples = 0;
    UINT64 uniqueRips = 0;
    std::vector<EtwProcessSamples> processes;
};

using EtwStackFrames = std::vector<UINT64>;

struct EtwStackAggregate
{
    EtwStackFrames frames;
    UINT64 count = 0;
};

struct EtwStackSampleResult
{
    DWORD tid = 0;
    DWORD pid = 0;
    UINT64 totalSamples = 0;
    UINT64 uniqueStacks = 0;
    UINT64 ripOnlySamples = 0;
    std::vector<EtwStackAggregate> stacks;
};

class EtwError
{
public:
    EtwError() : m_errorCode(0) {}
    EtwError(DWORD code) : m_errorCode(code) {}
    EtwError(DWORD code, const std::wstring& message) : m_errorCode(code), m_message(message) {}

    DWORD code() const { return m_errorCode; }
    bool hasError() const { return m_errorCode != 0; }
    std::wstring toString() const;

private:
    DWORD m_errorCode;
    std::wstring m_message;
};

typedef struct _EtwSessionContext
{
    TRACEHANDLE sessionHandle = 0;
    TRACEHANDLE loggerHandle = 0;
    std::wstring sessionName;
    std::vector<BYTE> propertyBuffer;
    std::vector<BYTE> controlBuffer;
    TRACE_PROFILE_INTERVAL originalInterval{};
    BOOL hasOriginalInterval = FALSE;
    BOOL initialized = FALSE;
} EtwSessionContext;

typedef struct _EtwSampleContext
{
    EtwSessionContext* sessionCtx = nullptr;
    std::map<DWORD, std::map<DWORD, std::map<UINT64, UINT64>>> samples;
    std::map<std::vector<UINT64>, UINT64> stackAggregates;
    std::map<DWORD, DWORD> threadPidCache;
    std::mutex counterMutex;
    DWORD targetPid = 0;
    DWORD targetTid = 0;
    DWORD observedPid = 0;
    EtwSampleMode sampleMode = etwSampleModeAll;
    BOOL recordStack = FALSE;
    UINT64 stackSampleTotal = 0;
    UINT64 stackRipOnlySamples = 0;
} EtwSampleContext;

class EtwSampler
{
public:
    EtwSampler();
    ~EtwSampler();

    EtwError Initialize(DWORD profileInterval = 1, BOOL recordStack = FALSE);
    EtwError Cleanup();
    EtwError GetRipSamples(DWORD pid, DWORD tid, DWORD duration,
                           EtwSampleMode sampleMode,
                           EtwSampleResult& outResult);
    EtwError GetStackSamples(DWORD pid, DWORD tid, DWORD duration,
                             EtwSampleMode sampleMode,
                             EtwStackSampleResult& outResult);

private:
    EtwSessionContext* m_sessionContext;
    BOOL m_recordStack = FALSE;

    EtwError CollectSamples(DWORD pid, DWORD tid, DWORD duration, EtwSampleMode sampleMode,
                            EtwSampleContext& sampleCtx);

    static PEVENT_TRACE_PROPERTIES GetSessionProperties(EtwSessionContext* context, BOOL recordStack);
    static PEVENT_TRACE_PROPERTIES GetControlProperties(EtwSessionContext* context);
    static ULONG StopSession(EtwSessionContext* context, TRACEHANDLE sessionHandle);
    static VOID WINAPI OnEventRecord(PEVENT_RECORD eventRecord);
    static BOOL IsAddressInMode(UINT64 address, EtwSampleMode sampleMode);
};

class SymbolManager;

using EtwSymbolLogFn = std::function<void(const std::wstring& message)>;

struct EtwFormatOptions
{
    SymbolManager* symbolManager = nullptr;
    EtwSymbolLogFn logFn;
    bool enableSymbols = true;
};

void FormatEtwSampleResult(DWORD filterPid, const EtwSampleResult& result, DWORD minCounter,
                           std::vector<std::wstring>& outChunks,
                           const EtwFormatOptions* formatOptions = nullptr);

void FormatEtwStackSampleResult(const EtwStackSampleResult& result, DWORD minCounter, DWORD topN,
                                std::vector<std::wstring>& outChunks,
                                const EtwFormatOptions* formatOptions = nullptr);
