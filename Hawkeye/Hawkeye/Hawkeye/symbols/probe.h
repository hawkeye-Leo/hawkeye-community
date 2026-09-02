#pragma once

#include "process.h"
#include "symmanager.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct ProbeModuleRecord
{
    std::wstring path;
    std::wstring fileName;
    std::uint64_t base = 0;
    bool symbolsLoaded = false;
    std::wstring statusMessage;
    std::size_t symbolCount = 0;
};

enum class ProbeFindKind : std::uint8_t
{
    Function,
    Data,
    Type,
    All
};

ProbeFindKind ProbeParseFindKind(const std::wstring& kindText);

// Comma-separated -mod: tokens (lowercased, trimmed). Empty = no module filter.
std::vector<std::wstring> ProbeParseModuleFilter(const std::wstring& filterText);

struct ProbeEnsureModulesResult
{
    std::size_t attempted = 0;
    std::size_t loaded = 0;
    std::size_t failed = 0;
    std::size_t alreadyLoaded = 0;
};

struct ProbeSymbolHit
{
    std::wstring moduleName;
    std::wstring modulePath;
    std::uint64_t moduleBase = 0;
    std::uint64_t rva = 0;
    std::uint64_t va = 0;
    std::wstring decoratedName;
    std::wstring friendlyName;
    std::wstring displayName;
    ULONG symTag = 0;
    ULONG flags = 0;
    // 0 unknown, 1 executable, 2 not executable (live page attribute)
    std::uint8_t executeAttr = 0;
};

using ProbeLogFn = std::function<void(const std::wstring& line)>;
using ProbeCancelFn = std::function<bool()>;

std::wstring ProbeFormatBytes(std::uint64_t bytes);
std::uint64_t ProbeMeasureDirectoryBytes(const std::wstring& directoryPath);
std::wstring ProbeFormatModuleShortName(const std::wstring& moduleFileName);
std::wstring ProbePickSymbolLabel(const ProbeSymbolHit& hit);
std::wstring ProbeFormatHitLine(const ProbeSymbolHit& hit, bool showKind = true);
void ProbeAnnotateExecuteKind(std::vector<ProbeSymbolHit>& hits, std::uint32_t pid);
void ProbeFilterHitsByExecuteKind(std::vector<ProbeSymbolHit>& hits, ProbeFindKind kind);

class ProbeSession{
public:
    bool IsAttached() const { return m_targetPid != 0; }
    std::uint32_t TargetPid() const { return m_targetPid; }

    bool Attach(std::uint32_t pid,
                SymbolManager& symbols,
                const ProbeLogFn& log,
                const ProbeCancelFn& shouldCancel = ProbeCancelFn{});    void Detach(SymbolManager& symbols, const ProbeLogFn& log);
    void GetStatus(std::uint32_t& outPid,
                   std::size_t& outTotalSymbols,
                   std::size_t& outLoadedModules,
                   std::size_t& outFailedModules,
                   std::vector<ProbeModuleRecord>& outModules) const;
    std::vector<ProbeSymbolHit> Find(const std::wstring& keyword,
                                     const std::wstring& moduleFilter,
                                     ProbeFindKind kind = ProbeFindKind::All) const;
    std::vector<ProbeSymbolHit> Resolve(const std::wstring& symbolQuery,
                                        const std::wstring& moduleFilter) const;
    std::size_t IndexedSymbolCount() const { return m_index.size(); }

    // When -mod: is set on -find/-sym: download (if needed) and index matching unloaded modules.
    ProbeEnsureModulesResult EnsureModulesForFilter(SymbolManager& symbols,
                                                    const std::wstring& moduleFilter,
                                                    const ProbeLogFn& log = ProbeLogFn{},
                                                    const ProbeCancelFn& shouldCancel = ProbeCancelFn{});

private:
    bool LoadAndIndexModule(ProbeModuleRecord& record,
                            SymbolManager& symbols,
                            bool allowDownload,
                            const ProbeLogFn& log,
                            std::size_t& outIndexedCount);

    std::uint32_t m_targetPid = 0;
    std::vector<ProbeModuleRecord> m_modules;
    std::vector<ProbeSymbolHit> m_index;
    std::vector<std::wstring> m_loadedPaths;
};
