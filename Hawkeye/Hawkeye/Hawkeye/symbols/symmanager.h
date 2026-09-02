#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>

#pragma comment(lib, "dbghelp.lib")

struct SYMBOL_FILE_INFO
{
    std::wstring filePath;
    std::wstring pdbName;
    DWORD timestamp = 0;  // PE header TimeDateStamp (display only; not PDB signature)
    DWORD checksum = 0;   // PE header CheckSum (display only)
    std::wstring localPdbPath;
    DWORD64 baseAddr = 0;
    bool loadedInDbgHelp = false;
    DWORD targetPid = 0;  // PID used to resolve base (display only; map key is file path)
};

struct SymbolLoadOptions
{
    std::function<void(const std::wstring& message)> logFn;
    int maxLoadAttempts = 4;
    // false = use local symbol cache only (no Microsoft symbol server download)
    bool allowDownload = true;
};

struct CollectedSymbol
{
    std::wstring decoratedName;
    std::wstring friendlyName;
    DWORD64 address = 0;
    ULONG symTag = 0; // DbgHelp SYMBOL_INFO::Tag (PDB/DIA SymTag*)
    ULONG flags = 0;  // DbgHelp SYMBOL_INFO::Flags (SYMFLAG_*)
};

class SymbolManager
{
public:
    SymbolManager();
    ~SymbolManager();

    bool Initialize();
    void Cleanup();

    bool DownloadSymbol(const std::wstring& filePath, std::wstring& outPdbPath, std::wstring& outError);
    bool LoadSymbol(const std::wstring& filePath,
                    std::wstring& outError,
                    DWORD targetPid = 0,
                    const SymbolLoadOptions* options = nullptr);
    bool UnloadSymbol(const std::wstring& filePath, bool* outBusy = nullptr);
    bool IsSymbolLoaded(const std::wstring& filePath, bool* outBusy = nullptr) const;
    // True when this session has a tracked entry (cached or loaded), not whether a PDB file exists on disk.
    bool IsSymbolCached(const std::wstring& filePath, bool* outBusy = nullptr) const;

    bool GetSymbolName(DWORD64 address, std::wstring& outSymbolName, bool* outBusy = nullptr);
    bool ResolveAddress(DWORD64 address,
                        std::wstring& outSymbolName,
                        DWORD64& outDisplacement,
                        std::wstring& outModuleName,
                        DWORD64& outModuleBase,
                        bool* outBusy = nullptr);

    bool GetSymbolAddress(const std::wstring& decoratedName,
                          DWORD64& outAddress,
                          bool* outBusy = nullptr);

    bool BuildNameIndex(DWORD64 moduleBase = 0, bool* outBusy = nullptr);

    bool GetSymbolAddressByName(const std::wstring& friendlyName,
                                DWORD64& outAddress,
                                bool* outBusy = nullptr);

    static std::wstring DemangleSymbolName(const std::wstring& symbolName);

    bool GetLoadedModuleBase(const std::wstring& filePath,
                             DWORD64& outBaseAddr,
                             bool* outBusy = nullptr) const;
    bool GetModuleAtAddress(DWORD64 address,
                            DWORD64& outModuleBase,
                            std::wstring& outModuleName,
                            bool* outBusy = nullptr);
    bool GetModuleInfo(DWORD64 address, IMAGEHLP_MODULE64& outModule);

    bool GetSymbolEntries(std::vector<SYMBOL_FILE_INFO>& outEntries, bool* outBusy = nullptr) const;

    std::wstring GetSymbolCacheDirectory(bool* outBusy = nullptr) const;
    bool CollectModuleSymbols(DWORD64 moduleBase,
                              std::vector<CollectedSymbol>& outSymbols,
                              bool* outBusy = nullptr);

    static std::wstring NormalizeFilePathKey(const std::wstring& filePath);

private:
    bool m_initialized;
    HANDLE m_processHandle;
    std::wstring m_symbolPath;
    std::wstring m_symbolSearchPath;
    std::wstring m_symbolSearchPathLocal;
    std::map<std::wstring, SYMBOL_FILE_INFO> m_symbols;
    mutable std::mutex m_mutex;

    std::map<std::wstring, DWORD64> m_nameIndex;
    bool m_nameIndexBuilt = false;
    DWORD64 m_nameIndexModuleBase = 0;

    void InvalidateNameIndex();

    bool CreateSymbolDirectory();
};
