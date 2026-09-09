#include "screensnap.h"

#include "dwm_hidden_windows.h"
#include "Driver.h"
#include "PathConvert.h"
#include "process.h"
#include "symmanager.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QImage>

#include <Windows.h>

#include <cstring>
#include <memory>
#include <sstream>
#include <vector>

namespace {

constexpr wchar_t kRenderForCaptureSymbol[] =
    L"?RenderForCapture@CaptureBitsResponse@@IEAAJXZ";

constexpr ULONG kSymTagFunction = 5;
constexpr DWORD kMinCompositionDisp = 0x400;
constexpr SIZE_T kPatchBytes = 7;
constexpr SIZE_T kMaxFunctionScanBytes = 8192;

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

struct SuperCapturePatchSite
{
    ULONGLONG patchVa = 0;
    DWORD flagOffset = 0;
    UCHAR original[kPatchBytes]{};
    UCHAR patched[kPatchBytes]{};
};

void logLine(const ScreensnapLogFn& logFn, const std::wstring& line)
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
void logf(const ScreensnapLogFn& logFn, Args&&... args)
{
    std::wostringstream stream;
    appendLogStream(stream, std::forward<Args>(args)...);
    logLine(logFn, stream.str());
}

std::wstring findDwmcoreModulePath(DWORD dwmPid)
{
    for (const Process::ModuleInfo& module : Process::enumerateModules(dwmPid)) {
        const size_t slash = module.path.find_last_of(L"\\/");
        const std::wstring fileName = (slash == std::wstring::npos)
            ? module.path
            : module.path.substr(slash + 1);
        if (_wcsicmp(fileName.c_str(), L"dwmcore.dll") == 0) {
            return module.path;
        }
    }
    return {};
}

bool loadDwmcoreSymbols(
    DWORD dwmPid,
    SymbolManager* symbolManager,
    const ScreensnapLogFn& logFn,
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

    const std::wstring modulePath = findDwmcoreModulePath(dwmPid);
    if (modulePath.empty()) {
        errorOut = L"dwmcore.dll was not found in dwm.exe module list.";
        return false;
    }

    logf(logFn, L"[screensnap] dwmcore.dll path: ", modulePath);

    const std::wstring dosPath = convertSystemRootPathW(modulePath.c_str());
    if (dosPath.empty()) {
        errorOut = L"Failed to normalize dwmcore.dll path.";
        return false;
    }

    moduleKeyOut = SymbolManager::NormalizeFilePathKey(dosPath);

    bool symBusy = false;
    if (!symbolManager->IsSymbolLoaded(moduleKeyOut, &symBusy)) {
        if (symBusy) {
            errorOut = L"Symbol manager is busy.";
            return false;
        }

        logLine(logFn, L"[screensnap] Loading dwmcore.dll symbols (PDB download allowed)...");
        SymbolLoadOptions loadOptions;
        loadOptions.allowDownload = true;
        loadOptions.maxLoadAttempts = 4;
        loadOptions.logFn = logFn;

        std::wstring loadError;
        if (!symbolManager->LoadSymbol(dosPath, loadError, dwmPid, &loadOptions)) {
            errorOut = loadError.empty() ? L"Failed to load dwmcore.dll symbols." : loadError;
            return false;
        }

        logLine(logFn, L"[screensnap] dwmcore.dll symbols loaded.");
    } else {
        logLine(logFn, L"[screensnap] dwmcore.dll symbols already loaded.");
    }

    if (!symbolManager->GetLoadedModuleBase(moduleKeyOut, moduleBaseOut, &symBusy) || moduleBaseOut == 0) {
        errorOut = symBusy ? L"Symbol manager is busy." : L"Could not resolve dwmcore.dll module base.";
        return false;
    }

    logf(logFn, L"[screensnap] dwmcore.dll base in dwm.exe: 0x", std::hex, moduleBaseOut, std::dec);
    return true;
}

HANDLE openProcessViaDriver(DWORD pid, DWORD desiredAccess)
{
    OPEN_PROCESS_HANDLE inout = {};
    inout.pid = pid;
    inout.desiredAccess = desiredAccess;
    OpenProcessHandle(&inout);
    if (inout.errCode != 1 || inout.processHandle == 0) {
        return nullptr;
    }

    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(inout.processHandle));
}

bool readRemoteBytes(HANDLE process, ULONGLONG address, UCHAR* buffer, SIZE_T size)
{
    if (!process || !buffer || size == 0) {
        return false;
    }

    SIZE_T bytesRead = 0;
    return ReadProcessMemory(
               process,
               reinterpret_cast<LPCVOID>(address),
               buffer,
               size,
               &bytesRead)
        && bytesRead == size;
}

bool writeRemoteBytes(HANDLE process, ULONGLONG address, const UCHAR* buffer, SIZE_T size)
{
    if (!process || !buffer || size == 0) {
        return false;
    }

    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(
               process,
               reinterpret_cast<LPVOID>(address),
               buffer,
               size,
               &bytesWritten)
        && bytesWritten == size;
}

bool resolveFunctionScanSize(
    SymbolManager* symbolManager,
    DWORD64 moduleBase,
    DWORD64 functionVa,
    SIZE_T& outSize)
{
    outSize = 4096;

    bool symBusy = false;
    std::vector<CollectedSymbol> symbols;
    if (!symbolManager->CollectModuleSymbols(moduleBase, symbols, &symBusy) || symBusy) {
        return true;
    }

    DWORD64 nextFunctionVa = functionVa + kMaxFunctionScanBytes;
    for (const CollectedSymbol& symbol : symbols) {
        if (symbol.symTag != kSymTagFunction) {
            continue;
        }
        if (symbol.address > functionVa && symbol.address < nextFunctionVa) {
            nextFunctionVa = symbol.address;
        }
    }

    if (nextFunctionVa > functionVa) {
        outSize = static_cast<SIZE_T>(nextFunctionVa - functionVa);
    }

    if (outSize > kMaxFunctionScanBytes) {
        outSize = kMaxFunctionScanBytes;
    }

    return outSize > 0;
}

bool isMovBytePtrRaxDisp(const UCHAR* insn, DWORD& dispOut)
{
    if (insn[0] == 0xC6 && insn[1] == 0x80) {
        dispOut = *reinterpret_cast<const DWORD*>(insn + 2);
        return dispOut > kMinCompositionDisp;
    }

    if (insn[0] >= 0x40 && insn[0] <= 0x4F && insn[1] == 0x88 && (insn[2] & 0xC7) == 0x80) {
        dispOut = *reinterpret_cast<const DWORD*>(insn + 3);
        return dispOut > kMinCompositionDisp;
    }

    return false;
}

int sourceRegFromRex88Modrm(UCHAR rexPrefix, UCHAR modrm)
{
    int reg = static_cast<int>((modrm >> 3) & 7);
    if ((rexPrefix & 0x04) != 0) {
        reg += 8;
    }
    return reg;
}

bool extendedRegAssignedOneEarlier(const UCHAR* code, SIZE_T codeSize, SIZE_T storeOffset, int regIndex)
{
    if (regIndex < 8 || regIndex > 15 || storeOffset == 0) {
        return false;
    }

    const UCHAR opcode32 = static_cast<UCHAR>(0xB8 + (regIndex & 7));
    const UCHAR opcode8 = static_cast<UCHAR>(0xB0 + (regIndex & 7));

    for (SIZE_T offset = 0; offset < storeOffset; ++offset) {
        if (offset + 6 <= storeOffset
            && code[offset] == 0x41
            && code[offset + 1] == opcode32
            && code[offset + 2] == 0x01
            && code[offset + 3] == 0x00
            && code[offset + 4] == 0x00
            && code[offset + 5] == 0x00) {
            return true;
        }

        if (offset + 3 <= storeOffset
            && code[offset] == 0x41
            && code[offset + 1] == opcode8
            && code[offset + 2] == 0x01) {
            return true;
        }
    }

    return false;
}

bool buildPatchedBytes(const UCHAR* original, SuperCapturePatchSite& site)
{
    std::memcpy(site.original, original, kPatchBytes);

    if (original[0] == 0xC6 && original[1] == 0x80) {
        std::memcpy(site.patched, original, kPatchBytes);
        site.patched[6] = 0x00;
        site.flagOffset = *reinterpret_cast<const DWORD*>(original + 2);
        return true;
    }

    if (original[0] >= 0x40 && original[0] <= 0x4F && original[1] == 0x88) {
        site.flagOffset = *reinterpret_cast<const DWORD*>(original + 3);
        site.patched[0] = 0xC6;
        site.patched[1] = 0x80;
        site.patched[2] = original[3];
        site.patched[3] = original[4];
        site.patched[4] = original[5];
        site.patched[5] = original[6];
        site.patched[6] = 0x00;
        return true;
    }

    return false;
}

bool resolveRenderForCapturePatchSite(
    const UCHAR* code,
    SIZE_T codeSize,
    ULONGLONG functionVa,
    SuperCapturePatchSite& siteOut,
    const ScreensnapLogFn& logFn)
{
    for (SIZE_T offset = 0; offset + kPatchBytes <= codeSize; ++offset) {
        const UCHAR* insn = code + offset;

        DWORD disp = 0;
        if (!isMovBytePtrRaxDisp(insn, disp)) {
            continue;
        }

        if (insn[0] == 0xC6 && insn[1] == 0x80) {
            if (insn[6] != 0x01) {
                continue;
            }

            SuperCapturePatchSite candidate{};
            if (!buildPatchedBytes(insn, candidate)) {
                continue;
            }

            candidate.patchVa = functionVa + offset;
            siteOut = candidate;
            logf(logFn,
                L"[screensnap] Confirmed patch site: mov byte ptr [rax+0x",
                std::hex,
                disp,
                std::dec,
                L"], 1");
            return true;
        }

        if (insn[0] >= 0x40 && insn[0] <= 0x4F && insn[1] == 0x88) {
            const int sourceReg = sourceRegFromRex88Modrm(insn[0], insn[2]);
            logf(logFn,
                L"[screensnap] Candidate: mov [rax+0x",
                std::hex,
                disp,
                std::dec,
                L"], r",
                sourceReg,
                L"b -- scanning RenderForCapture for mov r",
                sourceReg,
                L"d/r",
                sourceReg,
                L"b, 1 ...");

            if (!extendedRegAssignedOneEarlier(code, codeSize, offset, sourceReg)) {
                logf(logFn,
                    L"[screensnap]   no mov r",
                    sourceReg,
                    L"d/r",
                    sourceReg,
                    L"b, 1 found before this store; skipping.");
                continue;
            }

            SuperCapturePatchSite candidate{};
            if (!buildPatchedBytes(insn, candidate)) {
                continue;
            }

            candidate.patchVa = functionVa + offset;
            siteOut = candidate;
            logf(logFn,
                L"[screensnap] Confirmed patch site: mov [rax+0x",
                std::hex,
                disp,
                std::dec,
                L"], r",
                sourceReg,
                L"b (preceded by mov r",
                sourceReg,
                L"d/r",
                sourceReg,
                L"b, 1)");
            return true;
        }
    }

    return false;
}

std::wstring formatByteArray(const UCHAR* bytes, SIZE_T size)
{
    std::wostringstream stream;
    for (SIZE_T i = 0; i < size; ++i) {
        if (i > 0) {
            stream << L' ';
        }
        stream << std::hex << std::uppercase;
        stream.width(2);
        stream.fill(L'0');
        stream << static_cast<unsigned>(bytes[i]);
        stream << std::dec;
    }
    return stream.str();
}

bool capturePrimaryDisplayBitBlt(const QString& outputPath, std::wstring& errorOut)
{
    HDC screenDc = GetDC(nullptr);
    if (!screenDc) {
        errorOut = L"GetDC failed (err=" + std::to_wstring(GetLastError()) + L").";
        return false;
    }

    const int width = GetSystemMetrics(SM_CXSCREEN);
    const int height = GetSystemMetrics(SM_CYSCREEN);
    if (width <= 0 || height <= 0) {
        ReleaseDC(nullptr, screenDc);
        errorOut = L"Invalid screen dimensions.";
        return false;
    }

    BITMAPINFOHEADER bitmapInfo = {};
    bitmapInfo.biSize = sizeof(BITMAPINFOHEADER);
    bitmapInfo.biWidth = width;
    bitmapInfo.biHeight = -height;
    bitmapInfo.biPlanes = 1;
    bitmapInfo.biBitCount = 32;
    bitmapInfo.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP dib = CreateDIBSection(
        screenDc,
        reinterpret_cast<BITMAPINFO*>(&bitmapInfo),
        DIB_RGB_COLORS,
        &bits,
        nullptr,
        0);
    if (!dib || !bits) {
        ReleaseDC(nullptr, screenDc);
        errorOut = L"CreateDIBSection failed (err=" + std::to_wstring(GetLastError()) + L").";
        return false;
    }

    HDC memoryDc = CreateCompatibleDC(screenDc);
    if (!memoryDc) {
        DeleteObject(dib);
        ReleaseDC(nullptr, screenDc);
        errorOut = L"CreateCompatibleDC failed (err=" + std::to_wstring(GetLastError()) + L").";
        return false;
    }

    HGDIOBJ oldBitmap = SelectObject(memoryDc, dib);
    const BOOL bltOk = BitBlt(memoryDc, 0, 0, width, height, screenDc, 0, 0, SRCCOPY | CAPTUREBLT);

    SelectObject(memoryDc, oldBitmap);
    ReleaseDC(nullptr, screenDc);
    DeleteDC(memoryDc);

    if (!bltOk) {
        DeleteObject(dib);
        errorOut = L"BitBlt failed (err=" + std::to_wstring(GetLastError()) + L").";
        return false;
    }

    QImage image(width, height, QImage::Format_ARGB32);
    if (image.isNull()) {
        DeleteObject(dib);
        errorOut = L"Failed to allocate QImage buffer.";
        return false;
    }

    std::memcpy(image.bits(), bits, static_cast<size_t>(width) * static_cast<size_t>(height) * 4);
    DeleteObject(dib);

    if (!image.save(outputPath)) {
        errorOut = L"Failed to save image.";
        return false;
    }

    return true;
}

} // namespace

ScreensnapResult runScreensnapCapture(SymbolManager* symbolManager, const ScreensnapLogFn& logFn)
{
    ScreensnapResult result{};

    logLine(logFn, L"[screensnap] Starting super-capture screenshot (BitBlt path).");

    if (symbolManager == nullptr) {
        result.error = L"Symbol manager is not available.";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    const DWORD dwmPid = GetDwmProcessId();
    if (dwmPid == 0) {
        result.error = L"DWM notification window not found.";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    logf(logFn, L"[screensnap] DWM pid=", dwmPid);

    std::wstring moduleKey;
    DWORD64 moduleBase = 0;
    std::wstring symbolError;
    if (!loadDwmcoreSymbols(dwmPid, symbolManager, logFn, moduleKey, moduleBase, symbolError)) {
        result.error = symbolError.empty() ? L"Failed to prepare dwmcore.dll symbols." : symbolError;
        logf(logFn, L"[screensnap] Error: ", result.error);
        logLine(logFn, L"[screensnap] Hint: run !sym -load -path:<dwmcore.dll> -pid:<dwm pid> if symbols are missing.");
        return result;
    }

    bool symBusy = false;
    DWORD64 renderForCaptureVa = 0;
    if (!symbolManager->GetSymbolAddress(kRenderForCaptureSymbol, renderForCaptureVa, &symBusy)) {
        result.error = symBusy
            ? L"Symbol manager is busy."
            : L"RenderForCapture symbol not found in dwmcore.dll PDB.";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    logf(logFn, L"[screensnap] RenderForCapture VA=0x", std::hex, renderForCaptureVa, std::dec);

    SIZE_T functionSize = 0;
    if (!resolveFunctionScanSize(symbolManager, moduleBase, renderForCaptureVa, functionSize)) {
        result.error = L"Could not determine RenderForCapture scan size.";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    logf(logFn, L"[screensnap] RenderForCapture scan size=", functionSize, L" bytes");

    ScopedHandle readHandle(openProcessViaDriver(
        dwmPid,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ));
    if (!readHandle) {
        result.error = L"OpenProcessHandle failed for DWM (read access).";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    logf(logFn,
        L"[screensnap] OpenProcessHandle succeeded (read, handle=0x",
        std::hex,
        reinterpret_cast<ULONGLONG>(readHandle.get()),
        std::dec,
        L")");

    std::vector<UCHAR> functionBytes(functionSize);
    if (!readRemoteBytes(readHandle.get(), renderForCaptureVa, functionBytes.data(), functionBytes.size())) {
        result.error = L"ReadProcessMemory failed while reading RenderForCapture.";
        logf(logFn, L"[screensnap] Error: ", result.error, L" (win32=", GetLastError(), L")");
        return result;
    }

    SuperCapturePatchSite patchSite{};
    if (!resolveRenderForCapturePatchSite(
            functionBytes.data(),
            functionBytes.size(),
            renderForCaptureVa,
            patchSite,
            logFn))
    {
        result.error = L"Could not find capture patch site in RenderForCapture.";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    logf(logFn,
        L"[screensnap] Patch VA=0x",
        std::hex,
        patchSite.patchVa,
        std::dec,
        L"  [rax+0x",
        std::hex,
        patchSite.flagOffset,
        std::dec,
        L"]");
    logf(logFn, L"[screensnap] Original bytes: ", formatByteArray(patchSite.original, kPatchBytes));
    logf(logFn, L"[screensnap] Patched bytes:  ", formatByteArray(patchSite.patched, kPatchBytes));

    readHandle.reset();

    ScopedHandle writeHandle(openProcessViaDriver(
        dwmPid,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION));
    if (!writeHandle) {
        result.error = L"OpenProcessHandle failed for DWM (write access).";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    logf(logFn,
        L"[screensnap] OpenProcessHandle succeeded (write, handle=0x",
        std::hex,
        reinterpret_cast<ULONGLONG>(writeHandle.get()),
        std::dec,
        L")");

    UCHAR liveOriginal[kPatchBytes]{};
    if (!readRemoteBytes(writeHandle.get(), patchSite.patchVa, liveOriginal, kPatchBytes)) {
        result.error = L"ReadProcessMemory failed at patch site.";
        logf(logFn, L"[screensnap] Error: ", result.error, L" (win32=", GetLastError(), L")");
        return result;
    }

    logf(logFn, L"[screensnap] Live bytes before patch: ", formatByteArray(liveOriginal, kPatchBytes));

    if (std::memcmp(liveOriginal, patchSite.original, kPatchBytes) != 0) {
        logLine(logFn, L"[screensnap] Warning: live bytes differ from RenderForCapture scan; proceeding with live backup.");
        std::memcpy(patchSite.original, liveOriginal, kPatchBytes);
    }

    logLine(logFn, L"[screensnap] Applying temporary patch (mov byte ptr [rax+disp32], 0) ...");
    if (!writeRemoteBytes(writeHandle.get(), patchSite.patchVa, patchSite.patched, kPatchBytes)) {
        result.error = L"WriteProcessMemory failed while applying patch.";
        logf(logFn, L"[screensnap] Error: ", result.error, L" (win32=", GetLastError(), L")");
        return result;
    }

    const QDir outputDir(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("screensnap")));
    if (!outputDir.exists() && !outputDir.mkpath(QStringLiteral("."))) {
        writeRemoteBytes(writeHandle.get(), patchSite.patchVa, patchSite.original, kPatchBytes);
        result.error = L"Failed to create output directory.";
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    const QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
    const QString outputPath = outputDir.filePath(QStringLiteral("screensnap_%1.png").arg(timestamp));
    logLine(logFn, L"[screensnap] Capturing primary display via BitBlt ...");

    std::wstring captureError;
    const bool captured = capturePrimaryDisplayBitBlt(outputPath, captureError);

    logLine(logFn, L"[screensnap] Restoring original bytes ...");
    if (!writeRemoteBytes(writeHandle.get(), patchSite.patchVa, patchSite.original, kPatchBytes)) {
        logf(logFn, L"[screensnap] Error: WriteProcessMemory failed during restore (win32=", GetLastError(), L").");
        if (captured) {
            result.error = L"Capture saved but patch restore failed.";
            result.savedPath = outputPath.toStdWString();
        } else {
            result.error = L"Capture failed and patch restore failed.";
        }
        return result;
    }

    logLine(logFn, L"[screensnap] Patch restored.");

    if (!captured) {
        result.error = captureError.empty() ? L"BitBlt capture failed." : captureError;
        logf(logFn, L"[screensnap] Error: ", result.error);
        return result;
    }

    result.ok = true;
    result.savedPath = outputPath.toStdWString();
    logf(logFn, L"[screensnap] Saved screenshot: ", result.savedPath);
    return result;
}
