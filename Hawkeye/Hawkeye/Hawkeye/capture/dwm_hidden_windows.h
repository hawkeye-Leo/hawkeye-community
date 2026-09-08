#pragma once

#include <Windows.h>

#include <functional>
#include <string>
#include <vector>

class SymbolManager;

struct WndInfo
{
    ULONG pid = 0;
    ULONG hwnd = 0;
};

enum class HiddenWindowOffsetState
{
    NotInitialized = 0,
    Ready,
    Failed,
};

struct HiddenWindowOffsetInitResult
{
    HiddenWindowOffsetState state = HiddenWindowOffsetState::NotInitialized;
    ULONG flagsOffset = 0;
    ULONG kindOffset = 0;
    ULONG hwndOffset = 0;
    ULONG pidOffset = 0;
    ULONGLONG vtableAddress = 0;
    ULONGLONG sampleObjectAddress = 0;
    BOOL ranCalibration = FALSE;
    std::wstring message;
};

using HiddenWindowLogFn = std::function<void(const std::wstring&)>;
using HiddenWindowAffinityFn = std::function<bool(HWND, BOOL)>;

DWORD GetDwmProcessId();
HiddenWindowOffsetState GetHiddenWindowOffsetState();
HiddenWindowOffsetInitResult InitHiddenWindowOffsets(
    HWND mainWindow,
    SymbolManager* symbolManager,
    const HiddenWindowLogFn& logFn,
    const HiddenWindowAffinityFn& affinityFn = HiddenWindowAffinityFn{});
VOID DetectHiddenWindows(std::vector<WndInfo>& windows, HWND mainWindow);
BOOL SetWindowAntiCapture(HWND hwnd, BOOL enable);
