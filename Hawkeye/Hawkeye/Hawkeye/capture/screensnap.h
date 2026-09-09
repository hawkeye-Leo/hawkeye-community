#pragma once

#include <functional>
#include <string>

class SymbolManager;

struct ScreensnapResult
{
    bool ok = false;
    std::wstring error;
    std::wstring savedPath;
};

using ScreensnapLogFn = std::function<void(const std::wstring& line)>;

ScreensnapResult runScreensnapCapture(SymbolManager* symbolManager, const ScreensnapLogFn& logFn);
