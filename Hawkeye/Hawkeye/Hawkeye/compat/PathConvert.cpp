#include "PathConvert.h"

#include <Windows.h>

namespace {

std::wstring normalizeDriveRoot(const wchar_t* drive)
{
    if (!drive || !drive[0]) {
        return {};
    }

    std::wstring root;
    root.push_back(drive[0]);
    root.push_back(L':');
    return root;
}

bool isDevicePrefixMatch(const std::wstring& ntPath, const wchar_t* deviceName)
{
    const size_t deviceLength = wcslen(deviceName);
    if (deviceLength == 0 || ntPath.size() < deviceLength) {
        return false;
    }

    if (_wcsnicmp(ntPath.c_str(), deviceName, deviceLength) != 0) {
        return false;
    }

    if (ntPath.size() == deviceLength) {
        return true;
    }

    return ntPath[deviceLength] == L'\\';
}

std::wstring convertPathViaSystemRootSuffix(const std::wstring& ntPath)
{
    const std::wstring windowsMarker = L"\\Windows\\";
    const size_t markerPos = ntPath.find(windowsMarker);
    if (markerPos == std::wstring::npos) {
        return ntPath;
    }

    WCHAR sysRootBuf[MAX_PATH] = {};
    const DWORD len = GetEnvironmentVariableW(L"SystemRoot", sysRootBuf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return ntPath;
    }

    return std::wstring(sysRootBuf) + ntPath.substr(markerPos + wcslen(L"\\Windows"));
}

std::wstring convertNtDevicePathToDosPath(std::wstring ntPath)
{
    if (ntPath.empty()) {
        return ntPath;
    }

    const std::wstring dosDevicesPrefix = L"\\??\\";
    if (ntPath.size() >= dosDevicesPrefix.size()
        && _wcsnicmp(ntPath.c_str(), dosDevicesPrefix.c_str(), dosDevicesPrefix.size()) == 0) {
        return ntPath.substr(dosDevicesPrefix.size());
    }

    if (ntPath.compare(0, 8, L"\\Device\\") != 0) {
        return ntPath;
    }

    wchar_t driveStrings[512] = {};
    if (!GetLogicalDriveStringsW(static_cast<DWORD>(sizeof(driveStrings) / sizeof(driveStrings[0])), driveStrings)) {
        return convertPathViaSystemRootSuffix(ntPath);
    }

    for (wchar_t* drive = driveStrings; *drive != L'\0'; drive += wcslen(drive) + 1) {
        const std::wstring driveRoot = normalizeDriveRoot(drive);
        if (driveRoot.empty()) {
            continue;
        }

        wchar_t deviceName[512] = {};
        if (!QueryDosDeviceW(driveRoot.c_str(), deviceName,
                             static_cast<DWORD>(sizeof(deviceName) / sizeof(deviceName[0])))) {
            continue;
        }

        if (!isDevicePrefixMatch(ntPath, deviceName)) {
            continue;
        }

        const size_t deviceLength = wcslen(deviceName);
        const std::wstring remainder = ntPath.substr(deviceLength);

        std::wstring dosPath = driveRoot;
        if (!remainder.empty()) {
            if (remainder[0] == L'\\') {
                dosPath += remainder;
            } else {
                dosPath += L"\\" + remainder;
            }
        } else {
            dosPath += L"\\";
        }
        return dosPath;
    }

    return convertPathViaSystemRootSuffix(ntPath);
}

} // namespace

std::wstring convertSystemRootPathW(const WCHAR* wSrc)
{
    if (!wSrc || !wSrc[0]) {
        return {};
    }

    std::wstring src(wSrc);
    const std::wstring systemRootPrefix = L"\\SystemRoot\\";
    if (src.size() >= systemRootPrefix.size()
        && _wcsnicmp(src.c_str(), systemRootPrefix.c_str(), systemRootPrefix.size()) == 0) {
        WCHAR sysRootBuf[MAX_PATH] = {};
        const DWORD len = GetEnvironmentVariableW(L"SystemRoot", sysRootBuf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            src = std::wstring(sysRootBuf) + L"\\" + src.substr(systemRootPrefix.size());
        }
    }

    return convertNtDevicePathToDosPath(std::move(src));
}

QString convertSystemRootPath(const WCHAR* wSrc)
{
    return QString::fromStdWString(convertSystemRootPathW(wSrc));
}
