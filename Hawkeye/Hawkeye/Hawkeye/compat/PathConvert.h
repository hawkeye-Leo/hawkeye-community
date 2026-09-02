#pragma once

#include <Windows.h>

#include <QString>
#include <string>
QString convertSystemRootPath(const WCHAR* wSrc);
std::wstring convertSystemRootPathW(const WCHAR* wSrc);
