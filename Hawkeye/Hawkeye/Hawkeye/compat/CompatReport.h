#pragma once

#include <Windows.h>
#include <QString>

QString CompatReportText(const char* compatRef = nullptr, DWORD driverStartError = 0);

void CaptureMemoryIntegrityState();
bool MemoryIntegrityIsRunning();
bool MemoryIntegrityIsRunningNow();
bool MemoryIntegrityRestartNeeded();
bool TestSigningIsEnabled();
