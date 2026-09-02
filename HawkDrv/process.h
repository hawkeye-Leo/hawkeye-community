#pragma once

#include <ntddk.h>

VOID HawkIoctlOpenProcessHandle(PIRP Irp);
HANDLE HawkOpenProcessByPid(HANDLE pid);
