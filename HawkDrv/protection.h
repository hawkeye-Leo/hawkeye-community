#pragma once

#include <ntifs.h>

NTSTATUS HawkEnablePpl(_In_ ULONG Pid);
NTSTATUS HawkDisablePpl(_In_ ULONG Pid);
