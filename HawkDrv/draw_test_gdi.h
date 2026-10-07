#pragma once

#include <ntddk.h>
#include "..\common.h"

VOID HawkIoctlUsermodeCallbackInit(_In_ PIRP Irp);
VOID HawkIoctlUsermodeCallbackCall6(_In_ PIRP Irp);
