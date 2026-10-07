#pragma once

#include <Windows.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL CallbackExperimentEnsureReady(void);

BOOL CallbackExperimentDrawTestRect(
	HWND hwnd,
	LONG left,
	LONG top,
	LONG right,
	LONG bottom,
	PDRAW_TEST_GDI_REQUEST outResult);

BOOL CallbackExperimentQueryPebDebug(PCALLBACK_PEB_DEBUG outDebug);

#ifdef __cplusplus
}
#endif
