#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

#include "hawk_hot_targets.h"

int main(void)
{
	HMODULE dll;
	HawkHotTargetsQueryFn query;
	HAWK_HOT_TARGETS targets;
	ULONG i;

	dll = LoadLibraryW(L"HawkHotTargets.dll");
	if (dll == NULL) {
		printf("LoadLibrary HawkHotTargets.dll failed (%lu)\n", GetLastError());
		return 1;
	}

	query = (HawkHotTargetsQueryFn)GetProcAddress(dll, "HawkHotTargetsQuery");
	if (query == NULL) {
		printf("GetProcAddress HawkHotTargetsQuery failed (%lu)\n", GetLastError());
		FreeLibrary(dll);
		return 1;
	}

	RtlZeroMemory(&targets, sizeof(targets));
	if (!query(&targets)) {
		printf("HawkHotTargetsQuery failed (pid=%lu count=%lu err=%lu)\n",
			targets.pid,
			targets.count,
			GetLastError());
		FreeLibrary(dll);
		return 1;
	}

	printf("version=%lu pid=%lu count=%lu\n", targets.version, targets.pid, targets.count);
	for (i = 0; i < targets.count; ++i) {
		const HAWK_HOT_TARGET* item = &targets.items[i];
		printf("  [%lu] va=0x%llx size=0x%lx name=\"%s\" note=\"%s\"\n",
			i,
			(unsigned long long)item->va,
			item->size,
			item->name,
			item->note);
	}

	FreeLibrary(dll);
	return 0;
}
