#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define HAWK_HOT_TARGETS_ABI        1
#define HAWK_HOT_TARGETS_MAX        16
#define HAWK_HOT_NAME_CHARS         64
#define HAWK_HOT_NOTE_CHARS         128

/*
 * One live hot target. name and note are optional; empty string means omitted.
 * size 0 means unspecified; a page-sized probe typically uses 0x1000.
 */
typedef struct _HAWK_HOT_TARGET
{
	ULONG64 va;
	ULONG   size;
	CHAR    name[HAWK_HOT_NAME_CHARS];
	CHAR    note[HAWK_HOT_NOTE_CHARS];
} HAWK_HOT_TARGET;

typedef struct _HAWK_HOT_TARGETS
{
	ULONG version;
	ULONG pid;
	ULONG count;
	ULONG reserved;
	HAWK_HOT_TARGET items[HAWK_HOT_TARGETS_MAX];
} HAWK_HOT_TARGETS;

/*
 * Customer plugin export. Called once when the user starts an analysis.
 * Fill *out and return TRUE. Hawkeye only reads; it does not invent addresses.
 */
typedef BOOL (WINAPI *HawkHotTargetsQueryFn)(HAWK_HOT_TARGETS* out);

#ifdef __cplusplus
}
#endif
