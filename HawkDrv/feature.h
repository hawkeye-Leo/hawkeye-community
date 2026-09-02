#pragma once

#include <ntddk.h>
#include <ntimage.h>

#define HAWK_SIG_MAX            100
#define HAWK_PATTERN_TEXT_MAX   512

typedef struct _HAWK_SIG_BYTE
{
	UCHAR value;
	UCHAR mask;
} HAWK_SIG_BYTE, *PHAWK_SIG_BYTE;

BOOLEAN HawkParsePattern(
	const CHAR* text,
	HAWK_SIG_BYTE* outBytes,
	ULONG capacity,
	PULONG outLength);

BOOLEAN HawkIsValidPattern(const CHAR* text);
ULONG HawkPatternLength(const CHAR* text);

BOOLEAN HawkFormatPattern(
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	CHAR* outText,
	ULONG outChars);

BOOLEAN HawkSignatureEquals(
	const UCHAR* data,
	const HAWK_SIG_BYTE* signature,
	ULONG length);

const UCHAR* HawkFindSignatureFrom(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	SIZE_T startOffset);

const UCHAR* HawkFindSignature(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length);

const UCHAR* HawkFindNextSignature(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	const UCHAR* previousMatch);

ULONG HawkCountSignatureHits(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	ULONG maxHits);

const UCHAR* HawkFindPatternFrom(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text,
	SIZE_T startOffset);

const UCHAR* HawkFindPattern(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text);

const UCHAR* HawkFindNextPattern(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text,
	const UCHAR* previousMatch);

ULONG HawkCountPatternHits(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text,
	ULONG maxHits);

const UCHAR* HawkFindMasked(
	const UCHAR* region,
	SIZE_T regionSize,
	const UCHAR* bytes,
	const UCHAR* masks,
	ULONG patternLength);

BOOLEAN HawkReadMatchU32(
	const UCHAR* match,
	ULONG byteOffset,
	PULONG outValue);

BOOLEAN HawkReadMatchU64(
	const UCHAR* match,
	ULONG byteOffset,
	PUINT64 outValue);

ULONG_PTR HawkFindPatternInImageSection(
	const VOID* imageBase,
	const CHAR* sectionName,
	const CHAR* pattern);

ULONG_PTR HawkFindPatternInImageSectionFrom(
	const VOID* imageBase,
	const CHAR* sectionName,
	const CHAR* pattern,
	SIZE_T startOffset);

ULONG_PTR HawkFindSignatureInImageSection(
	const VOID* imageBase,
	const CHAR* sectionName,
	const HAWK_SIG_BYTE* signature,
	ULONG length);

ULONG_PTR HawkFindPatternInModule(
	const CHAR* moduleName,
	const CHAR* sectionName,
	const CHAR* pattern);
