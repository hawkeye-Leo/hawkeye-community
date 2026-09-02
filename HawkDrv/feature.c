#include "feature.h"
#include "module.h"

static BOOLEAN IsPatternSpace(CHAR c)
{
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

static INT HexNibble(CHAR c)
{
	if (c >= '0' && c <= '9')
	{
		return (INT)(c - '0');
	}
	if (c >= 'A' && c <= 'F')
	{
		return (INT)(c - 'A' + 10);
	}
	if (c >= 'a' && c <= 'f')
	{
		return (INT)(c - 'a' + 10);
	}
	return -1;
}

BOOLEAN HawkParsePattern(
	const CHAR* text,
	HAWK_SIG_BYTE* outBytes,
	ULONG capacity,
	PULONG outLength)
{
	ULONG count;
	const CHAR* cursor;

	if (outLength != NULL)
	{
		*outLength = 0;
	}

	if (text == NULL || outBytes == NULL || capacity == 0)
	{
		return FALSE;
	}

	count = 0;
	cursor = text;
	while (*cursor != '\0')
	{
		CHAR high;
		CHAR low;
		INT highNibble;
		INT lowNibble;
		HAWK_SIG_BYTE parsed;

		while (IsPatternSpace(*cursor))
		{
			cursor++;
		}
		if (*cursor == '\0')
		{
			break;
		}

		high = *cursor++;
		while (IsPatternSpace(*cursor))
		{
			cursor++;
		}

		if (*cursor == '\0')
		{
			if (high != '?')
			{
				return FALSE;
			}
			low = '?';
		}
		else
		{
			low = *cursor++;
		}

		RtlZeroMemory(&parsed, sizeof(parsed));
		highNibble = HexNibble(high);
		lowNibble = HexNibble(low);

		if (high == '?' && low == '?')
		{
			parsed.value = 0;
			parsed.mask = 0x00;
		}
		else if (high == '?' && lowNibble >= 0)
		{
			parsed.value = (UCHAR)lowNibble;
			parsed.mask = 0x0F;
		}
		else if (highNibble >= 0 && low == '?')
		{
			parsed.value = (UCHAR)(highNibble << 4);
			parsed.mask = 0xF0;
		}
		else if (highNibble >= 0 && lowNibble >= 0)
		{
			parsed.value = (UCHAR)((highNibble << 4) | lowNibble);
			parsed.mask = 0xFF;
		}
		else
		{
			return FALSE;
		}

		if (count >= capacity)
		{
			return FALSE;
		}

		outBytes[count++] = parsed;
	}

	if (count == 0)
	{
		return FALSE;
	}

	if (outLength != NULL)
	{
		*outLength = count;
	}
	return TRUE;
}

BOOLEAN HawkIsValidPattern(const CHAR* text)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG length;

	return HawkParsePattern(text, compiled, HAWK_SIG_MAX, &length);
}

ULONG HawkPatternLength(const CHAR* text)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG length = 0;

	if (!HawkParsePattern(text, compiled, HAWK_SIG_MAX, &length))
	{
		return 0;
	}

	return length;
}

BOOLEAN HawkFormatPattern(
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	CHAR* outText,
	ULONG outChars)
{
	ULONG i;
	ULONG pos;

	if (signature == NULL || outText == NULL || length == 0 ||
		length > HAWK_SIG_MAX || outChars < 3)
	{
		return FALSE;
	}

	pos = 0;
	outText[0] = '\0';

	for (i = 0; i < length; i++)
	{
		CHAR token[4];
		ULONG tokenLen;
		UCHAR mask = signature[i].mask;
		UCHAR value = signature[i].value;

		if (mask == 0xFF)
		{
			token[0] = "0123456789ABCDEF"[value >> 4];
			token[1] = "0123456789ABCDEF"[value & 0x0F];
			token[2] = '\0';
			tokenLen = 2;
		}
		else if (mask == 0x00)
		{
			token[0] = '?';
			token[1] = '?';
			token[2] = '\0';
			tokenLen = 2;
		}
		else if (mask == 0xF0)
		{
			token[0] = "0123456789ABCDEF"[value >> 4];
			token[1] = '?';
			token[2] = '\0';
			tokenLen = 2;
		}
		else if (mask == 0x0F)
		{
			token[0] = '?';
			token[1] = "0123456789ABCDEF"[value & 0x0F];
			token[2] = '\0';
			tokenLen = 2;
		}
		else
		{
			return FALSE;
		}

		if (pos != 0)
		{
			if (pos + 1 >= outChars)
			{
				return FALSE;
			}
			outText[pos++] = ' ';
		}

		if (pos + tokenLen >= outChars)
		{
			return FALSE;
		}

		outText[pos++] = token[0];
		outText[pos++] = token[1];
		outText[pos] = '\0';
	}

	return TRUE;
}

BOOLEAN HawkSignatureEquals(
	const UCHAR* data,
	const HAWK_SIG_BYTE* signature,
	ULONG length)
{
	ULONG i;

	if (data == NULL || signature == NULL || length == 0)
	{
		return FALSE;
	}

	for (i = 0; i < length; i++)
	{
		if ((data[i] & signature[i].mask) != (signature[i].value & signature[i].mask))
		{
			return FALSE;
		}
	}

	return TRUE;
}

const UCHAR* HawkFindSignatureFrom(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	SIZE_T startOffset)
{
	ULONG anchor;
	SIZE_T lastStart;
	SIZE_T index;
	const UCHAR* window;
	SIZE_T windowSize;

	if (region == NULL || signature == NULL ||
		length == 0 || length > HAWK_SIG_MAX ||
		startOffset >= regionSize)
	{
		return NULL;
	}

	window = region + startOffset;
	windowSize = regionSize - startOffset;
	if (windowSize < length)
	{
		return NULL;
	}

	anchor = 0;
	while (anchor < length && signature[anchor].mask != 0xFF)
	{
		anchor++;
	}

	if (anchor == length)
	{
		anchor = 0;
		while (anchor < length && signature[anchor].mask == 0x00)
		{
			anchor++;
		}
		if (anchor == length)
		{
			return window;
		}
	}

	lastStart = windowSize - length;
	for (index = 0; index <= lastStart; index++)
	{
		const HAWK_SIG_BYTE* probe = &signature[anchor];

		if ((window[index + anchor] & probe->mask) != (probe->value & probe->mask))
		{
			continue;
		}

		if (!HawkSignatureEquals(window + index, signature, length))
		{
			continue;
		}

		return window + index;
	}

	return NULL;
}

const UCHAR* HawkFindSignature(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length)
{
	return HawkFindSignatureFrom(region, regionSize, signature, length, 0);
}

const UCHAR* HawkFindNextSignature(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	const UCHAR* previousMatch)
{
	SIZE_T startOffset;

	if (previousMatch == NULL)
	{
		return HawkFindSignatureFrom(region, regionSize, signature, length, 0);
	}

	if (region == NULL || previousMatch < region)
	{
		return NULL;
	}

	startOffset = (SIZE_T)(previousMatch - region) + 1;
	return HawkFindSignatureFrom(region, regionSize, signature, length, startOffset);
}

ULONG HawkCountSignatureHits(
	const UCHAR* region,
	SIZE_T regionSize,
	const HAWK_SIG_BYTE* signature,
	ULONG length,
	ULONG maxHits)
{
	ULONG count = 0;
	const UCHAR* hit = NULL;

	for (;;)
	{
		hit = HawkFindNextSignature(region, regionSize, signature, length, hit);
		if (hit == NULL)
		{
			break;
		}

		count++;
		if (maxHits != 0 && count >= maxHits)
		{
			break;
		}
	}

	return count;
}

const UCHAR* HawkFindPatternFrom(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text,
	SIZE_T startOffset)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG length;

	if (!HawkParsePattern(text, compiled, HAWK_SIG_MAX, &length))
	{
		return NULL;
	}

	return HawkFindSignatureFrom(region, regionSize, compiled, length, startOffset);
}

const UCHAR* HawkFindPattern(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text)
{
	return HawkFindPatternFrom(region, regionSize, text, 0);
}

const UCHAR* HawkFindNextPattern(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text,
	const UCHAR* previousMatch)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG length;

	if (!HawkParsePattern(text, compiled, HAWK_SIG_MAX, &length))
	{
		return NULL;
	}

	return HawkFindNextSignature(region, regionSize, compiled, length, previousMatch);
}

ULONG HawkCountPatternHits(
	const UCHAR* region,
	SIZE_T regionSize,
	const CHAR* text,
	ULONG maxHits)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG length;

	if (!HawkParsePattern(text, compiled, HAWK_SIG_MAX, &length))
	{
		return 0;
	}

	return HawkCountSignatureHits(region, regionSize, compiled, length, maxHits);
}

const UCHAR* HawkFindMasked(
	const UCHAR* region,
	SIZE_T regionSize,
	const UCHAR* bytes,
	const UCHAR* masks,
	ULONG patternLength)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG i;

	if (bytes == NULL || masks == NULL ||
		patternLength == 0 || patternLength > HAWK_SIG_MAX)
	{
		return NULL;
	}

	for (i = 0; i < patternLength; i++)
	{
		compiled[i].value = bytes[i];
		compiled[i].mask = masks[i];
	}

	return HawkFindSignature(region, regionSize, compiled, patternLength);
}

BOOLEAN HawkReadMatchU32(
	const UCHAR* match,
	ULONG byteOffset,
	PULONG outValue)
{
	if (match == NULL || outValue == NULL)
	{
		return FALSE;
	}

	RtlCopyMemory(outValue, match + byteOffset, sizeof(*outValue));
	return TRUE;
}

BOOLEAN HawkReadMatchU64(
	const UCHAR* match,
	ULONG byteOffset,
	PUINT64 outValue)
{
	if (match == NULL || outValue == NULL)
	{
		return FALSE;
	}

	RtlCopyMemory(outValue, match + byteOffset, sizeof(*outValue));
	return TRUE;
}

static BOOLEAN CopySectionName(
	const CHAR* name,
	CHAR outName[IMAGE_SIZEOF_SHORT_NAME])
{
	SIZE_T i;

	if (name == NULL || outName == NULL || name[0] == '\0')
	{
		return FALSE;
	}

	RtlZeroMemory(outName, IMAGE_SIZEOF_SHORT_NAME);
	for (i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++)
	{
		if (name[i] == '\0')
		{
			return TRUE;
		}
		outName[i] = name[i];
	}

	return (name[i] == '\0');
}

static BOOLEAN GetNtHeaders(
	const UCHAR* imageBase,
	const IMAGE_NT_HEADERS** ntHeaders)
{
	const IMAGE_DOS_HEADER* dosHeader;
	ULONG ntOffset;
	const IMAGE_NT_HEADERS* headers;

	if (imageBase == NULL || ntHeaders == NULL)
	{
		return FALSE;
	}

	dosHeader = (const IMAGE_DOS_HEADER*)imageBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	ntOffset = (ULONG)dosHeader->e_lfanew;
	if (ntOffset < sizeof(IMAGE_DOS_HEADER) || ntOffset > 0x1000)
	{
		return FALSE;
	}

	headers = (const IMAGE_NT_HEADERS*)(imageBase + ntOffset);
	if (headers->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	if (headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return FALSE;
	}
	if (headers->OptionalHeader.SizeOfImage == 0)
	{
		return FALSE;
	}

	*ntHeaders = headers;
	return TRUE;
}

static BOOLEAN GetImageSectionRange(
	const UCHAR* imageBase,
	const CHAR* sectionName,
	const UCHAR** outStart,
	SIZE_T* outSize)
{
	const IMAGE_NT_HEADERS* ntHeaders;
	const IMAGE_SECTION_HEADER* section;
	USHORT sectionCount;
	USHORT i;
	CHAR expectedName[IMAGE_SIZEOF_SHORT_NAME];
	ULONG sizeOfImage;
	ULONG headersSize;
	ULONG sectionsOffset;
	ULONG sectionsBytes;

	if (outStart != NULL)
	{
		*outStart = NULL;
	}
	if (outSize != NULL)
	{
		*outSize = 0;
	}

	if (imageBase == NULL || !CopySectionName(sectionName, expectedName))
	{
		return FALSE;
	}

	if (!GetNtHeaders(imageBase, &ntHeaders))
	{
		return FALSE;
	}

	sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	headersSize = ntHeaders->OptionalHeader.SizeOfHeaders;
	sectionCount = ntHeaders->FileHeader.NumberOfSections;
	section = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)ntHeaders);
	sectionsOffset = (ULONG)((const UCHAR*)section - imageBase);
	sectionsBytes = (ULONG)sectionCount * sizeof(IMAGE_SECTION_HEADER);

	if (sectionCount == 0 ||
		sectionsOffset >= sizeOfImage ||
		sectionsBytes > sizeOfImage - sectionsOffset ||
		(headersSize != 0 && sectionsOffset >= headersSize))
	{
		return FALSE;
	}

	for (i = 0; i < sectionCount; i++)
	{
		ULONG sectionRva;
		ULONG sectionSize;
		ULONG maxSize;

		if (!RtlEqualMemory(section[i].Name, expectedName, IMAGE_SIZEOF_SHORT_NAME))
		{
			continue;
		}

		sectionRva = section[i].VirtualAddress;
		sectionSize = section[i].Misc.VirtualSize;
		if (sectionRva >= sizeOfImage || sectionSize == 0)
		{
			return FALSE;
		}

		maxSize = sizeOfImage - sectionRva;
		if (sectionSize > maxSize)
		{
			sectionSize = maxSize;
		}

		if (outStart != NULL)
		{
			*outStart = imageBase + sectionRva;
		}
		if (outSize != NULL)
		{
			*outSize = sectionSize;
		}
		return TRUE;
	}

	return FALSE;
}

ULONG_PTR HawkFindSignatureInImageSection(
	const VOID* imageBase,
	const CHAR* sectionName,
	const HAWK_SIG_BYTE* signature,
	ULONG length)
{
	const UCHAR* sectionStart;
	SIZE_T sectionSize;
	const UCHAR* hit;

	if (!GetImageSectionRange((const UCHAR*)imageBase, sectionName, &sectionStart, &sectionSize))
	{
		return 0;
	}

	hit = HawkFindSignature(sectionStart, sectionSize, signature, length);
	if (hit == NULL)
	{
		return 0;
	}

	return (ULONG_PTR)hit;
}

ULONG_PTR HawkFindPatternInImageSectionFrom(
	const VOID* imageBase,
	const CHAR* sectionName,
	const CHAR* pattern,
	SIZE_T startOffset)
{
	HAWK_SIG_BYTE compiled[HAWK_SIG_MAX];
	ULONG patternLength;
	const UCHAR* sectionStart;
	SIZE_T sectionSize;
	const UCHAR* hit;

	if (!HawkParsePattern(pattern, compiled, HAWK_SIG_MAX, &patternLength))
	{
		return 0;
	}

	if (!GetImageSectionRange((const UCHAR*)imageBase, sectionName, &sectionStart, &sectionSize))
	{
		return 0;
	}

	hit = HawkFindSignatureFrom(sectionStart, sectionSize, compiled, patternLength, startOffset);
	if (hit == NULL)
	{
		return 0;
	}

	return (ULONG_PTR)hit;
}

ULONG_PTR HawkFindPatternInImageSection(
	const VOID* imageBase,
	const CHAR* sectionName,
	const CHAR* pattern)
{
	return HawkFindPatternInImageSectionFrom(imageBase, sectionName, pattern, 0);
}

ULONG_PTR HawkFindPatternInModule(
	const CHAR* moduleName,
	const CHAR* sectionName,
	const CHAR* pattern)
{
	return HawkFindPatternInImageSection(
		HawkGetKernelModuleBase(moduleName, NULL),
		sectionName,
		pattern);
}
