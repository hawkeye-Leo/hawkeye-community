#include "callback_experiment.h"
#include "Driver.h"
#include <cstring>
#include <intrin.h>

namespace {

/*
 * Landing stub (PreCall) — sysret lands here with rax = TargetFunction.
 * Loads x64 home-slot args from the synthetic user stack, skips 0x48 bytes
 * (past home slots to the PostCall return address slot), then jmp rax.
 *
 *   mov rcx, [rsp+20h]    ; arg1 (HawkFillUserSyntheticStack +0x20)
 *   mov rdx, [rsp+28h]    ; arg2
 *   mov r8,  [rsp+30h]    ; arg3
 *   mov r9,  [rsp+38h]    ; arg4
 *   add rsp, 48h          ; rsp -> synth+0x48 (PostCall VA sits here for target ret)
 *   jmp rax               ; rax = callData[2] = TargetFunction (e.g. GDI)
 */
static const unsigned char kLandingStubBytes[] = {
	0x48, 0x8B, 0x4C, 0x24, 0x20, // mov rcx, [rsp+20h]
	0x48, 0x8B, 0x54, 0x24, 0x28, // mov rdx, [rsp+28h]
	0x4C, 0x8B, 0x44, 0x24, 0x30, // mov r8,  [rsp+30h]
	0x4C, 0x8B, 0x4C, 0x24, 0x38, // mov r9,  [rsp+38h]
	0x48, 0x83, 0xC4, 0x48,       // add rsp, 48h
	0xFF, 0xE0                    // jmp rax
};

/*
 * ntdll .text scan pattern for KiUserCallForwarder-style prologue (optional).
 * Mask "xxxx?xxxx?x" — bytes marked 0x00 are wildcards (disp8 may vary).
 *
 *   mov rcx, [rsp+??h]
 *   mov rdx, [rsp+??h]
 *   ... (4C = start of next mov r8/r9 opcode)
 */
static const unsigned char kForwarderPattern[] = {
	0x48, 0x8B, 0x4C, 0x24, 0x00, // mov rcx, [rsp+??h]
	0x48, 0x8B, 0x54, 0x24, 0x00, // mov rdx, [rsp+??h]
	0x4C                          // first byte of mov r8/r9, ...
};

/*
 * PostCall stub — target function ret's here; syscall NtCallbackReturn (index 5).
 * rax on entry = user function return value; stored to [rsp+20h] for kernel OutVar.
 *
 *   mov [rsp+20h], rax    ; save callback result qword
 *   lea rcx, [rsp+20h]    ; NtCallbackReturn OutputBuffer
 *   mov edx, 8            ; OutputLength = sizeof(ULONG64)
 *   xor r8d, r8d          ; Status / third arg = 0
 *   push 0                ; stack alignment before syscall
 *   mov r10, rcx          ; syscall ABI: r10 = rcx
 *   mov eax, 5            ; syscall number = NtCallbackReturn
 *   syscall
 *   int 3                 ; should not return (kernel resumes via NtCallbackReturn path)
 */
static const unsigned char kPostCallStubBytes[] = {
	0x48, 0x89, 0x44, 0x24, 0x20, // mov [rsp+20h], rax
	0x48, 0x8D, 0x4C, 0x24, 0x20, // lea rcx, [rsp+20h]
	0xBA, 0x08, 0x00, 0x00, 0x00, // mov edx, 8
	0x45, 0x33, 0xC0,             // xor r8d, r8d
	0x6A, 0x00,                   // push 0
	0x4C, 0x8B, 0xD1,             // mov r10, rcx
	0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
	0x0F, 0x05,                   // syscall
	0xCC                          // int 3
};

static void* g_landingEntry = nullptr;
static void* g_customLandingPage = nullptr;
static void* g_postCallRoutine = nullptr;
static bool g_driverRegistered = false;

static const unsigned char* FindPatternWithWildcards(
	const unsigned char* base,
	size_t size,
	const unsigned char* pattern,
	const char* mask,
	size_t patternSize)
{
	if (base == nullptr || pattern == nullptr || mask == nullptr || patternSize == 0 || size < patternSize)
	{
		return nullptr;
	}

	for (size_t i = 0; i + patternSize <= size; ++i)
	{
		bool matched = true;
		for (size_t j = 0; j < patternSize; ++j)
		{
			if (mask[j] == 'x' && base[i + j] != pattern[j])
			{
				matched = false;
				break;
			}
		}

		if (matched)
		{
			return base + i;
		}
	}

	return nullptr;
}

static void* ScanModuleText(HMODULE moduleHandle, const unsigned char* pattern, const char* mask, size_t patternSize)
{
	if (moduleHandle == nullptr)
	{
		return nullptr;
	}

	const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleHandle);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return nullptr;
	}

	const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
		reinterpret_cast<const unsigned char*>(moduleHandle) + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
	{
		return nullptr;
	}

	const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (memcmp(section->Name, ".text", 5) != 0)
		{
			continue;
		}

		const auto textBase = reinterpret_cast<const unsigned char*>(moduleHandle) + section->VirtualAddress;
		const size_t textSize = section->Misc.VirtualSize;
		const unsigned char* hit = FindPatternWithWildcards(
			textBase,
			textSize,
			pattern,
			mask,
			patternSize);
		if (hit != nullptr)
		{
			return const_cast<unsigned char*>(hit);
		}
	}

	return nullptr;
}

static bool EnsureCustomLandingPage()
{
	if (g_customLandingPage != nullptr)
	{
		return true;
	}

	g_customLandingPage = VirtualAlloc(
		nullptr,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (g_customLandingPage == nullptr)
	{
		return false;
	}

	memcpy(g_customLandingPage, kLandingStubBytes, sizeof(kLandingStubBytes));
	FlushInstructionCache(GetCurrentProcess(), g_customLandingPage, sizeof(kLandingStubBytes));
	return true;
}

static bool EnsureLandingEntry()
{
	if (g_landingEntry != nullptr)
	{
		return true;
	}

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == nullptr)
	{
		ntdll = LoadLibraryW(L"ntdll.dll");
	}

	if (ntdll != nullptr)
	{
		g_landingEntry = ScanModuleText(
			ntdll,
			kForwarderPattern,
			"xxxx?xxxx?x",
			sizeof(kForwarderPattern));
	}

	if (g_landingEntry == nullptr && EnsureCustomLandingPage())
	{
		g_landingEntry = g_customLandingPage;
	}

	return g_landingEntry != nullptr;
}

static bool EnsurePostCallRoutine()
{
	if (g_postCallRoutine == nullptr)
	{
		g_postCallRoutine = VirtualAlloc(
			nullptr,
			4096,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		if (g_postCallRoutine == nullptr)
		{
			return false;
		}
	}

	memcpy(g_postCallRoutine, kPostCallStubBytes, sizeof(kPostCallStubBytes));
	FlushInstructionCache(GetCurrentProcess(), g_postCallRoutine, sizeof(kPostCallStubBytes));
	return true;
}

static bool BuildUserStubs()
{
	return EnsureLandingEntry() && EnsurePostCallRoutine();
}

static bool RegisterWithDriver()
{
	if (g_driverRegistered)
	{
		return true;
	}

	USERMODE_CALLBACK_INIT initRequest = {};
	initRequest.landingStub = reinterpret_cast<ULONG64>(g_landingEntry);
	initRequest.postCallRoutine = reinterpret_cast<ULONG64>(g_postCallRoutine);

	UsermodeCallbackInit(&initRequest);
	if (initRequest.errCode != 0)
	{
		return false;
	}

	g_driverRegistered = true;
	return true;
}

static bool InvokeCallbackCall6(
	ULONG64 targetFunction,
	ULONG64 arg1,
	ULONG64 arg2,
	ULONG64 arg3,
	ULONG64 arg4,
	ULONG64 arg5,
	ULONG64 arg6,
	PUSERMODE_CALLBACK_CALL6 outResult)
{
	if (outResult == nullptr)
	{
		return false;
	}

	ZeroMemory(outResult, sizeof(*outResult));
	outResult->targetFunction = targetFunction;
	outResult->arg1 = arg1;
	outResult->arg2 = arg2;
	outResult->arg3 = arg3;
	outResult->arg4 = arg4;
	outResult->arg5 = arg5;
	outResult->arg6 = arg6;

	UsermodeCallbackCall6(outResult);
	return outResult->errCode == 0;
}

} // namespace

extern "C" BOOL CallbackExperimentQueryPebDebug(PCALLBACK_PEB_DEBUG outDebug)
{
	if (outDebug == nullptr)
	{
		return FALSE;
	}

	ZeroMemory(outDebug, sizeof(*outDebug));

	outDebug->processId = GetCurrentProcessId();

#ifdef _WIN64
	outDebug->tebSelf = __readgsqword(0x30);
	outDebug->peb = __readgsqword(0x60);
#else
	outDebug->tebSelf = __readfsdword(0x18);
	outDebug->peb = __readfsdword(0x30);
#endif

	if (outDebug->peb != 0)
	{
		const auto pebBytes = reinterpret_cast<const unsigned char*>(outDebug->peb);
		outDebug->kernelCallbackTable = *reinterpret_cast<const ULONG64*>(pebBytes + 0x58);

		if (outDebug->kernelCallbackTable != 0)
		{
			const auto table = reinterpret_cast<const ULONG64*>(outDebug->kernelCallbackTable);
			outDebug->tableEntry0 = table[0];
			outDebug->tableEntry2 = table[2];
		}
	}

	const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll != nullptr)
	{
		outDebug->kiUserCallbackDispatcher =
			reinterpret_cast<ULONG64>(GetProcAddress(ntdll, "KiUserCallbackDispatcher"));
		outDebug->kiUserCallForwarder =
			reinterpret_cast<ULONG64>(GetProcAddress(ntdll, "KiUserCallForwarder"));
	}

	return TRUE;
}

extern "C" BOOL CallbackExperimentEnsureReady(void)
{
	if (!TestDrv())
	{
		return FALSE;
	}

	if (!BuildUserStubs())
	{
		return FALSE;
	}

	if (!RegisterWithDriver())
	{
		return FALSE;
	}

	return TRUE;
}

extern "C" BOOL CallbackExperimentDrawTestRect(
	HWND hwnd,
	LONG left,
	LONG top,
	LONG right,
	LONG bottom,
	PDRAW_TEST_GDI_REQUEST outResult)
{
	if (outResult == nullptr)
	{
		return FALSE;
	}

	ZeroMemory(outResult, sizeof(*outResult));

	if (!CallbackExperimentEnsureReady())
	{
		outResult->errCode = DRAW_TEST_ERR_NOT_INITIALIZED;
		return FALSE;
	}

	HMODULE user32 = GetModuleHandleW(L"user32.dll");
	if (user32 == nullptr)
	{
		user32 = LoadLibraryW(L"user32.dll");
	}

	HMODULE gdi32 = GetModuleHandleW(L"gdi32.dll");
	if (gdi32 == nullptr)
	{
		gdi32 = LoadLibraryW(L"gdi32.dll");
	}

	if (user32 == nullptr || gdi32 == nullptr)
	{
		outResult->errCode = DRAW_TEST_ERR_BAD_PARAMETER;
		return FALSE;
	}

	const ULONG64 pfnGetDC = reinterpret_cast<ULONG64>(GetProcAddress(user32, "GetDC"));
	const ULONG64 pfnReleaseDC = reinterpret_cast<ULONG64>(GetProcAddress(user32, "ReleaseDC"));
	const ULONG64 pfnCreateSolidBrush = reinterpret_cast<ULONG64>(GetProcAddress(gdi32, "CreateSolidBrush"));
	const ULONG64 pfnGetStockObject = reinterpret_cast<ULONG64>(GetProcAddress(gdi32, "GetStockObject"));
	const ULONG64 pfnSelectObject = reinterpret_cast<ULONG64>(GetProcAddress(gdi32, "SelectObject"));
	const ULONG64 pfnRectangle = reinterpret_cast<ULONG64>(GetProcAddress(gdi32, "Rectangle"));
	const ULONG64 pfnDeleteObject = reinterpret_cast<ULONG64>(GetProcAddress(gdi32, "DeleteObject"));

	outResult->hwnd = reinterpret_cast<ULONG64>(hwnd);
	outResult->pfnGetDC = pfnGetDC;
	outResult->pfnReleaseDC = pfnReleaseDC;
	outResult->pfnCreatePen = pfnCreateSolidBrush;
	outResult->pfnSelectObject = pfnSelectObject;
	outResult->pfnRectangle = pfnRectangle;
	outResult->pfnDeleteObject = pfnDeleteObject;
	outResult->left = left;
	outResult->top = top;
	outResult->right = right;
	outResult->bottom = bottom;
	outResult->penWidth = 0;
	outResult->colorRef = RGB(255, 0, 0);

	if (pfnGetDC == 0 || pfnReleaseDC == 0 || pfnCreateSolidBrush == 0 ||
		pfnGetStockObject == 0 || pfnSelectObject == 0 || pfnRectangle == 0 || pfnDeleteObject == 0)
	{
		outResult->errCode = DRAW_TEST_ERR_BAD_PARAMETER;
		return FALSE;
	}

	USERMODE_CALLBACK_CALL6 callResult = {};

	if (!InvokeCallbackCall6(pfnGetDC, reinterpret_cast<ULONG64>(hwnd), 0, 0, 0, 0, 0, &callResult))
	{
		outResult->errCode = DRAW_TEST_ERR_GETDC;
		outResult->lastGdiResult = callResult.returnValue;
		return FALSE;
	}

	ULONG64 deviceContext = callResult.returnValue;
	outResult->lastGdiResult = deviceContext;
	if (deviceContext == 0)
	{
		outResult->errCode = DRAW_TEST_ERR_GETDC;
		return FALSE;
	}

	if (!InvokeCallbackCall6(pfnCreateSolidBrush, outResult->colorRef, 0, 0, 0, 0, 0, &callResult))
	{
		outResult->errCode = DRAW_TEST_ERR_CREATEBRUSH;
		return FALSE;
	}

	ULONG64 brushHandle = callResult.returnValue;
	outResult->lastGdiResult = brushHandle;
	if (brushHandle == 0)
	{
		outResult->errCode = DRAW_TEST_ERR_CREATEBRUSH;
		return FALSE;
	}

	/* NULL_PEN = 8 — fill only, no outline */
	if (!InvokeCallbackCall6(pfnGetStockObject, 8, 0, 0, 0, 0, 0, &callResult))
	{
		outResult->errCode = DRAW_TEST_ERR_BAD_PARAMETER;
		return FALSE;
	}

	ULONG64 nullPenHandle = callResult.returnValue;
	if (nullPenHandle == 0)
	{
		outResult->errCode = DRAW_TEST_ERR_BAD_PARAMETER;
		return FALSE;
	}

	InvokeCallbackCall6(pfnSelectObject, deviceContext, nullPenHandle, 0, 0, 0, 0, &callResult);
	InvokeCallbackCall6(pfnSelectObject, deviceContext, brushHandle, 0, 0, 0, 0, &callResult);
	InvokeCallbackCall6(
		pfnRectangle,
		deviceContext,
		static_cast<ULONG64>(static_cast<LONG>(left)),
		static_cast<ULONG64>(static_cast<LONG>(top)),
		static_cast<ULONG64>(static_cast<LONG>(right)),
		static_cast<ULONG64>(static_cast<LONG>(bottom)),
		0,
		&callResult);
	InvokeCallbackCall6(pfnDeleteObject, brushHandle, 0, 0, 0, 0, 0, &callResult);
	InvokeCallbackCall6(pfnReleaseDC, reinterpret_cast<ULONG64>(hwnd), deviceContext, 0, 0, 0, 0, &callResult);

	outResult->errCode = 0;
	outResult->status = 0;
	return TRUE;
}
