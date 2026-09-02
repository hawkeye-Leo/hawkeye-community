#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string.h>

#include "hawk_hot_targets.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

static const WCHAR kTargetTitle[] = L"Hawkeye Lab target -- do not close";
static const WCHAR kTargetFileName[] = L"Hawkeye Lab target -- do not close.txt";
static const WCHAR kNotepadSys[] = L"C:\\Windows\\System32\\notepad.exe";
static const WCHAR kNotepadWin[] = L"C:\\Windows\\notepad.exe";

static void EnableDebugPrivilege(void)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES privileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		return;
	}

	RtlZeroMemory(&privileges, sizeof(privileges));
	if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
	}

	CloseHandle(token);
}

static void CopyNarrow(CHAR* dst, size_t dstChars, const char* src)
{
	size_t i;

	if (dst == NULL || dstChars == 0) {
		return;
	}

	if (src == NULL) {
		dst[0] = '\0';
		return;
	}

	for (i = 0; i + 1 < dstChars && src[i] != '\0'; ++i) {
		dst[i] = src[i];
	}
	dst[i] = '\0';
}

static BOOL IsNotepadImage(const WCHAR* path)
{
	const WCHAR* name;

	if (path == NULL || path[0] == L'\0') {
		return FALSE;
	}

	name = wcsrchr(path, L'\\');
	name = (name == NULL) ? path : (name + 1);
	return _wcsicmp(name, L"notepad.exe") == 0;
}

static BOOL ProcessImageIsNotepad(DWORD pid)
{
	HANDLE process;
	WCHAR path[MAX_PATH];
	DWORD pathChars;

	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (process == NULL) {
		return FALSE;
	}

	pathChars = ARRAYSIZE(path);
	if (!QueryFullProcessImageNameW(process, 0, path, &pathChars)) {
		CloseHandle(process);
		return FALSE;
	}

	CloseHandle(process);
	return IsNotepadImage(path);
}

struct FindWindowByPidContext
{
	DWORD pid;
	HWND hwnd;
};

static BOOL CALLBACK FindVisibleWindowByPid(HWND hwnd, LPARAM lp)
{
	struct FindWindowByPidContext* ctx = (struct FindWindowByPidContext*)lp;
	DWORD windowPid = 0;

	if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != NULL) {
		return TRUE;
	}

	GetWindowThreadProcessId(hwnd, &windowPid);
	if (windowPid == ctx->pid) {
		ctx->hwnd = hwnd;
		return FALSE;
	}

	return TRUE;
}

static HWND FindVisibleWindowForPid(DWORD pid)
{
	struct FindWindowByPidContext ctx;

	RtlZeroMemory(&ctx, sizeof(ctx));
	ctx.pid = pid;
	EnumWindows(FindVisibleWindowByPid, (LPARAM)&ctx);
	return ctx.hwnd;
}

struct FindTargetPidContext
{
	DWORD pid;
};

static BOOL CALLBACK FindTargetTitleWindow(HWND hwnd, LPARAM lp)
{
	struct FindTargetPidContext* ctx = (struct FindTargetPidContext*)lp;
	WCHAR title[256];
	DWORD windowPid = 0;

	if (!IsWindowVisible(hwnd)) {
		return TRUE;
	}
	if (GetWindowTextW(hwnd, title, ARRAYSIZE(title)) <= 0) {
		return TRUE;
	}
	if (wcsstr(title, kTargetTitle) == NULL) {
		return TRUE;
	}

	GetWindowThreadProcessId(hwnd, &windowPid);
	if (windowPid != 0 && ProcessImageIsNotepad(windowPid)) {
		ctx->pid = windowPid;
		return FALSE;
	}

	return TRUE;
}

static DWORD FindExistingTargetPid(void)
{
	struct FindTargetPidContext ctx;

	RtlZeroMemory(&ctx, sizeof(ctx));
	EnumWindows(FindTargetTitleWindow, (LPARAM)&ctx);
	return ctx.pid;
}

static BOOL SnapshotNotepadPids(DWORD* pids, DWORD maxCount, DWORD* countOut)
{
	HANDLE snap;
	PROCESSENTRY32W entry;
	DWORD count = 0;

	if (countOut == NULL) {
		return FALSE;
	}

	*countOut = 0;
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	RtlZeroMemory(&entry, sizeof(entry));
	entry.dwSize = sizeof(entry);
	if (Process32FirstW(snap, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, L"notepad.exe") == 0) {
				if (count < maxCount) {
					pids[count] = entry.th32ProcessID;
				}
				count++;
			}
		} while (Process32NextW(snap, &entry));
	}

	CloseHandle(snap);
	*countOut = (count > maxCount) ? maxCount : count;
	return TRUE;
}

static BOOL PidInList(DWORD pid, const DWORD* pids, DWORD count)
{
	DWORD i;

	for (i = 0; i < count; ++i) {
		if (pids[i] == pid) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL WriteTargetNoteFile(WCHAR* pathOut, DWORD pathChars)
{
	WCHAR dir[MAX_PATH];
	DWORD dirLen;
	HANDLE file;
	const char body[] =
		"Hawkeye Lab target -- do not close.\r\n"
		"Do not close this window while analysis is running.\r\n";
	DWORD written = 0;

	if (pathOut == NULL || pathChars == 0) {
		return FALSE;
	}

	pathOut[0] = L'\0';
	dirLen = GetTempPathW(ARRAYSIZE(dir), dir);
	if (dirLen == 0 || dirLen >= ARRAYSIZE(dir)) {
		return FALSE;
	}
	if ((DWORD)(lstrlenW(dir) + lstrlenW(kTargetFileName) + 1) > pathChars) {
		return FALSE;
	}

	lstrcpynW(pathOut, dir, pathChars);
	if (lstrcatW(pathOut, kTargetFileName) == NULL) {
		return FALSE;
	}

	file = CreateFileW(
		pathOut,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	WriteFile(file, body, (DWORD)strlen(body), &written, NULL);
	CloseHandle(file);
	return TRUE;
}

static BOOL LaunchNotepadProcess(const WCHAR* notepadPath, const WCHAR* filePath, PROCESS_INFORMATION* pi)
{
	STARTUPINFOW si;
	WCHAR cmdLine[MAX_PATH * 3];

	if (notepadPath == NULL || pi == NULL) {
		return FALSE;
	}

	RtlZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;
	RtlZeroMemory(pi, sizeof(*pi));

	if (filePath != NULL && filePath[0] != L'\0') {
		if (swprintf_s(
				cmdLine,
				ARRAYSIZE(cmdLine),
				L"\"%s\" \"%s\"",
				notepadPath,
				filePath) < 0) {
			return FALSE;
		}
		return CreateProcessW(notepadPath, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, pi);
	}

	return CreateProcessW(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, pi);
}

static BOOL LaunchNotepad(DWORD* pidOut)
{
	DWORD before[64];
	DWORD beforeCount = 0;
	DWORD after[64];
	DWORD afterCount = 0;
	PROCESS_INFORMATION pi;
	WCHAR cmdPath[MAX_PATH];
	WCHAR filePath[MAX_PATH];
	HWND hwnd = NULL;
	DWORD i;
	DWORD attempt;
	BOOL haveFile;
	const WCHAR* notePath;

	if (pidOut == NULL) {
		return FALSE;
	}

	*pidOut = 0;
	SnapshotNotepadPids(before, ARRAYSIZE(before), &beforeCount);
	haveFile = WriteTargetNoteFile(filePath, ARRAYSIZE(filePath));
	notePath = haveFile ? filePath : NULL;

	lstrcpynW(cmdPath, kNotepadSys, ARRAYSIZE(cmdPath));
	if (!LaunchNotepadProcess(cmdPath, notePath, &pi)) {
		lstrcpynW(cmdPath, kNotepadWin, ARRAYSIZE(cmdPath));
		if (!LaunchNotepadProcess(cmdPath, notePath, &pi)) {
			lstrcpynW(cmdPath, kNotepadSys, ARRAYSIZE(cmdPath));
			if (!LaunchNotepadProcess(cmdPath, NULL, &pi)) {
				lstrcpynW(cmdPath, kNotepadWin, ARRAYSIZE(cmdPath));
				if (!LaunchNotepadProcess(cmdPath, NULL, &pi)) {
					return FALSE;
				}
			}
		}
	}

	WaitForInputIdle(pi.hProcess, 4000);

	for (attempt = 0; attempt < 40; ++attempt) {
		Sleep(100);
		hwnd = FindVisibleWindowForPid(pi.dwProcessId);
		if (hwnd != NULL) {
			*pidOut = pi.dwProcessId;
			break;
		}

		SnapshotNotepadPids(after, ARRAYSIZE(after), &afterCount);
		for (i = 0; i < afterCount; ++i) {
			if (!PidInList(after[i], before, beforeCount)) {
				hwnd = FindVisibleWindowForPid(after[i]);
				if (hwnd != NULL) {
					*pidOut = after[i];
					break;
				}
			}
		}
		if (*pidOut != 0) {
			break;
		}
	}

	if (*pidOut == 0) {
		*pidOut = pi.dwProcessId;
		hwnd = FindVisibleWindowForPid(*pidOut);
	}

	if (hwnd != NULL) {
		SetWindowTextW(hwnd, kTargetTitle);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return *pidOut != 0;
}

static BOOL OpenTargetProcess(DWORD pid, HANDLE* processOut)
{
	HANDLE process;

	if (processOut == NULL || pid == 0) {
		return FALSE;
	}

	process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (process == NULL) {
		return FALSE;
	}

	*processOut = process;
	return TRUE;
}

static BOOL FindModuleBase(
	HANDLE process,
	const char* fileName,
	ULONG64* baseOut)
{
	HMODULE modules[256];
	DWORD bytesNeeded = 0;
	DWORD moduleCount;
	DWORD i;
	char name[MAX_PATH];

	if (baseOut == NULL) {
		return FALSE;
	}

	*baseOut = 0;
	if (!EnumProcessModules(process, modules, sizeof(modules), &bytesNeeded)) {
		return FALSE;
	}

	moduleCount = bytesNeeded / sizeof(HMODULE);
	if (moduleCount > ARRAYSIZE(modules)) {
		moduleCount = ARRAYSIZE(modules);
	}

	for (i = 0; i < moduleCount; ++i) {
		RtlZeroMemory(name, sizeof(name));
		if (GetModuleBaseNameA(process, modules[i], name, ARRAYSIZE(name)) == 0) {
			continue;
		}
		if (_stricmp(name, fileName) == 0) {
			*baseOut = (ULONG64)(ULONG_PTR)modules[i];
			return TRUE;
		}
	}

	return FALSE;
}

static void AddTarget(
	HAWK_HOT_TARGETS* out,
	ULONG64 va,
	ULONG size,
	const char* name,
	const char* note)
{
	HAWK_HOT_TARGET* item;

	if (out->count >= HAWK_HOT_TARGETS_MAX) {
		return;
	}

	item = &out->items[out->count];
	RtlZeroMemory(item, sizeof(*item));
	item->va = va;
	item->size = size;
	CopyNarrow(item->name, HAWK_HOT_NAME_CHARS, name);
	CopyNarrow(item->note, HAWK_HOT_NOTE_CHARS, note);
	out->count++;
}

__declspec(dllexport) BOOL WINAPI HawkHotTargetsQuery(HAWK_HOT_TARGETS* out)
{
	HANDLE process = NULL;
	ULONG64 notepadBase = 0;
	ULONG64 ntdllBase = 0;
	BOOL ok = FALSE;

	if (out == NULL) {
		return FALSE;
	}

	RtlZeroMemory(out, sizeof(*out));
	out->version = HAWK_HOT_TARGETS_ABI;

	EnableDebugPrivilege();

	out->pid = FindExistingTargetPid();
	if (out->pid != 0 && !OpenTargetProcess(out->pid, &process)) {
		out->pid = 0;
	}

	if (out->pid == 0) {
		if (!LaunchNotepad(&out->pid)) {
			return FALSE;
		}
		if (!OpenTargetProcess(out->pid, &process)) {
			return FALSE;
		}
	}

	if (FindModuleBase(process, "notepad.exe", &notepadBase) && notepadBase != 0) {
		AddTarget(
			out,
			notepadBase,
			0x1000,
			"notepad.exe PE",
			"Image base of notepad.exe (MZ/PE header page)");
	}

	if (FindModuleBase(process, "ntdll.dll", &ntdllBase) && ntdllBase != 0) {
		AddTarget(
			out,
			ntdllBase,
			0x1000,
			"ntdll.dll PE",
			"ntdll.dll image base inside the target (MZ/PE header page)");
	}

	ok = (out->count == 2);
	CloseHandle(process);
	return ok;
}
