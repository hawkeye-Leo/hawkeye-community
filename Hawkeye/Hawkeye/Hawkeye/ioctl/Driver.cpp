#include "Driver.h"

#include <StrSafe.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

#define SYMBOLIC_LINK_NAME     L"\\\\.\\hawkeye123"

static DWORD g_lastDriverStartError = 0;
static DrvStartFailReason g_lastDriverStartReason = DrvStartOk;
static const char* g_lastDriverCompatRef = nullptr;
static HANDLE g_instanceMutex = NULL;
static const char kInstanceMutexName[] = "Hawkeye-community";

static HANDLE OpenHawkDevice()
{
	return CreateFileW(
		SYMBOLIC_LINK_NAME,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

BOOL HawkDeviceIoControl(
	DWORD ioctl,
	LPVOID inBuf,
	DWORD inSize,
	LPVOID outBuf,
	DWORD outSize)
{
	HANDLE handle = OpenHawkDevice();
	DWORD bytesReturned = 0;
	BOOL ok = FALSE;

	if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	ok = DeviceIoControl(handle, ioctl, inBuf, inSize, outBuf, outSize, &bytesReturned, NULL);
	CloseHandle(handle);
	return ok;
}

static SC_HANDLE OpenSCMRetry();
static bool CreateDriverService(LPCWSTR svcName, LPCWSTR imagePath);
static bool StartDriverService(LPCWSTR svcName);
static bool StartDriverService(LPCWSTR svcName, PDWORD outStartErrorCode);
static bool StopDriverService(LPCWSTR svcName);
static bool RemoveDriverService(LPCWSTR svcName);
static bool InstallKernelDriver(LPCWSTR svcName, LPCWSTR sysPath);
static DWORD AppendToLog(LPWSTR buf, DWORD bufChars, DWORD pos, LPCWSTR text);
static DWORD CaptureCommandOutput(LPCWSTR commandLine, LPWSTR capture, DWORD captureChars, LPDWORD outExitCode);


static bool InstallKernelDriver(LPCWSTR svcName, LPCWSTR sysPath)
{
	if (svcName == NULL || sysPath == NULL)
	{
		return false;
	}

	WCHAR fullImagePath[MAX_PATH] = { 0 };
	if (GetFullPathNameW(sysPath, MAX_PATH, fullImagePath, NULL) == 0)
	{
		return false;
	}

	return CreateDriverService(svcName, fullImagePath);
}


static SC_HANDLE OpenSCMRetry()
{
	SC_HANDLE scm = NULL;
	for (int i = 0; i < 5 && scm == NULL; i++)
	{
		scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (scm == NULL)
		{
			Sleep(80);
		}
	}
	return scm;
}

static bool CreateDriverService(
	LPCWSTR svcName,
	LPCWSTR imagePath)
{
	SC_HANDLE scm = OpenSCMRetry();
	if (scm == NULL)
	{
		return false;
	}

	SC_HANDLE svc = CreateServiceW(
		scm,
		svcName,
		svcName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		imagePath,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);

	bool ok = false;
	if (svc != NULL)
	{
		CloseServiceHandle(svc);
		ok = true;
	}
	else if (GetLastError() == ERROR_SERVICE_EXISTS)
	{
		ok = true;
	}

	CloseServiceHandle(scm);
	return ok;
}

static bool StartDriverService(LPCWSTR svcName)
{
	return StartDriverService(svcName, NULL);
}

static bool StartDriverService(LPCWSTR svcName, PDWORD outStartErrorCode)
{
	SC_HANDLE scm = OpenSCMRetry();
	if (scm == NULL)
	{
		return false;
	}

	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_ALL_ACCESS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		return false;
	}

	SERVICE_STATUS st;
	if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_RUNNING)
	{
		CloseServiceHandle(svc);
		CloseServiceHandle(scm);
		return true;
	}

	bool ok = false;
	if (StartService(svc, 0, NULL))
	{
		ok = true;
	}
	else
	{
		DWORD err = GetLastError();
		if (err == ERROR_SERVICE_ALREADY_RUNNING)
		{
			ok = true;
		}
		else if (outStartErrorCode != NULL)
		{
			*outStartErrorCode = err;
		}
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return ok;
}

static bool StopDriverService(LPCWSTR svcName)
{
	SC_HANDLE scm = OpenSCMRetry();
	if (scm == NULL)
	{
		return false;
	}

	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_ALL_ACCESS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		return false;
	}

	SERVICE_STATUS st;
	bool ok = ControlService(svc, SERVICE_CONTROL_STOP, &st) ? true : false;

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return ok;
}

static bool RemoveDriverService(LPCWSTR svcName)
{
	StopDriverService(svcName);

	SC_HANDLE scm = OpenSCMRetry();
	if (scm == NULL)
	{
		return false;
	}

	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_ALL_ACCESS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		return false;
	}

	bool ok = DeleteService(svc) ? true : false;

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return ok;
}

bool TestDrv()
{
	HANDLE handle = OpenHawkDevice();
	if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
		return false;
	}
	CloseHandle(handle);
	return true;
}

VOID InstallHawkDrv()
{
	InstallHawkDrvWithReason();
}

VOID UninstallHawkDrv()
{
	RemoveDriverService(L"HawkeyeDrv");
}

static ULONG NtStatusToWin32(NTSTATUS status)
{
	using RtlNtStatusToDosErrorFn = ULONG(WINAPI*)(NTSTATUS);
	static const auto fn = reinterpret_cast<RtlNtStatusToDosErrorFn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
	return fn ? fn(status) : static_cast<ULONG>(status);
}

static const char* CompatRefForStartError(DWORD errCode)
{
	struct Entry {
		NTSTATUS status;
		const char* ref;
	};

	static const Entry kTable[] = {
		{ STATUS_HAWK_NO_MIGETSYSTEMREGION, HAWK_COMPAT_REF_MIGETSYSTEMREGION },
		{ STATUS_HAWK_NO_PTE_BASE, HAWK_COMPAT_REF_PTE_BASE },
		{ STATUS_HAWK_NO_PFN_BASE, HAWK_COMPAT_REF_PFN_BASE },
	};

	for (const Entry& entry : kTable)
	{
		const DWORD asNt = static_cast<DWORD>(entry.status);
		if (errCode == asNt || errCode == NtStatusToWin32(entry.status))
		{
			return entry.ref;
		}
	}
	return nullptr;
}

static bool IsSignatureBlocked(DWORD errCode)
{
	if (errCode == 0)
	{
		return false;
	}
	return (errCode == 577)
		|| (errCode == 1275)
		|| (errCode == 2148204800)
		|| (errCode == 2148204811);
}

static DrvStartFailReason ClassifyDriverStartError(DWORD errCode)
{
	if (IsSignatureBlocked(errCode))
	{
		return DrvStartFailSignature;
	}
	if (CompatRefForStartError(errCode) != nullptr)
	{
		return DrvStartFailKernelLayout;
	}
	return DrvStartFailGeneric;
}

DrvStartFailReason InstallHawkDrvWithReason()
{
	g_lastDriverStartError = 0;
	g_lastDriverStartReason = DrvStartOk;
	g_lastDriverCompatRef = nullptr;

	WCHAR  wsPath[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, wsPath, MAX_PATH);
	PWCHAR p = wcsrchr(wsPath, '\\');
	if (!p)
	{
		g_lastDriverStartReason = DrvStartFailGeneric;
		return g_lastDriverStartReason;
	}

	memset(p, 0, wcslen(p) * sizeof(WCHAR));
	wcscat_s(wsPath, MAX_PATH, L"\\Hawkeye.sys");

	if (!InstallKernelDriver(L"HawkeyeDrv", wsPath))
	{
		g_lastDriverStartReason = DrvStartFailGeneric;
		return g_lastDriverStartReason;
	}

	DWORD startErr = 0;
	if (StartDriverService(L"HawkeyeDrv", &startErr))
	{
		g_lastDriverStartReason = DrvStartOk;
		return DrvStartOk;
	}

	g_lastDriverStartError = startErr;
	g_lastDriverCompatRef = CompatRefForStartError(startErr);
	g_lastDriverStartReason = ClassifyDriverStartError(startErr);
	return g_lastDriverStartReason;
}

DrvStartFailReason GetLastDriverStartFailReason()
{
	return g_lastDriverStartReason;
}

const char* GetLastDriverCompatRef()
{
	return g_lastDriverCompatRef;
}

DWORD GetLastDriverStartError()
{
	return g_lastDriverStartError;
}

VOID GetKernelVaRegion(KERNEL_VA_REGION* in, KERNEL_VA_REGION* out)
{
	HawkDeviceIoControl(
		IOCTL_GET_KERNEL_VA_MEMORY_REGION,
		in,
		sizeof(KERNEL_VA_REGION),
		out,
		sizeof(KERNEL_VA_REGION));
}


VOID  GetVirtualAddressPte(GET_VIRTUAL_ADDRESS_PTE* inout)
{
	if (inout == NULL) {
		return;
	}

	HawkDeviceIoControl(
		IOCTL_GET_VIRTUAL_ADDRESS_PTE,
		inout,
		sizeof(GET_VIRTUAL_ADDRESS_PTE),
		inout,
		sizeof(GET_VIRTUAL_ADDRESS_PTE));
}


VOID  GetVirtualAddressPfn(GET_VIRTUAL_ADDRESS_PFN* inout)
{
	if (inout == NULL) {
		return;
	}

	HawkDeviceIoControl(
		IOCTL_GET_VIRTUAL_ADDRESS_PFN,
		inout,
		sizeof(GET_VIRTUAL_ADDRESS_PFN),
		inout,
		sizeof(GET_VIRTUAL_ADDRESS_PFN));
}


VOID  OpenProcessHandle(OPEN_PROCESS_HANDLE* inout)
{
	if (inout == NULL) {
		return;
	}

	HawkDeviceIoControl(
		IOCTL_OPEN_PROCESS_HANDLE,
		inout,
		sizeof(OPEN_PROCESS_HANDLE),
		inout,
		sizeof(OPEN_PROCESS_HANDLE));
}


VOID  ReadProcessPage(READ_MEMORY_PAGES* in, READ_MEMORY_PAGES* out)
{
	HawkDeviceIoControl(
		IOCTL_READ_PROCESS_PAGE,
		in,
		sizeof(READ_MEMORY_PAGES),
		out,
		sizeof(READ_MEMORY_PAGES));
}


VOID GetModulePathByPid(GET_MODULE_PATH* inout)
{
	HawkDeviceIoControl(
		IOCTL_GET_MODULE_PATH_BY_PID,
		inout,
		sizeof(GET_MODULE_PATH),
		inout,
		sizeof(GET_MODULE_PATH));
}


VOID  CheckValidHwnd(CHECK_VALID_HWND* inout)
{
	HawkDeviceIoControl(
		IOCTL_CHECK_VALID_HWND,
		inout,
		sizeof(CHECK_VALID_HWND),
		inout,
		sizeof(CHECK_VALID_HWND));
}


VOID IGuardPitScan(IGUARD_PIT_SCAN* inout)
{
	if (inout == NULL) {
		return;
	}

	HawkDeviceIoControl(
		IOCTL_IGUARD_PIT_SCAN,
		inout,
		sizeof(IGUARD_PIT_SCAN),
		inout,
		sizeof(IGUARD_PIT_SCAN));
}


void SetHawkeyeInstanceMutex(HANDLE mutex)
{
	g_instanceMutex = mutex;
}

static void ReleaseHawkeyeInstanceMutex()
{
	if (g_instanceMutex != NULL)
	{
		CloseHandle(g_instanceMutex);
		g_instanceMutex = NULL;
	}
}

static void RecreateHawkeyeInstanceMutex()
{
	g_instanceMutex = CreateMutexA(NULL, FALSE, kInstanceMutexName);
}

bool RestartHawkeyeAsAdministrator()
{
	WCHAR path[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0)
	{
		return false;
	}

	ReleaseHawkeyeInstanceMutex();

	SHELLEXECUTEINFOW sei;
	ZeroMemory(&sei, sizeof(sei));
	sei.cbSize = sizeof(sei);
	sei.lpVerb = L"runas";
	sei.lpFile = path;
	sei.nShow = SW_SHOWNORMAL;
	if (!ShellExecuteExW(&sei))
	{
		RecreateHawkeyeInstanceMutex();
		return false;
	}
	return true;
}

bool IsRunningAsAdmin()
{
	BOOL isAdmin = FALSE;
	SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
	PSID adminGroup = NULL;

	if (AllocateAndInitializeSid(&auth, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &adminGroup))
	{
		if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
		{
			isAdmin = FALSE;
		}
		FreeSid(adminGroup);
	}
	return isAdmin ? true : false;
}

bool IsSecureBootEnabled()
{
	HKEY hKey = NULL;
	DWORD value = 0;
	DWORD size = sizeof(value);

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
		0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueExW(hKey, L"UEFISecureBootEnabled", NULL, NULL,
			(LPBYTE)&value, &size);
		RegCloseKey(hKey);
	}
	return value != 0;
}

static DWORD AppendToLog(LPWSTR buf, DWORD bufChars, DWORD pos, LPCWSTR text)
{
	if (buf == NULL || bufChars == 0 || text == NULL)
	{
		return pos;
	}
	size_t textLen = wcslen(text);
	if (pos >= bufChars)
	{
		return pos;
	}
	DWORD available = bufChars - pos - 1;
	DWORD toCopy = (DWORD)(textLen < available ? textLen : available);
	if (toCopy > 0)
	{
		memcpy(buf + pos, text, toCopy * sizeof(WCHAR));
	}
	pos += toCopy;
	buf[pos] = L'\0';
	return pos;
}

static DWORD CaptureCommandOutput(LPCWSTR commandLine, LPWSTR capture, DWORD captureChars, LPDWORD outExitCode)
{
	DWORD exitCode = (DWORD)-1;
	if (outExitCode != NULL)
	{
		*outExitCode = (DWORD)-1;
	}
	if (capture != NULL && captureChars > 0)
	{
		capture[0] = L'\0';
	}

	WCHAR cmdLineCopy[4096];
	if (commandLine == NULL)
	{
		return 0;
	}
	size_t cmdLen = wcslen(commandLine);
	if (cmdLen >= _countof(cmdLineCopy))
	{
		return 0;
	}
	memcpy(cmdLineCopy, commandLine, (cmdLen + 1) * sizeof(WCHAR));

	HANDLE hReadPipe = NULL;
	HANDLE hWritePipe = NULL;
	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
	{
		return 0;
	}
	SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = hWritePipe;
	si.hStdError = hWritePipe;

	BOOL createOk = CreateProcessW(
		NULL,
		cmdLineCopy,
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi);

	CloseHandle(hWritePipe);

	if (!createOk)
	{
		CloseHandle(hReadPipe);
		if (outExitCode != NULL)
		{
			*outExitCode = GetLastError();
		}
		return 0;
	}

	DWORD pos = 0;
	char readBuf[2048];
	DWORD bytesRead = 0;
	while (ReadFile(hReadPipe, readBuf, sizeof(readBuf) - 1, &bytesRead, NULL) && bytesRead > 0)
	{
		readBuf[bytesRead] = '\0';
		int wideLen = MultiByteToWideChar(CP_OEMCP, 0, readBuf, (int)bytesRead, NULL, 0);
		if (wideLen > 0 && capture != NULL && captureChars > 1 && pos < captureChars - 1)
		{
			DWORD available = captureChars - pos - 1;
			int copyLen = wideLen;
			if ((DWORD)copyLen > available)
			{
				copyLen = (int)available;
			}
			MultiByteToWideChar(CP_OEMCP, 0, readBuf, (int)bytesRead, capture + pos, copyLen);
			pos += (DWORD)copyLen;
			capture[pos] = L'\0';
		}
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exitCode);
	if (outExitCode != NULL)
	{
		*outExitCode = exitCode;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(hReadPipe);
	return pos;
}

static void CollapseToOneLine(LPWSTR text)
{
	if (text == NULL)
	{
		return;
	}
	WCHAR* read = text;
	WCHAR* write = text;
	BOOL inSpace = TRUE;
	for (; *read != L'\0'; ++read)
	{
		if (*read == L'\r' || *read == L'\n' || *read == L'\t' || *read == L' ')
		{
			if (!inSpace && write != text)
			{
				*write++ = L' ';
				inSpace = TRUE;
			}
			continue;
		}
		*write++ = *read;
		inSpace = FALSE;
	}
	if (write > text && *(write - 1) == L' ')
	{
		--write;
	}
	*write = L'\0';
}

static void SummarizeCapture(LPCWSTR capture, DWORD exitCode, LPWSTR out, DWORD outChars)
{
	WCHAR tmp[2048];
	StringCchCopyW(tmp, _countof(tmp), capture != NULL ? capture : L"");
	CollapseToOneLine(tmp);
	if (tmp[0] == L'\0')
	{
		StringCchCopyW(out, outChars, L"OK");
		return;
	}
	LPCWSTR removed = wcsstr(tmp, L"Removed:");
	if (removed != NULL)
	{
		StringCchCopyW(out, outChars, removed);
		return;
	}
	if (wcsstr(tmp, L"No matching certificate") != NULL)
	{
		StringCchCopyW(out, outChars, L"none found");
		return;
	}
	if (exitCode == 0)
	{
		StringCchCopyW(out, outChars, L"OK");
		return;
	}
	StringCchCopyW(out, outChars, tmp);
}

static void QueryTestSigningState(LPWSTR out, DWORD outChars)
{
	WCHAR cap[1024] = { 0 };
	DWORD ec = 0;
	CaptureCommandOutput(
		L"cmd /c bcdedit /enum {current} | findstr /i testsigning",
		cap, _countof(cap), &ec);
	CollapseToOneLine(cap);
	if (wcsstr(cap, L"Yes") != NULL)
	{
		StringCchCopyW(out, outChars, L"On");
	}
	else if (wcsstr(cap, L"No") != NULL)
	{
		StringCchCopyW(out, outChars, L"Off");
	}
	else
	{
		StringCchCopyW(out, outChars, L"unknown");
	}
}

bool TestSigningBcdEnabled()
{
	WCHAR state[32] = { 0 };
	QueryTestSigningState(state, _countof(state));
	return wcscmp(state, L"On") == 0;
}

static DWORD AppendField(LPWSTR buf, DWORD bufChars, DWORD pos, LPCWSTR name, LPCWSTR value)
{
	WCHAR line[768];
	StringCchPrintfW(line, _countof(line), L"  %-16s %s\r\n", name, value);
	return AppendToLog(buf, bufChars, pos, line);
}

DWORD EnableTestSigning(LPWSTR outLogBuf, DWORD outLogBufChars)
{
	DWORD pos = 0;
	if (outLogBuf != NULL && outLogBufChars > 0)
	{
		outLogBuf[0] = L'\0';
	}

	pos = AppendToLog(outLogBuf, outLogBufChars, pos, L"Enable test signing\r\n\r\n");

	if (!IsRunningAsAdmin())
	{
		return AppendToLog(outLogBuf, outLogBufChars, pos,
			L"Error: Administrator privileges required. Restart Hawkeye as Administrator.\r\n");
	}

	if (IsSecureBootEnabled())
	{
		return AppendToLog(outLogBuf, outLogBufChars, pos,
			L"Error: Secure Boot is on. Turn it off in firmware or in the VM settings, then restart Windows.\r\n");
	}

	WCHAR exeDir[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, exeDir, MAX_PATH);
	PWCHAR slash = wcsrchr(exeDir, L'\\');
	if (!slash)
	{
		return AppendToLog(outLogBuf, outLogBufChars, pos, L"Error: Failed to get executable directory.\r\n");
	}
	*(slash + 1) = L'\0';

	WCHAR cerPath[MAX_PATH];
	StringCchPrintfW(cerPath, MAX_PATH, L"%scer\\Hawkeye.cer", exeDir);
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesExW(cerPath, GetFileExInfoStandard, &fad))
	{
		WCHAR msg[1024];
		StringCchPrintfW(msg, _countof(msg), L"Error: Certificate not found: %s\r\n", cerPath);
		return AppendToLog(outLogBuf, outLogBufChars, pos, msg);
	}

	WCHAR before[32] = { 0 };
	WCHAR after[32] = { 0 };
	QueryTestSigningState(before, _countof(before));

	WCHAR cap[2048] = { 0 };
	DWORD bcdeditExit = (DWORD)-1;
	CaptureCommandOutput(L"cmd /c bcdedit /set testsigning on", cap, _countof(cap), &bcdeditExit);
	if (bcdeditExit != 0)
	{
		WCHAR detail[512];
		SummarizeCapture(cap, bcdeditExit, detail, _countof(detail));
		pos = AppendToLog(outLogBuf, outLogBufChars, pos, L"Error: bcdedit /set testsigning on failed.\r\n");
		if (detail[0] != L'\0' && wcscmp(detail, L"OK") != 0)
		{
			pos = AppendField(outLogBuf, outLogBufChars, pos, L"Detail", detail);
		}
		return pos;
	}
	QueryTestSigningState(after, _countof(after));
	WCHAR ts[64];
	StringCchPrintfW(ts, _countof(ts), L"%s -> %s", before, after);
	pos = AppendField(outLogBuf, outLogBufChars, pos, L"Test signing", ts);

	WCHAR quotedCer[MAX_PATH * 2];
	StringCchPrintfW(quotedCer, _countof(quotedCer), L"\"%s\"", cerPath);
	WCHAR cmd[4096];
	WCHAR summary[512];

	StringCchPrintfW(cmd, _countof(cmd), L"cmd /c certutil -addstore Root %s", quotedCer);
	DWORD rootEc = 0;
	cap[0] = L'\0';
	CaptureCommandOutput(cmd, cap, _countof(cap), &rootEc);
	if (rootEc == 0)
	{
		StringCchCopyW(summary, _countof(summary), L"OK");
	}
	else
	{
		SummarizeCapture(cap, rootEc, summary, _countof(summary));
		if (wcscmp(summary, L"OK") == 0)
		{
			StringCchCopyW(summary, _countof(summary), L"already present");
		}
	}
	pos = AppendField(outLogBuf, outLogBufChars, pos, L"Root", summary);

	StringCchPrintfW(cmd, _countof(cmd), L"cmd /c certutil -addstore TrustedPublisher %s", quotedCer);
	DWORD tpEc = 0;
	cap[0] = L'\0';
	CaptureCommandOutput(cmd, cap, _countof(cap), &tpEc);
	if (tpEc == 0)
	{
		StringCchCopyW(summary, _countof(summary), L"OK");
	}
	else
	{
		SummarizeCapture(cap, tpEc, summary, _countof(summary));
		if (wcscmp(summary, L"OK") == 0)
		{
			StringCchCopyW(summary, _countof(summary), L"already present");
		}
	}
	pos = AppendField(outLogBuf, outLogBufChars, pos, L"Publisher", summary);

	return AppendToLog(outLogBuf, outLogBufChars, pos,
		L"\r\nRestart Windows, then start Hawkeye again.\r\n");
}

DWORD DisableTestSigning(LPWSTR outLogBuf, DWORD outLogBufChars)
{
	DWORD pos = 0;
	if (outLogBuf != NULL && outLogBufChars > 0)
	{
		outLogBuf[0] = L'\0';
	}

	pos = AppendToLog(outLogBuf, outLogBufChars, pos, L"Disable test signing\r\n\r\n");

	if (!IsRunningAsAdmin())
	{
		return AppendToLog(outLogBuf, outLogBufChars, pos,
			L"Error: Administrator privileges required. Restart Hawkeye as Administrator.\r\n");
	}

	WCHAR before[32] = { 0 };
	WCHAR after[32] = { 0 };
	QueryTestSigningState(before, _countof(before));

	WCHAR cap[2048] = { 0 };
	DWORD bcdeditExit = (DWORD)-1;
	CaptureCommandOutput(L"cmd /c bcdedit /set testsigning off", cap, _countof(cap), &bcdeditExit);
	if (bcdeditExit != 0)
	{
		WCHAR detail[512];
		SummarizeCapture(cap, bcdeditExit, detail, _countof(detail));
		pos = AppendToLog(outLogBuf, outLogBufChars, pos, L"Error: bcdedit /set testsigning off failed.\r\n");
		if (detail[0] != L'\0' && wcscmp(detail, L"OK") != 0)
		{
			pos = AppendField(outLogBuf, outLogBufChars, pos, L"Detail", detail);
		}
		return pos;
	}
	QueryTestSigningState(after, _countof(after));
	WCHAR ts[64];
	StringCchPrintfW(ts, _countof(ts), L"%s -> %s", before, after);
	pos = AppendField(outLogBuf, outLogBufChars, pos, L"Test signing", ts);

	const WCHAR* stores[] = {
		L"Cert:\\LocalMachine\\Root",
		L"Cert:\\LocalMachine\\TrustedPublisher",
		L"Cert:\\LocalMachine\\My",
		L"Cert:\\CurrentUser\\My",
	};
	const WCHAR* names[] = {
		L"Root",
		L"Publisher",
		L"Machine My",
		L"User My",
	};

	for (int i = 0; i < 4; ++i)
	{
		WCHAR cmd[4096];
		StringCchPrintfW(cmd, _countof(cmd),
			L"cmd /c powershell -ExecutionPolicy Bypass -Command \""
			L"$c = Get-ChildItem %s | Where-Object { $_.Subject -match 'Hawkeye' };"
			L"if ($c) { $c | ForEach-Object { Remove-Item ('%s\\' + $_.Thumbprint) -Force; Write-Output ('Removed: ' + $_.Subject) } }"
			L"else { Write-Output 'No matching certificate found in store.' }\"",
			stores[i], stores[i]);
		DWORD ec = 0;
		cap[0] = L'\0';
		CaptureCommandOutput(cmd, cap, _countof(cap), &ec);
		WCHAR summary[512];
		SummarizeCapture(cap, ec, summary, _countof(summary));
		if (ec != 0 && wcscmp(summary, L"OK") == 0)
		{
			StringCchCopyW(summary, _countof(summary), L"failed");
		}
		pos = AppendField(outLogBuf, outLogBufChars, pos, names[i], summary);
	}

	return AppendToLog(outLogBuf, outLogBufChars, pos,
		L"\r\nRestart Windows for this to take effect.\r\n");
}
