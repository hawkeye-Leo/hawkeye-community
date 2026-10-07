#pragma once

#ifdef WIN32
#ifndef PAGE_SIZE
#define PAGE_SIZE   4096
#endif
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE   4096
#endif

#define IOCTL_GET_KERNEL_VA_MEMORY_REGION       CTL_CODE(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_PROCESS_PAGE                 CTL_CODE(FILE_DEVICE_UNKNOWN, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_PATH_BY_PID            CTL_CODE(FILE_DEVICE_UNKNOWN, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHECK_VALID_HWND                  CTL_CODE(FILE_DEVICE_UNKNOWN, 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IGUARD_PIT_SCAN                   CTL_CODE(FILE_DEVICE_UNKNOWN, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VIRTUAL_ADDRESS_PTE           CTL_CODE(FILE_DEVICE_UNKNOWN, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OPEN_PROCESS_HANDLE               CTL_CODE(FILE_DEVICE_UNKNOWN, 16, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_VIRTUAL_ADDRESS_PFN           CTL_CODE(FILE_DEVICE_UNKNOWN, 17, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_USERMODE_CALLBACK_INIT            CTL_CODE(FILE_DEVICE_UNKNOWN, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_USERMODE_CALLBACK_CALL6           CTL_CODE(FILE_DEVICE_UNKNOWN, 19, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_SAMPLE_TID        65536 * 2

typedef struct _KERNEL_VA_REGION
{
	DWORD64    va;
	ULONG      mRegion;
	ULONG      regionValue;
	DWORD64    pteMType;
	DWORD64    pfnMType;
	DWORD64    imageMType;
	DWORD64    stackMType;
	DWORD64    sectionMType;
	DWORD64    unusedMType;
	DWORD64    nonpagedMType;
	DWORD64    pagedMType;
	DWORD64    systemMType;
	DWORD64    specialPoolPagedMType;
} KERNEL_VA_REGION, *PKERNEL_VA_REGION;

#define VA_PTE_ENTRY_TYPE_PTE 1
#define VA_PTE_ENTRY_TYPE_PDE 2

typedef struct _GET_VIRTUAL_ADDRESS_PTE
{
	ULONG   pid;
	DWORD64 va;
	DWORD64 pteData;
	DWORD64 entryAddress;
	UCHAR   errCode;
	UCHAR   entryType;
	UCHAR   reserved[6];
} GET_VIRTUAL_ADDRESS_PTE, * PGET_VIRTUAL_ADDRESS_PTE;

#define VA_PFN_DATA_SIZE 0x30

#define VA_PFN_ERR_NONE            0
#define VA_PFN_ERR_SUCCESS         1
#define VA_PFN_ERR_BASE_UNAVAILABLE 2
#define VA_PFN_ERR_PTE_NOT_FOUND   3
#define VA_PFN_ERR_PTE_INVALID     4
#define VA_PFN_ERR_PFN_READ_FAILED 5

typedef struct _GET_VIRTUAL_ADDRESS_PFN
{
	ULONG   pid;
	DWORD64 va;
	DWORD64 pteData;
	DWORD64 entryAddress;
	ULONG64 pfnNumber;
	DWORD64 pfnEntryAddress;
	UCHAR   pfnData[VA_PFN_DATA_SIZE];
	UCHAR   entryType;
	UCHAR   errCode;
	UCHAR   reserved[6];
} GET_VIRTUAL_ADDRESS_PFN, * PGET_VIRTUAL_ADDRESS_PFN;

typedef struct _OPEN_PROCESS_HANDLE
{
	ULONG   pid;
	ULONG   desiredAccess;
	ULONG64 processHandle;
	UCHAR   errCode;
	UCHAR   reserved[3];
	LONG    status;
} OPEN_PROCESS_HANDLE, * POPEN_PROCESS_HANDLE;

typedef struct _READ_MEMORY_PAGES
{
	ULONG  pid;
	DWORD64    va;
	UCHAR  readMethod;
	UCHAR  reserved[3];
	UCHAR  page[PAGE_SIZE];
	ULONG  bytesRead;
	UCHAR  errStep;
	LONG    status;
} READ_MEMORY_PAGES, * PREAD_MEMORY_PAGES;

#define READ_KERNEL_METHOD_MMCOPY       0
#define READ_KERNEL_METHOD_PTE_REMAP    1
#define READ_KERNEL_METHOD_MAP_IO       2

#define READ_PAGE_ERR_LOOKUP_FAILED     1
#define READ_PAGE_ERR_USER_ACCESS       2
#define READ_PAGE_ERR_VA_RANGE          4
#define READ_PAGE_ERR_PHYS_INVALID      10
#define READ_PAGE_ERR_PHYS_NO_PA        11
#define READ_PAGE_ERR_PHYS_COPY         12
#define READ_PAGE_ERR_PTE_BASE          13
#define READ_PAGE_ERR_PTE_LOOKUP        14
#define READ_PAGE_ERR_PTE_INVALID       15
#define READ_PAGE_ERR_PTE_REMAP         16
#define READ_PAGE_ERR_MAP_IO            17

typedef struct _GET_MODULE_PATH
{
	ULONG  pid;
	DWORD64  va;
	UCHAR   image;
	WCHAR  path[512];
	WCHAR  temp[512];
} GET_MODULE_PATH, * PGET_MODULE_PATH;

typedef struct _CHECK_VALID_HWND
{
	ULONG   hwnd;
	ULONG   isValid;
	DWORD64 tagWnd;
	ULONG   reserved1;
	ULONG   reserved2;
	UCHAR   errCode;
} CHECK_VALID_HWND, * PCHECK_VALID_HWND;

#define MAX_IGUARD_PIT_HITS  16384

typedef struct _IGUARD_PIT_HIT
{
	DWORD64 pitAddr;
	DWORD64 pitData;
	ULONG   mRegion;
	ULONG   regionValue;
} IGUARD_PIT_HIT, * PIGUARD_PIT_HIT;

typedef struct _IGUARD_PIT_SCAN
{
	DWORD64 sysBase;
	DWORD64 sysEnd;
	ULONG   hitCount;
	UCHAR   errCode;
	UCHAR   reserved[3];
	IGUARD_PIT_HIT hits[MAX_IGUARD_PIT_HITS];
} IGUARD_PIT_SCAN, * PIGUARD_PIT_SCAN;

#ifndef STATUS_HAWK_NO_MIGETSYSTEMREGION
#define STATUS_HAWK_NO_MIGETSYSTEMREGION  ((NTSTATUS)0xC0010201L)
#define STATUS_HAWK_NO_PTE_BASE           ((NTSTATUS)0xC0010202L)
#define STATUS_HAWK_NO_PFN_BASE           ((NTSTATUS)0xC0010203L)
#endif

#define HAWK_COMPAT_REF_MIGETSYSTEMREGION "HAWK-COMPAT-0201"
#define HAWK_COMPAT_REF_PTE_BASE          "HAWK-COMPAT-0202"
#define HAWK_COMPAT_REF_PFN_BASE          "HAWK-COMPAT-0203"

typedef struct _USERMODE_CALLBACK_INIT
{
    ULONG64 landingStub;
    ULONG64 postCallRoutine;
    UCHAR   errCode;
    UCHAR   reserved[3];
    LONG    status;
    ULONG64 kvaShadowEnabled;
    ULONG64 stackGsOffset;
    ULONG64 kernelStackTop;
    ULONG64 kernelStackControl;
    ULONG64 kernelStackLimit;
} USERMODE_CALLBACK_INIT, *PUSERMODE_CALLBACK_INIT;

typedef struct _USERMODE_CALLBACK_CALL6
{
    ULONG64 targetFunction;
    ULONG64 arg1;
    ULONG64 arg2;
    ULONG64 arg3;
    ULONG64 arg4;
    ULONG64 arg5;
    ULONG64 arg6;
    ULONG64 returnValue;
    ULONG64 userSyntheticStack;
    UCHAR   errCode;
    UCHAR   reserved[3];
    LONG    status;
} USERMODE_CALLBACK_CALL6, *PUSERMODE_CALLBACK_CALL6;

#define USERMODE_CALLBACK_CALL6_ERR_NOT_READY     1
#define USERMODE_CALLBACK_CALL6_ERR_BAD_PARAMETER 2
#define USERMODE_CALLBACK_CALL6_ERR_STACK_WRITE   3

/*
 * !draw_test experiment: draw a red rectangle on the Hawkeye main window (GDI).
 * Function pointers are resolved via GetProcAddress in user mode:
 * GetDC/ReleaseDC from user32, all others from gdi32.
 */
typedef struct _DRAW_TEST_GDI_REQUEST
{
    ULONG64 hwnd;
    ULONG64 pfnGetDC;
    ULONG64 pfnReleaseDC;
    ULONG64 pfnCreatePen;
    ULONG64 pfnSelectObject;
    ULONG64 pfnRectangle;
    ULONG64 pfnDeleteObject;
    LONG    left;
    LONG    top;
    LONG    right;
    LONG    bottom;
    ULONG   penWidth;
    ULONG   colorRef;
    UCHAR   errCode;
    UCHAR   reserved[3];
    LONG    status;
    ULONG64 lastGdiResult;
} DRAW_TEST_GDI_REQUEST, *PDRAW_TEST_GDI_REQUEST;

#define DRAW_TEST_ERR_NOT_INITIALIZED   1
#define DRAW_TEST_ERR_BAD_PARAMETER     2
#define DRAW_TEST_ERR_GETDC             10
#define DRAW_TEST_ERR_CREATEPEN         11
#define DRAW_TEST_ERR_CREATEBRUSH       12

/*
 * User-mode PEB / KernelCallbackTable snapshot for !draw_test debugging.
 * Matches ntdll KiUserCallbackDispatcher: PEB = gs:[0x60], table = [PEB+0x58].
 */
typedef struct _CALLBACK_PEB_DEBUG
{
    ULONG processId;
    ULONG64 tebSelf;
    ULONG64 peb;
    ULONG64 kernelCallbackTable;
    ULONG64 tableEntry0;
    ULONG64 tableEntry2;
    ULONG64 kiUserCallbackDispatcher;
    ULONG64 kiUserCallForwarder;
} CALLBACK_PEB_DEBUG, *PCALLBACK_PEB_DEBUG;
