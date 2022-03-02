#pragma once
#include "common.h"
#include "queue.h"

#define STOP_MARKER L"stopmarker"
CONST DWORD BufferSize = 5242880;
#define MAX_TASKS 15000

namespace threadpool {

	enum THREADPOOLS {

		LOCAL_THREADPOOL,
		NETWORK_THREADPOOL,
		BACKUPS_THREADPOOL

	};

	typedef TAILQ_HEAD(task_list_, task_info_) TASK_LIST, * PTASK_LIST;

	typedef struct task_info_ {

		std::wstring FileName;
		TAILQ_ENTRY(task_info_) Entries;

	} TASK_INFO, * PTASK_INFO;

	typedef struct threadpool_info_ {

		PHANDLE hThreads;
		SIZE_T ThreadsCount;
		SIZE_T TasksCount;
		CRITICAL_SECTION ThreadPoolCS;
		TASK_LIST TaskList;
		BOOL IsWaiting;
		HANDLE hQueueEvent;

	} THREADPOOL_INFO, * PTHREADPOOL_INFO;

	BOOL Create(INT ThreadPoolId, SIZE_T ThreadsCount);
	BOOL Start(INT ThreadPoolId);
	VOID Wait(INT ThreadPoolId);
	VOID Delete(INT ThreadPoolId);
	VOID SuspendThread(INT ThreadPoolId);
	INT PutTask(INT ThreadPoolId, std::wstring Filename);

};