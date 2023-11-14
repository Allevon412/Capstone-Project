#include "StringManipulation.hpp"
#include "Structs.h"
#include "ApiHashing.hpp"
#include "MemoryManipulation.hpp"
#include "ResolveFunctionsDynamically.hpp"

#define DYNFUNCDEBUG 0

#if DYNFUNCDEBUG
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintf( buf, STR, __VA_ARGS__ );                                   \
            WriteConsole( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

#endif //DEBUGMAIN

//this function is to initialize our function table with the addresses required for dynamically calling windows APIs.
// this way we do not fill our IAT with the functions we're using.
BOOL InitFunctionTable(IN OUT pFunctionTable pFuncTable)
{
	pFuncTable->CloseHandle.pAddress = (t_CloseHandle)ManualGetProcAddress(ManualGetModuleHandle(pFuncTable->dwK32NameHash, pFuncTable->g_KEY),
		pFuncTable->CloseHandle.dwFuncNameHash, pFuncTable->g_KEY);
	if (pFuncTable->CloseHandle.pAddress == NULL)
		return FALSE;

	pFuncTable->CreateFileW.pAddress = (t_CreateFileW)ManualGetProcAddress(ManualGetModuleHandle(pFuncTable->dwK32NameHash, pFuncTable->g_KEY),
		pFuncTable->CreateFileW.dwFuncNameHash, pFuncTable->g_KEY);
	if (pFuncTable->CreateFileW.pAddress == NULL)
		return FALSE;

	pFuncTable->SetFileInformationByHandle.pAddress = (t_SetFileInformationByHandle)ManualGetProcAddress(ManualGetModuleHandle(pFuncTable->dwK32NameHash, pFuncTable->g_KEY),
		pFuncTable->SetFileInformationByHandle.dwFuncNameHash, pFuncTable->g_KEY);
	if (pFuncTable->SetFileInformationByHandle.pAddress == NULL)
		return FALSE;

	pFuncTable->GetModuleFileNameW.pAddress = (t_GetModuleFileNameW)ManualGetProcAddress(ManualGetModuleHandle(pFuncTable->dwK32NameHash, pFuncTable->g_KEY),
		pFuncTable->GetModuleFileNameW.dwFuncNameHash, pFuncTable->g_KEY);
	if (pFuncTable->GetModuleFileNameW.pAddress == NULL)
		return FALSE;

	pFuncTable->HeapAlloc.pAddress = (t_HeapAlloc)ManualGetProcAddress(ManualGetModuleHandle(pFuncTable->dwK32NameHash, pFuncTable->g_KEY),
		 pFuncTable->HeapAlloc.dwFuncNameHash, pFuncTable->g_KEY);
	if (pFuncTable->HeapAlloc.pAddress == NULL)
		return FALSE;

	pFuncTable->GetProcessHeap.pAddress = (t_GetProcessHeap)ManualGetProcAddress(ManualGetModuleHandle(pFuncTable->dwK32NameHash, pFuncTable->g_KEY),
		pFuncTable->GetProcessHeap.dwFuncNameHash, pFuncTable->g_KEY);
	if (pFuncTable->GetProcessHeap.pAddress == NULL)
		return FALSE;

	t_HeapAlloc pHeapAlloc = (t_HeapAlloc)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "HeapAlloc");

	return TRUE;
}

//manually obtains the process address of a function by crawling a target modules IAT.
PVOID ManualGetProcAddress(IN HMODULE hModule, IN DWORD lpApiName, IN INT g_KEY)
{
	PBYTE pBase = (PBYTE)hModule;

	//obtain pointer to dos header and sanity check.
	PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	//obtain pointer to nt headers and sanity check.
	PIMAGE_NT_HEADERS pImgNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pImgDosHeader->e_lfanew);
	if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	//get option header pointer
	IMAGE_OPTIONAL_HEADER pImgOptHeader = pImgNtHeaders->OptionalHeader;

	// get image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//get func's name array pointer
	PDWORD funcNameArray = (PDWORD)(pBase + pImgExportDirectory->AddressOfNames);

	//get func's address array pointer
	PDWORD funcAddrArray = (PDWORD)(pBase + pImgExportDirectory->AddressOfFunctions);

	//get func's ordianl array pointer
	PWORD funcOrdArray = (PWORD)(pBase + pImgExportDirectory->AddressOfNameOrdinals);
	
	//loop through all exported functions.
	for (DWORD i = 0; i < pImgExportDirectory->NumberOfFunctions; i++)
	{
		//obtain name of the current function.
		CHAR* pFuncName = (CHAR*)(pBase + funcNameArray[i]);

		//check if it's the function we're looking for.
		DWORD funcHash = RTIME_HASHA(pFuncName, g_KEY); // TODO: FIX THIS SHIT
		if (funcHash == lpApiName)
		{
			//get the address of the function from ordinal if we've found the function.
			PVOID pFuncAddress = (PVOID)(pBase + funcAddrArray[funcOrdArray[i]]);
			return pFuncAddress;
		}
	}

	//return null if function never found.
	return NULL;
}

//manually retrieves the base address of a module when given the module's name hash.
HMODULE ManualGetModuleHandle(IN DWORD dwModuleNameHash, IN INT g_KEY)
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
	while (pDataTableEntry)
	{
		if (pDataTableEntry->FullDllName.Buffer[0] != NULL)
		{
			WCHAR tmpStr[MAX_PATH];
			ZeroMemoryEx(tmpStr, MAX_PATH * sizeof(WCHAR));
			toLowerW(tmpStr, pDataTableEntry->FullDllName.Buffer);
			DWORD currentHash = RTIME_HASHW(StringTerminateStringAtCharW(tmpStr, '.'), g_KEY);
			
			//do we have a match?
			if (dwModuleNameHash == currentHash)
			{
#ifdef STRUCTS
				return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDataTableEntry->Reserved2[0];
#endif // STRUCTS
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