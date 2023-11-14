#pragma once
#include "FunctionDefinitions.h"

typedef struct _FunctionObjEntry {
	PVOID   pAddress;
	WORD    wSystemCall;
	DWORD	dwFuncNameHash;
} FunctionTableEntry, * pFunctionTableEntry;

typedef struct _FunctionTable
{
	FunctionTableEntry createProcessA;
	FunctionTableEntry GetModuleFileNameW;
	FunctionTableEntry CloseHandle;
	FunctionTableEntry SetFileInformationByHandle;
	FunctionTableEntry CreateFileW;
	FunctionTableEntry HeapAlloc;
	FunctionTableEntry GetProcessHeap;
	DWORD	dwK32NameHash;
	DWORD	dwNtdllNameHash;
	INT g_KEY;

} FunctionTable, * pFunctionTable;

PVOID ManualGetProcAddress(IN HMODULE hModule, IN DWORD lpApiName, IN INT g_KEY);
#ifdef __cplusplus
extern "C" {
#endif
HMODULE ManualGetModuleHandle(IN DWORD dwModuleNameHash, IN INT g_KEY);
#ifdef __cplusplus
}
#endif
BOOL InitFunctionTable(IN OUT pFunctionTable pFuncTable);


