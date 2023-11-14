#pragma once

#define STATUS_IMAGE_NOT_AT_BASE 0x40000003 // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

BOOL MapDllFromKnownDlls(IN PWSTR DllName, IN PNTAPI_FUNC_TABLE SysCallTable, OUT PVOID* ppNtdllBuffer);
BOOL ReplaceDllTextSection(IN DWORD dwModuleName, IN PNTAPI_FUNC_TABLE SysCallTable, IN PVOID pUnhookedDll, IN unsigned char* DecryptedConfig);
PWSTR GetModuleNameFromHash(IN DWORD dwModuleNameHash, IN PNTAPI_FUNC_TABLE FuncTable);
BOOL UnhookDll(IN PNTAPI_FUNC_TABLE FuncTable, unsigned char* DecryptedConfig);
DWORD CFuncHashStringDjb2W(const wchar_t* String, UINT g_KEY, UINT SEEDLING);
