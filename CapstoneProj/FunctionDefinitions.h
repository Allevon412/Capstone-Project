#pragma once
#include <Windows.h>

//functions that need to be resolved dynamically.
typedef BOOL(WINAPI* t_CreateProcessA)(
	IN OPTIONAL      LPCSTR                lpApplicationName,
	IN OUT OPTIONAL LPSTR                 lpCommandLine,
	IN OPTIONAL     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	IN OPTIONAL     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN                BOOL                  bInheritHandles,
	IN                DWORD                 dwCreationFlags,
	IN OPTIONAL      LPVOID                lpEnvironment,
	IN OPTIONAL      LPCSTR                lpCurrentDirectory,
	IN                LPSTARTUPINFOA        lpStartupInfo,
	OUT               LPPROCESS_INFORMATION lpProcessInformation
	);

typedef DWORD(WINAPI* t_GetModuleFileNameW)(
	_In_opt_ HMODULE hModule,
	_Out_ LPWSTR lpFilename,
	_In_ DWORD nSize
	);

typedef HANDLE(WINAPI* t_CreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef BOOL(WINAPI* t_SetFileInformationByHandle)(
	HANDLE                    hFile,
	FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	LPVOID                    lpFileInformation,
	DWORD                     dwBufferSize
	);

typedef BOOL(WINAPI* t_CloseHandle)(
	HANDLE hObject
	);

typedef LPVOID(WINAPI* t_HeapAlloc)(
	IN HANDLE hHeap,
	IN DWORD  dwFlags,
	IN SIZE_T dwBytes
	);
typedef HANDLE(WINAPI* t_GetProcessHeap)();
