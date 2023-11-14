#include "ResolveFunctionsDynamically.hpp"
#include "MemoryManipulation.hpp"
#include "StringManipulation.hpp"
#include "StringRandomizer.h"
#include "SelfDelete.h"

#if DEBUGDELETE
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  
#endif //DEBUG

BOOL DeleteSelf(pFunctionTable pFuncTable)
{
	t_GetModuleFileNameW pGetModuleFileNameW				= (t_GetModuleFileNameW)pFuncTable->GetModuleFileNameW.pAddress;
	t_CreateFileW pCreateFileW								= (t_CreateFileW)pFuncTable->CreateFileW.pAddress;
	t_SetFileInformationByHandle pSetInformationByHandle	= (t_SetFileInformationByHandle)pFuncTable->SetFileInformationByHandle.pAddress;
	t_CloseHandle pCloseHandle								= (t_CloseHandle)pFuncTable->CloseHandle.pAddress;

	//setup variables needed for self deletion.
	WCHAR szPath[MAX_PATH * 2]; 
	FILE_DISPOSITION_INFO fileDisInfo;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	ZeroMemoryEx(szPath, (MAX_PATH * 2) * sizeof(WCHAR));
	ZeroMemoryEx(&fileDisInfo, sizeof(FILE_DISPOSITION_INFO));

	//set our delete flag
	fileDisInfo.DeleteFileW = TRUE;

	//success is not 0. return if not successful.
	if (pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0)
		return FALSE;

	//--------------------------------------------------------------------------------------------------------------------------
	// RENAMING

	// openning a handle to the current file
	hFile = pCreateFileW(szPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	//setup stuff to rename the data stream.
	FILE_RENAME_INFO reNameInfo;
	WCHAR RandomizedString[12];

	ZeroMemoryEx(&reNameInfo, sizeof(FILE_RENAME_INFO));
	ZeroMemoryEx(RandomizedString, 12 * sizeof(WCHAR));

	RandomizeStringW(RandomizedString, 12);

	reNameInfo.FileNameLength = 12 * sizeof(WCHAR);
	CopyMemoryEx(reNameInfo.FileName, RandomizedString, reNameInfo.FileNameLength);
	reNameInfo.ReplaceIfExists = TRUE;

	// renaming the data stream
	if (!pSetInformationByHandle(hFile, FileRenameInfo, &reNameInfo, sizeof(reNameInfo))) {
		return FALSE;
	}

	pCloseHandle(hFile);

	//--------------------------------------------------------------------------------------------------------------------------
	// DELEING

	// openning a new handle to the current file
	hFile = pCreateFileW(szPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		// in case the file is already deleted
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	// marking for deletion after the file's handle is closed
	if (!pSetInformationByHandle(hFile, FileDispositionInfo, &fileDisInfo, sizeof(fileDisInfo))) {
		return FALSE;
	}

	if (!pCloseHandle(hFile))
	{
		return FALSE;
	}
	
	return TRUE;

}