#pragma once

#define SYSCALLDEBUG 0

//#define SEED2        0xEDB88320
#define UP          -32
#define DOWN        32
#define RANGE       0xFF


// structure that will be used to hold information about ntdll.dll
// so that its not computed every time 
typedef struct _NTDLL_CONFIG
{

    PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of ntdll's exported functions   [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    PDWORD      pdwArrayOfNames;     // The VA of the array of names of ntdll's exported functions       [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of ntdll's exported functions    [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]    
    DWORD       dwNumberOfNames;     // The number of exported functions from ntdll.dll                  [IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    ULONG_PTR   uModule;             // The base address of ntdll - requred to calculated future RVAs    [BaseAddress]

}NTDLL_CONFIG, * PNTDLL_CONFIG;

typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // syscall number
    DWORD dwSyscallHash;            // syscall hash value
    PVOID pSyscallAddress;          // syscall address
    PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll    

}NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTAPI_FUNC_TABLE
{
    //function for process manipulation
    NT_SYSCALL NtOpenProcess;

    //functions required for memory manipulation
    NT_SYSCALL NtAllocateVirtualMemory;
    NT_SYSCALL NtProtectVirtualMemory;
    NT_SYSCALL NtQueryVirtualMemory;

    //functions required for dll unhooking via mapped sections
    NT_SYSCALL NtMapViewOfSection;
    NT_SYSCALL NtCreateSection;
    NT_SYSCALL NtUnmapViewOfSection;
    NT_SYSCALL NtOpenSection;

    //functions required for file manipulation
    NT_SYSCALL NtReadFile;
    NT_SYSCALL NtOpenFile;
    NT_SYSCALL NtCreateFile;

    //thread execution
    NT_SYSCALL NtCreateThreadEx;
    NT_SYSCALL NtWaitForSingleObject;

    //used for DLL Unhooking initialization.
    DWORD dwNtDllHash;
    UINT g_Key;
    UINT SEEDLING;

    //used for etw bypassing using hardware breakpoints.
    NT_SYSCALL EtwEventWrite;

}NTAPI_FUNC_TABLE, * PNTAPI_FUNC_TABLE;

/*
unsigned int crc32b(char* str);
#define HASH(API)	(crc32b((char*)API))
*/

// from 'HellsHall.c'

BOOL InitNtdllConfigStructure(PNTDLL_CONFIG pNtdllConf);
BOOL InitNTSysCallsTable(IN OUT PNTAPI_FUNC_TABLE pSyscallTable, IN PNTDLL_CONFIG pNtdllConf);
BOOL FetchNtSyscall(IN DWORD dwSysHash, IN PNTDLL_CONFIG pNtdllConf, OUT PNT_SYSCALL pNtSys);

// from 'HellsAsm.asm'
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern NTSTATUS RunSyscall();

//  a macro to make calling 'SetSSn' easier
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess() 

