#pragma once
#include <Windows.h>

//functions necessary to remove C Runtime library.


#ifdef __cplusplus
extern "C" {
#endif
VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size);
PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
extern void* __cdecl memset(void*, int, size_t);
#ifdef __cplusplus
}
#endif


