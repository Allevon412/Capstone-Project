#include "MemoryManipulation.hpp"

#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	// logic similar to memset's one
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}


VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    if (Source == NULL)
        return NULL;

    while (Length--)
        *D++ = *S++;

    return Destination;
}