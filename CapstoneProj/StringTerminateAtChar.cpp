#include "StringManipulation.hpp"

#define TESTING 0

#if TESTING
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

PCHAR StringTerminateStringAtCharA(_Inout_ PCHAR String, _In_ INT Character)
{
	DWORD Length = (DWORD)StringLengthA(String);

	for (DWORD Index = 0; Index < Length; Index++)
	{
		if (String[Index] == Character)
		{
			String[Index] = '\0';
			return String;
		}
	}

	return NULL;
}

PWCHAR StringTerminateStringAtCharW(_Inout_ PWCHAR String, _In_ INT Character)
{
	DWORD Length = (DWORD)StringLengthW(String);

	for (DWORD Index = 0; Index < Length; Index++)
	{
		if (String[Index] == Character)
		{
			String[Index] = L'\0';
			return String;
		}
	}

	return NULL;
}