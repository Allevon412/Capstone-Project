#include "ApiHashing.hpp"

#define CRCSEED        0xAED43149

#define HASHINGDEBUG 0

#if HASHINGDEBUG
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


// Source: https://stackoverflow.com/a/21001712
// the string hashing function - another implementation of the 'Cyclic redundancy check' string hashing algorithm
unsigned int crc32b(char* str) {

    unsigned int    byte, mask, crc = 0xFFFFFFFF;
    int             i = 0, j = 0;

    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (CRCSEED & mask);
        }

        i++;
    }

    return ~crc;
}

// compile time Djb2 hashing function (WIDE)
DWORD HashStringDjb2W(const wchar_t* String, int g_KEY) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}
	return Hash;
}

// compile time Djb2 hashing function (ASCII)
DWORD HashStringDjb2A(const char* String, int g_KEY) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// generate a random key (used as initial hash)
int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};
