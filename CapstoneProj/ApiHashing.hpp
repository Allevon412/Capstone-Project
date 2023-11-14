#pragma once
#include <Windows.h>

#define SEED 5
int RandomCompileTimeSeed(void);
DWORD HashStringDjb2A(const char* String, int g_KEY);
DWORD HashStringDjb2W(const wchar_t* String, int g_KEY);

// runtime hashing macros 
#define RTIME_HASHA( API, KEY ) HashStringDjb2A((const char*) API, (int) KEY)
#define RTIME_HASHW( API, KEY ) HashStringDjb2W((const wchar_t*) API, (int) KEY)


// compile time hashing macros (used to create variables)
//#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = RTIME_HASHA((const char*) #API);
//#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);

unsigned int crc32b(char* str);

#define RTIME_crc32b( API ) crc32b((char*) API)
