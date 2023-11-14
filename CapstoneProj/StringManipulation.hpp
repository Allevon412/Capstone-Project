#pragma once
#include <Windows.h>

//functions necessary to remove the C Runtime library.
#ifdef __cplusplus
extern "C" {
#endif
INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2);
INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2);
SIZE_T StringLengthA(_In_ LPCSTR String);
SIZE_T StringLengthW(_In_ LPCWSTR String);
BOOL toLowerW(OUT wchar_t* dst, IN PCWSTR src);
BOOL toLowerA(OUT PSTR* dst, IN PCSTR src);
PWCHAR StringCopyW(_Inout_ PWCHAR Dst, _In_ LPCWSTR Src);
PCHAR StringCopyA(_Inout_ PCHAR Dst, _In_ LPCSTR Src);
PCHAR StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2);
PWCHAR StringConcatW(_Inout_ PWCHAR String, _In_ LPCWSTR String2);
PCHAR StringTerminateStringAtCharA(_Inout_ PCHAR String, _In_ INT Character);
PWCHAR StringTerminateStringAtCharW(_Inout_ PWCHAR String, _In_ INT Character);
SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, _In_ SIZE_T MaximumAllowed);
SIZE_T WCharStringToCharString(_Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed);
PWCHAR StringLocateCharW(_Inout_ PWCHAR String, _In_ INT Character, _In_ INT Index);
PCHAR StringLocateCharA(_Inout_ PCHAR String, _In_ INT Character, _In_ INT Index);
#ifdef __cplusplus
}
#endif