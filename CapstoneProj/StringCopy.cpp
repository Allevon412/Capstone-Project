#include "StringManipulation.hpp"

PCHAR StringCopyA(_Inout_ PCHAR Dst, _In_ LPCSTR Src)
{
	PCHAR p = Dst;

	while ((*p++ = *Src++) != 0);

	return Dst;
}

PWCHAR StringCopyW(_Inout_ PWCHAR Dst, _In_ LPCWSTR Src)
{
	PWCHAR p = Dst;

	while ((*p++ = *Src++) != 0);

	return Dst;
}