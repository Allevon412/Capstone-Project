#include "StringManipulation.hpp"

PCHAR StringLocateCharA(_Inout_ PCHAR String, _In_ INT Character, _In_ INT Index)
{
	int i = 0;
	do
	{
		if(i == Index+1)
			return (PCHAR)String;
		if (*String == Character)
			i++;

	} while (*String++);

	return NULL;
}

PWCHAR StringLocateCharW(_Inout_ PWCHAR String, _In_ INT Character, _In_ INT Index)
{
	int i = 0;
	do
	{
		if (i == Index+1)
			return (PWCHAR)String;
		if (*String == Character)
			i++;
	} while (*String++);

	return NULL;
}