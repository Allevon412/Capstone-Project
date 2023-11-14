#include <Windows.h>
#include "RandomIntGenerator.h"
#include "StringRandomizer.h"


BOOL RandomizeStringW(PWCHAR RandomString, UINT Length)
{
	if (RandomString != NULL)
	{
		int min = 0x41;
		int max = 0x7a;
		RandomString[0] = L':';
		for (int i = 1; i < Length; i++)
		{
			WCHAR RandomChar = (WCHAR)(min + CreatePseudoRandomInteger(i) % (max - min + 1));
			if (RandomChar >= 0x5B && RandomChar <= 0x60)
			{
				RandomChar -= 0x27;
			}
			RandomString[i] = RandomChar;
		}
	}
	return TRUE;
}

BOOL RandomizeStringA(PCHAR RandomString, UINT Length)
{
	if (RandomString != NULL)
	{
		int min = 0x41;
		int max = 0x7a;
		RandomString[0] = ':';
		for (int i = 1; i < Length; i++)
		{
			WCHAR RandomChar = (WCHAR)(min + CreatePseudoRandomInteger(i) % (max - min + 1));
			if (RandomChar >= 0x5B && RandomChar <= 0x60)
			{
				RandomChar -= 0x27;
			}
			RandomString[i] = RandomChar;
		}
	}
	return TRUE;
}