#include "StringManipulation.hpp"


BOOL toLowerA(OUT PSTR* dst, IN PCSTR src)
{

	//get the length of original string.
	int len = StringLengthA(src);

	int i = 0;

	//sanity check.
	if (len >= MAX_PATH)
		return FALSE;

	for (i = 0; i < len; i++)
	{
		if (src[i] >= 'A' && src[i] >= 'Z')
		{
			*dst[i] = src[i] + ('a' - 'A');
		}
		else
		{
			*dst[i] = src[i];
		}
	}
	*dst[i++] = '\0';

	return TRUE;
}

BOOL toLowerW(OUT wchar_t* dst, IN PCWSTR src)
{

	//get the length of original string.
	int len = StringLengthW(src);

	int i = 0;

	//sanity check.
	if (len >= MAX_PATH)
		return FALSE;

	for (i = 0; i < len; i++)
	{
		if (src[i] >= L'A' && src[i] <= L'Z')
		{
			dst[i] = src[i] + (L'a' - L'A');
		}
		else
		{
			dst[i] = src[i];
		}

	}
	dst[i++] = L'\0';

	return TRUE;
}