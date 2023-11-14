#ifndef _AES_HPP_
#define _AES_HPP_

#ifndef __cplusplus
#error Do not include the hpp header in a c project!
#endif //__cplusplus

extern "C" {
#include "aes.h"
}

#endif //_AES_HPP_


#define AESDEBUG 0

unsigned char* Decrypt();
BYTE BruteForceDecryption(IN BYTE HintByte, IN INT HintByteIndex, IN PBYTE pProtectedKey, IN SIZE_T dwKeySize, OUT PBYTE* ppRealKey);

#if AESDEBUG
	VOID GenerateProtectedKey(IN PBYTE pbPlainTextKey, IN SIZE_T dwKeySize, IN BYTE HintByteIndex, OUT PBYTE* ppbProtectedKey);
	VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
#endif // !DEBUG






