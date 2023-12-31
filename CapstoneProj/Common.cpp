#include <Windows.h>
#include "Common.h"

#if COMMONDEBUG 
const unsigned char ASCIIKeyStream[] = {
        0x3A, 0x61, 0x71, 0x37, 0x51, 0x42, 0x67, 0x48, 0x74, 0x37, 0x75, 0x48, 0x73, 0x39 };
const unsigned char NecessaryASCIIStrings[] = "kernel32|ntdll|\\\\KnownDlls\\\\|CloseHandle|CreateFileW|GetModuleFileNameW|SetFileInformationByHandle|HeapAlloc|GetProcessHeap|.text|";
#endif
const unsigned char ASCIIEncryptedKeyStream[] = {
        0x23, 0x7B, 0x6A, 0x23, 0x4C, 0x5E, 0x74, 0x56, 0x65, 0x59, 0x66, 0x4A, 0x66, 0x5F };

unsigned const char NecessaryEncryptedASCIIStrings[] = {
        0x68, 0x40, 0x39, 0x90, 0xAE, 0x5D, 0x9B, 0x4E, 0x3E, 0x6F, 0x00, 0x86, 0x8D, 0xE6, 0x70, 0x9F,
        0x46, 0xFD, 0x84, 0x4E, 0x8B, 0x65, 0x9D, 0xAD, 0xF8, 0xD2, 0xCB, 0x73, 0x2D, 0xEA, 0xC4, 0x03,
        0x91, 0x44, 0x9B, 0xE7, 0x70, 0x64, 0x64, 0x51, 0xF3, 0x77, 0xA7, 0x63, 0x2C, 0xCC, 0x5E, 0x68,
        0x81, 0x95, 0x29, 0x86, 0x51, 0xB9, 0x98, 0x0F, 0x16, 0x09, 0xB7, 0x36, 0x08, 0x08, 0x9F, 0x40,
        0xA1, 0x64, 0x9C, 0xA2, 0xB6, 0xD9, 0x8F, 0x19, 0xD1, 0xAB, 0xD0, 0xDA, 0x44, 0x17, 0x8E, 0x7A,
        0xFE, 0x18, 0x62, 0x0F, 0xC8, 0xF8, 0xEF, 0xA9, 0x06, 0x10, 0xE7, 0x3F, 0xBF, 0x3B, 0x67, 0x51,
        0x25, 0xFC, 0xF0, 0x9D, 0x08, 0x05, 0x66, 0x12, 0xE3, 0xE4, 0x72, 0xDF, 0xA1, 0x07, 0xDA, 0xEF,
        0x8A, 0x9E, 0x55, 0x67, 0xCE, 0x90, 0x6E, 0xE1, 0x25, 0x60, 0xEC, 0xDC, 0x8E, 0x57, 0x4E, 0x5B,
        0x2E };


/*const unsigned char NecessaryEncryptedASCIIStrings[] = {
        0x68, 0x40, 0x39, 0x90, 0xAE, 0x5D, 0x9B, 0x4E, 0x3E, 0x6F, 0x00, 0x86, 0x8D, 0xE6, 0x70, 0x9F,
        0x51, 0xD8, 0x85, 0x56, 0x92, 0x4F, 0xB5, 0xAD, 0xE7, 0xFD, 0xEB, 0x6C, 0x3D, 0xC6, 0xDB, 0x09,
        0xAA, 0x40, 0xBD, 0xE2, 0x72, 0x65, 0x74, 0x77, 0xFD, 0x51, 0xB4, 0x72, 0x28, 0xFE, 0x52, 0x42,
        0x8D, 0xAE, 0x30, 0x96, 0x48, 0x8A, 0xB0, 0x14, 0x3F, 0x13, 0xBF, 0x26, 0x22, 0x04, 0xB5, 0x4C,
        0x83, 0x60, 0xBF, 0xA6, 0x8C, 0xC0, 0x8B, 0x00, 0xF6, 0x88, 0xCD, 0xF0, 0x48, 0x32, 0x85, 0x55,
        0xFF, 0x0C, 0x60, 0x1C, 0xD1, 0xF0, 0xF4, 0xAE, 0x2B, 0x07, 0xED, 0x27, 0x99, 0x3E, 0x65, 0x50,
        0x35, 0xD1, 0xE9, 0xB4, 0x1D, 0x25, 0x7A, 0x3F, 0xE0, 0xEB, 0x61, 0xFB, 0xB8, 0x34, 0xEF, 0xE9,
        0xB5, 0x8F, 0x5F, 0x77, 0xD8, 0xAB, 0x78, 0xC8, 0x30, 0x7D, 0xB2, 0xD4, 0xC5, 0x5B, 0x5F, 0x5F,
        0x5A, 0x2E, 0xC0 };
*/
#if COMMONDEBUG
const unsigned int DataLengthA = sizeof(NecessaryASCIIStrings);
#else
const unsigned int DataLengthA = sizeof(NecessaryEncryptedASCIIStrings);
#endif //COMMONDEBUG
const unsigned int KeyLengthA = sizeof(ASCIIEncryptedKeyStream);