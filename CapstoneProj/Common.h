#pragma once

extern const unsigned char ASCIIEncryptedKeyStream[];
extern const unsigned char NecessaryEncryptedASCIIStrings[];


extern const unsigned int DataLengthA;
extern const unsigned int KeyLengthA;


#define COMMONDEBUG 0
#if COMMONDEBUG
extern const unsigned char ASCIIKeyStream[];
extern const unsigned char NecessaryASCIIStrings[];
#endif //COMMONDEBUG

#define HINTBYTECOMMON 0x3A