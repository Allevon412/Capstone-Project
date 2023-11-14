#pragma once
//RTIMEHASH For function for process manipulation
#define NtOpenProcessCRC 0x5D6DB1FD

//RTIMEHASH For functions required for memory manipulation
#define NtAllocateVirtualCRC 0x74649B9B
#define NtProtectVirtualMemoryCRC 0x96D14C23
#define NtQueryVirtualMemoryCRC 0x47479CF1


//RTIMEHASH For functions required for dll unhooking via mapped sections
#define NtMapViewOfSectionCRC 0xB063D371
#define NtCreateSectionCRC 0x40B96C37
#define NtOpenSectionCRC 0x69FE8437
#define NtUnmapViewOfSectionCRC 0x15E3FA87

//RTIMEHASH For functions required for file manipulation
#define NtOpenFileCRC 0x1EF69528
#define NtReadFileCRC 0xBFD7E4A8
#define NtCreateFileCRC 0x691E904C

//RTIMEHASH For Thread execution
#define NtCreateThreadExCRC 0xA1623D09
#define NtWaitForSingleObjectCRC 0x8A6CF434

//RTIME CRC HASH for ETW Bypassing.
#define EtwEventWriteCRC 0x54C6D97F
#define NtQuerySystemInformationCRC 0xB4BF3C9A