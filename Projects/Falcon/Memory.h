#ifndef _MEMORY_H_
#define _MEMORY_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif

    typedef struct _PHYSICAL_MEMORY_INFO {

        ULONGLONG pfn;
        ULONGLONG PageCnt;
    }PHYSICAL_MEMORY_INFO, * PPHYSICAL_MEMORY_INFO;

    typedef struct _PHYSICAL_MEMORY_RANGE_INFO {

        struct {
            ULONG32 Items;
            ULONGLONG AllPhyPageCnt;
        }Header;

        PHYSICAL_MEMORY_INFO PhyMemInfo[1];
    }PHYSICAL_MEMORY_RANGE_INFO, * PPHYSICAL_MEMORY_RANGE_INFO;


    NTSTATUS ReadWriteProcessMemory(
        PVOID srcProcess,
        PUCHAR src,
        PVOID dstProcess,
        PUCHAR dst, 
        ULONG32 len,
        KPROCESSOR_MODE mode,
        PULONG32 retlen
    );

    NTSTATUS MdlMapVirtualMemory(
        PVOID target,
        SIZE_T size,
        KPROCESSOR_MODE preMode,
        LOCK_OPERATION operation,
        PVOID* pMapedBase,
        PMDL* ppmdl
    );

    NTSTATUS ReadKernelVirtualMemory(
        PVOID outBuffer,
        PVOID address,
        SIZE_T readSize, 
        PSIZE_T pRetLen
    );

    PVOID MemoryCompare(PVOID pSrc, SIZE_T srcSize, PVOID pDst, SIZE_T dstSize);

    PHYSICAL_MEMORY_RANGE_INFO* InitPhysicalMemoryRanges();
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _MEMORY_H_