
#include "Memory.h"
#include "Global.h"
#include "Dpc.h"


typedef struct _INTERRUPTREADMEM {
    ptr address; //目标地址
    ptr outbuffer;//输出缓冲区
    size_t readSize;//要读取的大小
    size_t* pRetlen;//已读取大小
    status status;//读取结果
}INTERRUPTREADMEM, * PINTERRUPTREADMEM;


PHYSICAL_MEMORY_RANGE_INFO* InitPhysicalMemoryRanges()
{
    PPHYSICAL_MEMORY_RANGE pm = MmGetPhysicalMemoryRanges();

    if (!pm)
        return NULL;

    b bFinished = FALSE;
    s32 items = -1;
    ULONGLONG pageCnt = 0;
    PPHYSICAL_MEMORY_RANGE pPhysical = NULL;

    do
    {
        items++;
        pPhysical = (PPHYSICAL_MEMORY_RANGE)&pm[items];

        if (pPhysical->BaseAddress.QuadPart || pPhysical->NumberOfBytes.QuadPart)
        {
            pageCnt += BYTES_TO_PAGES(pPhysical->NumberOfBytes.QuadPart);
            bFinished = 1;
        }
        else
        {
            bFinished = 0;
        }
    } while (bFinished);

    PHYSICAL_MEMORY_RANGE_INFO* memRangeInfo = NULL;

    if (items)
    {
        size_t allocSize = sizeof(PHYSICAL_MEMORY_INFO) * (items - 1) + sizeof(PHYSICAL_MEMORY_RANGE_INFO);
        memRangeInfo = (PHYSICAL_MEMORY_RANGE_INFO*)ExAllocatePoolWithTag(NonPagedPool, allocSize, 'FkTX');
        
        if (memRangeInfo)
        {
            memset(memRangeInfo, 0, allocSize);
            memRangeInfo->Header.Items = items;
            memRangeInfo->Header.AllPhyPageCnt = pageCnt;

            s32 idx = 0;

            do
            {
                MMPTE* ppte = (MMPTE*)(&pm[idx].BaseAddress.QuadPart);
                memRangeInfo->PhyMemInfo[idx].pfn = ppte->u.Hard.PageFrameNumber;
                memRangeInfo->PhyMemInfo[idx].PageCnt = BYTES_TO_PAGES(pm[idx].NumberOfBytes.QuadPart);
                ++idx;
            } while (idx < items);
        }
    }

    ExFreePoolWithTag(pm, 'hPmM');
    
    return memRangeInfo;
}

b IsOutPhysicalMemoryRanges(LONGLONG physicalAddress)
{
    PHYSICAL_MEMORY_RANGE_INFO* pTemp = RtBlock.PhysicalMemoryRanges;
    b isValid = FALSE, result = FALSE;

    if (pTemp->Header.Items)
    {
        u32 idx = 0;
        LONGLONG phyStart = 0, phyEnd = 0;

        do {

            phyStart = pTemp->PhyMemInfo[idx].pfn << PAGE_SHIFT;
            phyEnd = ((pTemp->PhyMemInfo[idx].PageCnt + pTemp->PhyMemInfo[idx].pfn) << PAGE_SHIFT) - 0x1;
            isValid = IsAddressInRange(&physicalAddress, &phyStart, &phyEnd);

            if (isValid)
                break;

            idx++;
        } while (idx < pTemp->Header.Items);

        result = !isValid;
    }
    else
    {
        result = TRUE;
    }

    return result;
}

NTSTATUS ReadWriteProcessMemory(
    PVOID srcProcess,
    PUCHAR src,
    PVOID dstProcess,
    PUCHAR dst,
    ULONG32 len,
    KPROCESSOR_MODE mode,
    PULONG32 retlen
)
{
    u32 rwSize = (len < 0xE000) ? len : 0xE000;
    u8ptr _src = src;
    u8ptr _dst = dst;
    u32 _len = len;
    b bCopied = FALSE;

    while (_len)
    {
        if (_len < rwSize)
            rwSize = _len;

        KAPC_STATE srcState, dstState;
        ptr mappedBase = NULL;
        b bLocked = FALSE,bDstAttached = FALSE,bSrcAttached = FALSE;
        PMDL pMdl = NULL;

        KeStackAttachProcess(srcProcess, &srcState);
        bSrcAttached = TRUE;

        __try {

            if (mode != KernelMode)
                ProbeForRead(_src, _len, 1);

           pMdl = MmCreateMdl(NULL, _src, _len);

            MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
            bLocked = TRUE;
            mappedBase = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, 0, 0, HighPagePriority);

            if (!mappedBase)
                ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

            KeUnstackDetachProcess(&srcState);
            bSrcAttached = FALSE;

            KeStackAttachProcess(dstProcess, &dstState);
            bDstAttached = TRUE;

            if (mode != KernelMode)
                ProbeForWrite(_dst, _len, 1);

            memcpy(_dst, mappedBase, rwSize);

            bCopied = TRUE;

            KeUnstackDetachProcess(&dstState);
            bDstAttached = FALSE;
            MmUnmapLockedPages(mappedBase, pMdl);
            mappedBase = NULL;
            MmUnlockPages(pMdl);
            bLocked = FALSE;
            IoFreeMdl(pMdl);

            if (retlen)
                *retlen += rwSize;

            _len -= rwSize;
            _src += rwSize;
            _dst += rwSize;
        }

        __except (EXCEPTION_EXECUTE_HANDLER) {

            if (bSrcAttached)
                KeUnstackDetachProcess(&srcState);

            if (mappedBase)
                MmUnmapLockedPages(mappedBase, pMdl);

            if (bLocked)
                MmUnlockPages(pMdl);

            if (bDstAttached)
                KeUnstackDetachProcess(&dstState);

            if(pMdl)
                IoFreeMdl(pMdl);

            if (bCopied)
                return STATUS_PARTIAL_COPY;

            return STATUS_WORKING_SET_QUOTA;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS MdlMapVirtualMemory(
    PVOID target,
    SIZE_T size,
    KPROCESSOR_MODE preMode,
    LOCK_OPERATION operation,
    PVOID* pMapedBase,
    PMDL* ppmdl
)
{
    status st = STATUS_INSUFFICIENT_RESOURCES;
    ptr mappedSystemVa = NULL;
    PMDL pMdl = MmCreateMdl(NULL,target, size);

    if (pMdl)
    {
        __try {
            MmProbeAndLockPages(pMdl, preMode, operation);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

            ExFreePoolWithTag(pMdl, 0);
            return st;
        }

        pMdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

        if ((pMdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) != 0)
            mappedSystemVa = pMdl->MappedSystemVa;
        else
            mappedSystemVa = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, 0, HighPagePriority);

        *pMapedBase = mappedSystemVa;

        if (mappedSystemVa)
        {
            *ppmdl = pMdl;
            return STATUS_SUCCESS;
        }
        else
        {
            MmUnlockPages(pMdl);
            IoFreeMdl(pMdl);
        }
    }

    return st;
}


NTSTATUS CopyKernelMemory(ptr outBuffer, ptr address, size_t size, size_t* pRetLen)
{
    status st;
    size_t readedSize = 0, readSize = 0;

    if (size)
    {
        ptr base = PAGE_ALIGN(address);
        u32 pageOffset = BYTE_OFFSET(address);
        size_t copySize = PAGE_SIZE - pageOffset;

        if (copySize >= size)
            copySize = size;

        if (copySize >= PAGE_SIZE)
            copySize = PAGE_SIZE;

        ptr pBuffer = outBuffer;
        b copiedSuccess = FALSE;

        do {

            if (MmIsAddressValid(base))
            {
                PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(base);
                b out = IsOutPhysicalMemoryRanges(physical.QuadPart);

                if (!out && base >= RtBlock.MmUserProbeAddress)
                {
                    ptr target = (u8ptr)base + pageOffset;

                    if (MmIsAddressValid(target))
                    {
                        memcpy(pBuffer, target, copySize);
                        readedSize += copySize;
                        copiedSuccess = TRUE;
                    }
                }
            }

            if (!copiedSuccess)
                memset(pBuffer, 0, copySize);

            pBuffer = (u8ptr)pBuffer + copySize;
            (u8ptr)base += PAGE_SIZE;
            readSize += copySize;
            copySize = size - readSize;

            if (copySize >= PAGE_SIZE)
                copySize = PAGE_SIZE;

            pageOffset = 0;

        } while (readSize < size);
    }
    else
    {
        readSize = 0;
        readedSize = 0;
    }

    if (pRetLen)
        *pRetLen = readedSize;

    st = STATUS_PARTIAL_COPY;

    if (readedSize >= readSize)
        st = STATUS_SUCCESS;

    if (readedSize)
        return st;

    return STATUS_ACCESS_DENIED;
}

NTSTATUS ReadKernelMemoryRoutine(INTERRUPTREADMEM* info)
{
    status st = CopyKernelMemory(info->outbuffer, info->address, info->readSize, info->pRetlen);
    info->status = st;
    return st;
}

NTSTATUS ReadKernelVirtualMemory(
    PVOID outBuffer,
    PVOID address,
    SIZE_T readSize,
    PSIZE_T pRetLen
)
{
    INTERRUPTREADMEM params = { 0 };

    params.address = address;
    params.outbuffer = outBuffer;
    params.readSize = readSize;
    params.pRetlen = pRetLen;
    params.status = STATUS_UNSUCCESSFUL;

    if (RtBlock.NtVersion < _WINNT_VISTA)
        SyncDpcExecuteProxy((PVOID)ReadKernelMemoryRoutine, &params);
    else
        SyncIpiExecuteProxy((PVOID)ReadKernelMemoryRoutine, &params);

    return params.status;
}

PVOID MemoryCompare(PVOID pSrc, SIZE_T srcSize, PVOID pDst, SIZE_T dstSize)
{
    if (srcSize < dstSize)
        return NULL;

    size_t range = srcSize - dstSize;
    size_t index = 0;
    u8ptr pItr = NULL;

    while (TRUE)
    {
        pItr = (u8ptr)pSrc + index;

        if (RtlCompareMemory(pDst, (u8ptr)pSrc + index, dstSize) == dstSize)
            break;

        if (++index > range)
            return NULL;
    }
    return pItr;
}
