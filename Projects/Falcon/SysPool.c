
#include "SysPool.h"
#include "Global.h"
#include "Memory.h"

typedef struct _POOLCONTEXT
{
    ptr OriBuffer; // �����buffer��ַ,δ����ʹ��
    ptr MappedBuffer; //ӳ�䵽�ں˵ĵ�ַ
    u32 InfoSize; //ÿ��Pool����Ϣ��С sizeof(POOLINFO)
    u32 AllSize;//����Pool��Ϣ�ܴ�С
    u64 BufferSize;// buffer��С
    u32ptr RetLen; // ���������ȡ����pool��Ϣ��С��ʵ���Ͼ���allSize
    status Status;//���������
}POOLCONTEXT, * PPOOLCONTEXT;

typedef struct _POOLINFO
{
    u32 InfoSize; //Ϊ����Ч��Ϊsizeof(POOLINFO)��Чpool��Ϣ
    ptr PoolStart;// pool��ʼ��ַ
    size_t PoolSize; // pool size
    u32 ImageSize; //������pool�Ǹ�PE image�Ļ������������SizeOfImage
}POOLINFO, * PPOOLINFO;


typedef struct _SPECIFICPOOLINFO
{
    __in ptr Address; // ָ����ѯ��ַ
    __out ptr PoolStart;//pool��ʼ��ַ
    __out size_t PoolSize;//pool��С

}SPECIFICPOOLINFO, * PSPECIFICPOOLINFO;

b GetImagePoolInfo(ptr pb, size_t ps, u32 sizeOfImage, POOLCONTEXT* poolCtx)
{
    u8ptr pMappedBuffer = poolCtx->MappedBuffer;
    POOLINFO* pCurInfoBuffer = (POOLINFO*)(pMappedBuffer + poolCtx->AllSize);
    poolCtx->InfoSize = sizeof(POOLINFO);
    poolCtx->AllSize += sizeof(POOLINFO);

    if (poolCtx->AllSize < poolCtx->BufferSize)
    {
        pCurInfoBuffer->PoolSize = ps;
        pCurInfoBuffer->ImageSize = sizeOfImage;
        pCurInfoBuffer->PoolStart = pb;
        pCurInfoBuffer->InfoSize = sizeof(POOLINFO);
        poolCtx->Status = STATUS_SUCCESS;
    }
    else
    {
        pCurInfoBuffer->InfoSize = 0;
        poolCtx->Status = STATUS_INFO_LENGTH_MISMATCH;
    }

    if (poolCtx->RetLen)
        *(poolCtx->RetLen) = poolCtx->AllSize;

    return (poolCtx->Status != STATUS_SUCCESS);
}

b PoolImageHandler(ptr pb, size_t ps, b nonpaged, ptr params)
{
    if (nonpaged || !MmIsAddressValid(pb) || ((IMAGE_DOS_HEADER*)pb)->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    IMAGE_NT_HEADERS* pNt = RtlImageNtHeader(pb);

    if (MmIsAddressValid(pNt) && pNt->Signature == IMAGE_NT_SIGNATURE)
    {
        if (MmIsAddressValid(&pNt->FileHeader))
        {
            u32 sizeOfImage = 0;
            
            if (MmIsAddressValid(&pNt->OptionalHeader.SizeOfImage))
                sizeOfImage = pNt->OptionalHeader.SizeOfImage;

            return GetImagePoolInfo(pb, ps, sizeOfImage, params);
        }
    }

    return FALSE;
}

b PoolInfoHandler(ptr pa, size_t ps, b nonpaged, ptr params)
{
    UNREFERENCED_PARAMETER(nonpaged);

    SPECIFICPOOLINFO* poolInfo = params;

    if (poolInfo->Address < pa || poolInfo->Address >= (ptr)((u8ptr)pa + ps))
        return FALSE;

    poolInfo->PoolStart = pa;
    poolInfo->PoolSize = ps;
    return TRUE;
}

VOID EnumBigPoolWithCallback(BigPoolHandler callback, ptr params)
{
    status status = STATUS_UNSUCCESSFUL;
    u32 size = 0x40000;

    do {

        PSYSTEM_BIGPOOL_INFORMATION pool = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(PagedPool,size,POOLTAGTX);

        if (!pool)
            break;

        status = ZwQuerySystemInformation(SystemBigPoolInformation, pool, size, NULL);

        if (NT_SUCCESS(status))
        {
            u32 index = 0;

            if (pool->Count)
            {
                ptr base = NULL;
                b nonpaged = FALSE;
                size_t poolsize = 0;

                do {
                    base = (ptr)(((LONGLONG)pool->AllocatedInfo[index].VirtualAddress) & (~0x1));
                    poolsize = pool->AllocatedInfo[index].SizeInBytes;
                    nonpaged = (LONGLONG)(pool->AllocatedInfo[index].VirtualAddress) & 0x1;

                    //// Set to 1 if entry is nonpaged.

                    if (callback(base, poolsize, nonpaged, params))
                        break;

                    ++index;
                } while (index < pool->Count);
            }

            ExFreePoolWithTag(pool, POOLTAGTX);
            return;
        }

        ExFreePoolWithTag(pool, POOLTAGTX);
        size += 0x40000;

    } while (status == STATUS_INFO_LENGTH_MISMATCH);
    return;
}

NTSTATUS SacnBigPoolAndFindImage(PVOID outBuffer, SIZE_T outlen, PULONG32 pRetLen)
{
    if (pRetLen)
        *pRetLen = 0;

    ptr pMapped = NULL;
    PMDL pMdl = NULL;

    KPROCESSOR_MODE mode = ExGetPreviousMode();
    status st = MdlMapVirtualMemory(outBuffer, outlen, mode, IoWriteAccess, &pMapped, &pMdl);

    if (NT_SUCCESS(st))
    {
        POOLCONTEXT poolCtx;
        poolCtx.OriBuffer = outBuffer;
        poolCtx.BufferSize = outlen;
        poolCtx.MappedBuffer = pMapped;
        poolCtx.AllSize = 0;
        poolCtx.InfoSize = 0;
        poolCtx.RetLen = pRetLen;
        poolCtx.Status = STATUS_SUCCESS;

        EnumBigPoolWithCallback(PoolImageHandler, &poolCtx);
        st = poolCtx.Status;
    }

    if (pMapped)
    {
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
    }

    return st;
}

SIZE_T GetPoolInfoByAddress(PVOID address, PVOID* outPoolStart, PSIZE_T outPoolSize)
{
    SPECIFICPOOLINFO poolInfo;
    poolInfo.Address = address;
    poolInfo.PoolSize = 0;
    poolInfo.PoolStart = NULL;
    size_t size = 0;

    EnumBigPoolWithCallback(PoolInfoHandler, &poolInfo);

    if (poolInfo.PoolStart)
    {
        *outPoolStart = poolInfo.PoolStart;
        size = poolInfo.PoolSize;
    }
    else
    {
        *outPoolStart = (ptr)((size_t)address & (~7));
        size = PAGE_SIZE;
    }

    *outPoolSize = size;
    return size;
}