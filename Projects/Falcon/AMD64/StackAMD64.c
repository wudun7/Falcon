
#include "Stack.h"
#include "Thread.h"
#include "Global.h"


u64 StackCopy(PETHREAD thread, ptr buffer)
{
    u64 stackLimit = 0;
    u64 stackBase = 0;
    u64 copidSize = 0;

    stackLimit = \
        ThreadRtb.ThreadStackLimitOffset != 0 ? \
        __rdu64((u8ptr)thread + ThreadRtb.ThreadStackLimitOffset) : \
        0;


    stackBase = \
        ThreadRtb.ThreadStackBaseOffset != 0 ? \
        __rdu64((u8ptr)thread + ThreadRtb.ThreadStackBaseOffset) : \
        0;

#ifdef DEBUG

    ASSERT(stackLimit != 0 && stackBase != 0);
#endif // DEBUG

    if (PsIsSystemThread(thread) &&
        buffer &&
        ThreadRtb.ThreadStateOffset &&
        ThreadRtb.ThreadKernelStackOffset &&
        ThreadRtb.ThreadLockOffset &&
        stackLimit &&
        stackBase
        )
    {
        if ((KeGetCurrentIrql() & 0xFE) == 0 && thread != (PETHREAD)KeGetCurrentThread()) //thread 的中断级别小于等于APC_LEVEL
        {
            memset(buffer, 0, PAGE_SIZE);
            KIRQL irql = LockThread(thread);

            do {
                if (!PsIsThreadTerminating(thread))
                {
                    if (__rds8(ThreadRtb.ThreadStateOffset + (u8ptr)thread) == Waiting)
                    {
                        u64 kernelStack = __rdu64((u8ptr)thread + ThreadRtb.ThreadKernelStackOffset);

                        if(kernelStack <= stackLimit || kernelStack >= stackBase)
                            break;

                        copidSize = stackBase - kernelStack;

                        if (copidSize >= PAGE_SIZE)
                            copidSize = PAGE_SIZE;

                        memcpy(buffer, (ptr)kernelStack, copidSize);
                    }
                }
            } while (0);

            UnlockThread(thread, irql);
            return copidSize;
        }
    }

    return copidSize;
}

BOOLEAN StackWalk(
    PETHREAD thread,
    PCONTEXT ctx,
    PVOID* callers,
    PULONG32 pCallersCount)
{
    b result = FALSE;
    u64 copied = 0;
    ptr stackBuffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAGTX);

    if (stackBuffer)
    {
        copied = StackCopy(thread, stackBuffer);

        if (copied == PAGE_SIZE || copied < 0x48)
        {
            ExFreePoolWithTag(stackBuffer, 0);
            return result;
        }
        else
        {
            u64 retPtr = __rdu64((u8ptr)stackBuffer + 0x38);
            u64 stackLimit = 0;
            u64 stackBase = 0;

            if (retPtr > RtBlock.KrnlStart && retPtr < RtBlock.KrnlEnd)
            {
                stackLimit = \
                    ThreadRtb.ThreadStackLimitOffset != 0 ? \
                    __rdu64((u8ptr)thread + ThreadRtb.ThreadStackLimitOffset) : \
                    0;


                stackBase = \
                    ThreadRtb.ThreadStackBaseOffset != 0 ? \
                    __rdu64((u8ptr)thread + ThreadRtb.ThreadStackBaseOffset) : \
                    0;

#ifdef DEBUG

                ASSERT(stackLimit != 0 && stackBase != 0);
                ASSERT(RtBlock.MmSystemRangeStart != 0);

#endif // DEBU

                ctx->Rip = retPtr;
                ctx->Rsp = __rdu64((u8ptr)thread + ThreadRtb.ThreadKernelStackOffset) + 0x40;

                u32 idx = 0;
                u64 target = 0;
                b unNull = 0;

                do {
                    __wru64((u8ptr)callers + idx * sizeof(ptr), ctx->Rip);

                    if ((u64)RtBlock.MmSystemRangeStart > ctx->Rip)
                        break;

                    if ((u64)RtBlock.MmSystemRangeStart > ctx->Rsp)
                        break;

                    target = ctx->Rsp;

                    if (!IsAddressInRange(&target, &stackLimit, &stackBase))
                        break;

                    u64 imageBase = 0;
                    u64 establisherFrame = 0;
                    ptr handlerData = NULL;
                    PRUNTIME_FUNCTION pRunFunc = RtlLookupFunctionEntry(ctx->Rip, &imageBase, NULL);

                    if (pRunFunc)
                    {
                        RtlVirtualUnwind(0, imageBase, ctx->Rip, pRunFunc, ctx, &handlerData, &establisherFrame, 0);
                        unNull = (ctx->Rip != 0);
                        idx += unNull;
                    }

                } while (unNull && idx < 0x20);

                *pCallersCount = ++idx;
                result = TRUE;
            }
        }

        ExFreePoolWithTag(stackBuffer, POOLTAGTX);
    }

    return result;
}



