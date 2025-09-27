#include "Dpc.h"
#include "Global.h"

#define DEFERRED_REVERSE_BARRIER_SYNCHRONIZED 0x80000000

DPCRTB DpcRtb;

typedef struct _DPCCONTEXT
{
    status (*funcptr)(ptr info);
    ptr arg;

}DPCCONTEXT, * PDPCCONTEXT;

typedef struct _IPICONTEXT
{
    u32 currentProcessorNumber;
    volatile s32 barrier;
    volatile s32 reverseBarrier;
    u32 synchronized;
    status(*ipiCallback)(ptr info);
    ptr params;
}IPICONTEXT, * PIPICONTEXT;

typedef struct _DEFERRED_REVERSE_BARRIER {
    u32 Barrier;
    u32 TotalProcessors;
} DEFERRED_REVERSE_BARRIER, * PDEFERRED_REVERSE_BARRIER;


VOID InsertDpcOnProcessors(PKDEFERRED_ROUTINE routine, ptr context)
{
    if (DpcRtb.KeGenericCallDpc)
    {
        DpcRtb.KeGenericCallDpc(routine, context);
    }
    else
    {
        if (DpcRtb.CallDpcOffset)
        {
            KIRQL OldIrql;
            DEFERRED_REVERSE_BARRIER ReverseBarrier;
#ifdef DEBUG
            ASSERT(RtBlock.KeNumberProcessors != 0);
#endif // DEBUG

            u32 Barrier = RtBlock.KeNumberProcessors;
            u32  limit = RtBlock.KeNumberProcessors;
            ReverseBarrier.Barrier = Barrier;
            ReverseBarrier.TotalProcessors = Barrier;

            PKPRCB* ppkprcb = (PKPRCB*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PKPRCB) * limit, POOLTAGTX);
            
            if (ppkprcb)
            {
                if (limit >= 2)
                {
                    u32 mask = 1;
                    do {
                        KeSetSystemAffinityThread((u64c(1) << mask));
                        ppkprcb[mask++] = KeGetCurrentPrcb();

                    } while (mask < limit);
                }

                KeSetSystemAffinityThread(1);
                KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

                u32 number = KECURRENT_PROCESSOR_NUMBER();
                u32 index = 0;
                KDPC* pDpc = NULL;

                do {

                    if (number != index)
                    {
                       pDpc = (KDPC*)(ppkprcb[index] + DpcRtb.CallDpcOffset);
                       pDpc->DeferredRoutine = routine;
                       pDpc->DeferredContext = context;
                       KeInsertQueueDpc(pDpc, &Barrier, &ReverseBarrier);
                    }

                    index++;

                } while (index < limit);

                routine((KDPC*)((u8ptr)KeGetCurrentPrcb() + DpcRtb.CallDpcOffset), context, &Barrier, &ReverseBarrier);

                while (*((u32 volatile*)&Barrier) != 0) {
                    KeYieldProcessor();
                }

                KeLowerIrql(OldIrql);
                KeRevertToUserAffinityThread();
                ExFreePoolWithTag(ppkprcb, POOLTAGTX);
            }
        }
    }

    return;
}

LOGICAL SignalCallDpcSynchronize(ptr sysarg2)
{
    if (DpcRtb.KeSignalCallDpcSynchronize)
        return DpcRtb.KeSignalCallDpcSynchronize(sysarg2);

    PDEFERRED_REVERSE_BARRIER reverseBarrier = sysarg2;
    s32 volatile* barrier;

    barrier = (s32 volatile*)&reverseBarrier->Barrier;

    while ((*barrier & DEFERRED_REVERSE_BARRIER_SYNCHRONIZED) != 0) {
        YieldProcessor();
    }

    if (InterlockedDecrement(barrier) == 0) {
        if (reverseBarrier->TotalProcessors == 1) {
            InterlockedExchange(barrier, reverseBarrier->TotalProcessors);
        }
        else {
            InterlockedExchange(barrier, DEFERRED_REVERSE_BARRIER_SYNCHRONIZED + 1);
        }
        return TRUE;
    }

    while ((*barrier & DEFERRED_REVERSE_BARRIER_SYNCHRONIZED) == 0) {
        YieldProcessor();
    }

    if ((ULONG)InterlockedIncrement(barrier) == (reverseBarrier->TotalProcessors | DEFERRED_REVERSE_BARRIER_SYNCHRONIZED)) {
        InterlockedExchange(barrier, reverseBarrier->TotalProcessors);
    }

    return FALSE;
}

VOID SignalCallDpcDone(ptr sysarg1)
{
    if (DpcRtb.KeSignalCallDpcDone)
    {
        DpcRtb.KeSignalCallDpcDone(sysarg1);
        return;
    }

    InterlockedDecrement((LONG volatile*)sysarg1);
    return;
}

VOID DeferredRoutine(KDPC* Dpc, ptr DeferredContext, ptr SystemArgument1, ptr SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    KIRQL old;
    DPCCONTEXT* dpcCtx = DeferredContext;
    KeRaiseIrql(CLOCK_LEVEL, &old);

    if (dpcCtx && SystemArgument2)
    {
        if (SignalCallDpcSynchronize(SystemArgument2))
            dpcCtx->funcptr(dpcCtx->arg);

        SignalCallDpcSynchronize(SystemArgument2);
    }

    KeLowerIrql(old);
    SignalCallDpcDone(SystemArgument1);
    return;
}

VOID SyncDpcExecuteProxy(PVOID funcPtr, PVOID params)
{
    DPCCONTEXT dpcCtx;
    dpcCtx.funcptr = (status(*)(ptr))funcPtr;
    dpcCtx.arg = params;

    InsertDpcOnProcessors(DeferredRoutine, &dpcCtx);
    return;
}

ULONG_PTR IpiBroadcastWorker(ptr arg)
{
    IPICONTEXT* ipiCtx = arg;

    if (KECURRENT_PROCESSOR_NUMBER() == ipiCtx->currentProcessorNumber)
    {
        while (ipiCtx->barrier)
            KeYieldProcessor();

        ipiCtx->ipiCallback(ipiCtx->params);
        ipiCtx->synchronized = 1;
        
        while (ipiCtx->reverseBarrier)
            KeYieldProcessor();
    }
    else
    {
        _InterlockedDecrement(&ipiCtx->barrier);
        
        while (!ipiCtx->synchronized)
            KeYieldProcessor();
        
        _InterlockedDecrement(&ipiCtx->reverseBarrier);
    }
    return 0;
}

 NTSTATUS CallKeIpiGenericCall(PKIPI_BROADCAST_WORKER BroadcastFunction, ULONG_PTR Context)
{
    if (!RtBlock.KeIpiGenericCall)
        return STATUS_NOT_SUPPORTED;
    RtBlock.KeIpiGenericCall(BroadcastFunction, Context);
    return STATUS_SUCCESS;
}

 VOID SyncIpiExecuteProxy(PVOID funcPtr, PVOID params)
{
    IPICONTEXT* pIpiParams = ExAllocatePoolWithTag(NonPagedPool, sizeof(IPICONTEXT), POOLTAGTX);

    if (pIpiParams)
    {
        pIpiParams->currentProcessorNumber = KECURRENT_PROCESSOR_NUMBER();
        pIpiParams->barrier = QUERY_ACTIVE_PROCESSOR_COUNT() - 1;
        pIpiParams->reverseBarrier = QUERY_ACTIVE_PROCESSOR_COUNT() - 1;
        pIpiParams->ipiCallback = (NTSTATUS(*)(PVOID))funcPtr;
        pIpiParams->params = params;
        pIpiParams->synchronized = 0;
        CallKeIpiGenericCall((PKIPI_BROADCAST_WORKER)IpiBroadcastWorker, (ULONG_PTR)pIpiParams);
        ExFreePoolWithTag(pIpiParams, POOLTAGTX);
    }
    return;
}

void InitDpcRtb()
{
    UNICODE_STRING str;
    ptr ta = NULL;

    RtlInitUnicodeString(&str, L"KeGenericCallDpc");
    ta = MmGetSystemRoutineAddress(&str);
    DpcRtb.KeGenericCallDpc = ta;

    RtlInitUnicodeString(&str, L"KeSignalCallDpcDone");
    ta = MmGetSystemRoutineAddress(&str);
    DpcRtb.KeSignalCallDpcDone = ta;

    RtlInitUnicodeString(&str, L"KeSignalCallDpcSynchronize");
    ta = MmGetSystemRoutineAddress(&str);
    DpcRtb.KeSignalCallDpcSynchronize = ta;
}