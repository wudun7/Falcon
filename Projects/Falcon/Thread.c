
#include "Thread.h"
#include "Global.h"
#include "Search.h"
#include "NtApi.h"
#include "Stack.h"



THREADRTB ThreadRtb;

u8 PreModePattern[3] =
{
  0x00,0x00,0xc3
};

FORCEINLINE
VOID
KzAcquireSpinLock(
    IN PKSPIN_LOCK SpinLock
)

/*++

Routine Description:

    This function acquires a spin lock at the current IRQL.

Arguments:

    SpinLock - Supplies a pointer to an spin lock.

Return Value:

    None.

--*/

{

#if !defined(NT_UP)

#if defined(_WIN64)

#if defined(_AMD64_)
    while (InterlockedBitTestAndSet64((LONG64*)SpinLock, 0))
#else
    while (InterlockedExchangeAcquire64((PLONGLONG)SpinLock, 1) != 0)
#endif

#else   // defined(_WIN64)
    while (InterlockedExchange((PLONG)SpinLock, 1) != 0)
#endif
    {
        do {
            KeYieldProcessor();
        } while (*(volatile LONG_PTR*)SpinLock != 0);
    }

#else  // !defined(NT_UP)

    UNREFERENCED_PARAMETER(SpinLock);

#endif // !defined(NT_UP)

    return;
}

SIZE_T
FORCEINLINE
PspInterlockedExchangeQuota(
    IN PSIZE_T pQuota,
    IN SIZE_T NewQuota)
    /*++

    Routine Description:

        This function does an interlocked exchange on a quota variable.

    Arguments:

        pQuota   - Pointer to a quota entry to exchange into

        NewQuota - The new value to exchange into the quota location.

    Return Value:

        SIZE_T - Old value that was contained in the quota variable

    --*/
{
#if !defined(_WIN64)
    return InterlockedExchange((PLONG)pQuota, NewQuota);
#else
    return InterlockedExchange64((PLONGLONG)pQuota, NewQuota);
#endif    
}

VOID UnlockThread(PETHREAD thread, KIRQL irql)
{
    ptr pQuota = (u8ptr)thread + ThreadRtb.ThreadLockOffset;

    if (RtBlock.NtVersion < 0x620)
        PspInterlockedExchangeQuota(pQuota, 0);
    else
        RtBlock.ExReleaseSpinLockSharedFromDpcLevel(pQuota);

    KeLowerIrql(irql);
}

KIRQL LockThread(PETHREAD thread)
{
    KIRQL oldIrql = 0;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    ptr lock = ThreadRtb.ThreadLockOffset + (u8ptr)thread;

    if (RtBlock.NtVersion < _WINNT_WIN8)
        KzAcquireSpinLock(lock);
    else
        RtBlock.ExAcquireSpinLockSharedAtDpcLevel(lock);

    return oldIrql;
}

NTSTATUS ThreadStackWalk(PETHREAD thread, PVOID* pcallers, PULONG32 pcnt)
{
    status st = STATUS_SUCCESS;
    CONTEXT ctx = { 0 };

    if (thread == (PETHREAD)KeGetCurrentThread())
    {
#ifdef DEBUG
        ASSERT(RtBlock.KeEnterCriticalRegion != NULL && RtBlock.KeLeaveCriticalRegion != NULL);
#endif // DEBUG
        RtBlock.KeEnterCriticalRegion();
        *pcnt = RtlWalkFrameChain(pcallers, *pcnt, 0);
        RtBlock.KeLeaveCriticalRegion();
    }
    else
    {
        u32 cc = 0;

        if (StackWalk(thread, &ctx, pcallers, &cc) && cc)
        {
            *pcnt = cc;
            st = STATUS_SUCCESS;
        }
        else
        {
            st = STATUS_UNSUCCESSFUL;
        }
    }
    return st;
}
VOID InitThreadOffsets()
{
    const u32 osVer = RtBlock.NtVersion;

    // Handle Windows versions 6.00 to 6.30 (Vista to 8.1)
    if (osVer >= _WINNT_VISTA && osVer <= _WINNT_WINBLUE)
    {
        const  s32 versionIndex = osVer - _WINNT_VISTA;
        const s64 versionMask = 0x1000100030001;

        if (_bittest64(&versionMask, versionIndex))
        {
            ThreadRtb.ThreadInitialStackOffset = 0x28;
            ThreadRtb.ThreadStackLimitOffset = 0x30;
            ThreadRtb.ThreadKernelStackOffset = 0x38;
            ThreadRtb.ThreadLockOffset = 0x40;
        }
    }

    // Handle Windows 10
    if (osVer == _WINNT_WIN10)
    {
        ThreadRtb.ThreadInitialStackOffset = 0x28;
        ThreadRtb.ThreadStackLimitOffset = 0x30;
        ThreadRtb.ThreadStackBaseOffset = 0x38;
        ThreadRtb.ThreadKernelStackOffset = 0x58;
        ThreadRtb.ThreadLockOffset = 0x40;
    }

    // Set version-specific offsets
    if (osVer == _WINNT_VISTA) // Vista
    {
        ThreadRtb.ThreadStackBaseOffset = 0x250;
        ThreadRtb.ThreadStateOffset = 0x154;
    }
    else if ((osVer & 0xFFFFFFFE) == _WINNT_WIN7) // Win7
    {
        ThreadRtb.ThreadStackBaseOffset = 0x278;
        ThreadRtb.ThreadStateOffset = 0x164;
    }
    else if (osVer == _WINNT_WIN8 || osVer == _WINNT_WIN10 || osVer == _WINNT_WINBLUE) // Win8/8.1/10
    {
        ThreadRtb.ThreadStateOffset = 0x184;
    }

    status st = STATUS_NOT_FOUND;
    ptr pExGetPreviousMode = GetSystemRoutineAddress((ptr)RtBlock.KrnlStart, "ExGetPreviousMode");
    ptr foundPtr = NULL;

    if (pExGetPreviousMode)
    {
        st = FindPattern(PreModePattern, 0xCC, sizeof(PreModePattern), pExGetPreviousMode, 0x20, &foundPtr);

        if (NT_SUCCESS(st))
            ThreadRtb.PreModeOffset = __rdu32((u8ptr)foundPtr - 0x2);
    }

}


