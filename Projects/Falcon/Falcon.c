#include "Falcon.h"
#include "Global.h"
#include "Modules.h"
#include "Thread.h"
#include "Search.h"
#include "Dpc.h"
#include "Memory.h"
#include "Space.h"
#include "Dump.h"


GRTBLOCK RtBlock = { 0 };

void InitializeDebuggerBlock()
{
    PKDDEBUGGER_DATA64 kdDebuggerDataBlock = NULL;
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    PDUMP_HEADER dumpHeader = ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, POOLTAGTX);

    if (dumpHeader)
    {
        DbgPrint("MmPagedPoolEnd : %x\n", FIELD_OFFSET(KDDEBUGGER_DATA64, MmPagedPoolEnd));

        if( KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader) >= 0x23E0 )
        {
            kdDebuggerDataBlock = (u8ptr)dumpHeader + KDDEBUGGER_DATA_OFFSET;

            RtBlock.PspCidTable = kdDebuggerDataBlock->PspCidTable;
            RtBlock.PsLoadedModuleList = kdDebuggerDataBlock->PsLoadedModuleList;

            if (kdDebuggerDataBlock->MmPfnDatabase)
                RtBlock.MmPfnDatabase = __rdu64(kdDebuggerDataBlock->MmPfnDatabase);

            if (kdDebuggerDataBlock->MmNonPagedPoolStart)
                RtBlock.MmNonPagedPoolStart = __rdu64(kdDebuggerDataBlock->MmNonPagedPoolStart);

            if (kdDebuggerDataBlock->MmNonPagedPoolEnd)
                RtBlock.MmNonPagedPoolEnd = __rdu64(kdDebuggerDataBlock->MmNonPagedPoolEnd);

            if (kdDebuggerDataBlock->MmPagedPoolStart)
                RtBlock.MmPagedPoolStart = __rdu64((kdDebuggerDataBlock->MmPagedPoolStart));

            if (kdDebuggerDataBlock->MmPagedPoolEnd)
                RtBlock.MmPagedPoolEnd = __rdu64(kdDebuggerDataBlock->MmPagedPoolEnd);

            if (RtBlock.NtVersion >= 0x513)
            {
                RtBlock.MmAllocatedNonPagedPool = kdDebuggerDataBlock->MmAllocatedNonPagedPool;
                RtBlock.MmUnloadedDrivers = kdDebuggerDataBlock->MmUnloadedDrivers;
            }
        }
        ExFreePoolWithTag(dumpHeader, POOLTAGTX);
    }
}

VOID FalconEntry()
{
    RTL_OSVERSIONINFOW os = { 0 };
    os.dwOSVersionInfoSize = sizeof(os);

    RtlGetVersion(&os);
    RtBlock.NtVersion = MAKE_OS_VERSION(os.dwMajorVersion, os.dwMinorVersion);
    RtBlock.NtBuildNumber = os.dwBuildNumber;
    
    RtBlock.MiPagingLevels = 2;

    if ((ReadCR4() & CR4_PAE))
        RtBlock.MiPagingLevels = 3; // 29912

    if ((ReadCR4() & CR4_PAE) && (ReadMSR(MSR_EFER) & MSR_LME))
        RtBlock.MiPagingLevels = 4; //5.. 999912
    
    InitSelfAndKrnl();
    MapNtdll();
    InitNtApi();
    InitThreadOffsets();
    InitDpcRtb();
    InitPetBase();
    InitializeDebuggerBlock();
    RtBlock.PhysicalMemoryRanges = InitPhysicalMemoryRanges();

    RtBlock.MapperRtbPtr = &NtdllMappedInfo;
    RtBlock.SysCallRtbPtr = &SysCallRtb;
    RtBlock.ThreadRtbPtr = &ThreadRtb;
    RtBlock.DpcRtbPtr = &DpcRtb;

    UNICODE_STRING str = { 0 };
    RtlInitUnicodeString(&str, L"PsInitialSystemProcess");
    ptr ta = MmGetSystemRoutineAddress(&str);
    RtlCopyMemory(
        &(RtBlock.PsInitialSystemProcess),
        ta,
        sizeof(ptr));

    RtlInitUnicodeString(&str, L"MmSystemRangeStart");
    ta = MmGetSystemRoutineAddress(&str);
    RtlCopyMemory(
        &(RtBlock.MmSystemRangeStart),
        ta,
        sizeof(ptr));

    RtlInitUnicodeString(&str, L"MmUserProbeAddress");
    ta = MmGetSystemRoutineAddress(&str);
    RtlCopyMemory(
        &(RtBlock.MmUserProbeAddress),
        ta,
        sizeof(ptr));

    RtlInitUnicodeString(&str, L"KeNumberProcessors");
    ta = MmGetSystemRoutineAddress(&str);
    RtlCopyMemory(
        &(RtBlock.KeNumberProcessors),
        ta,
        sizeof(u8));

    RtlInitUnicodeString(&str, L"ExReleaseSpinLockSharedFromDpcLevel");
    RtBlock.ExReleaseSpinLockSharedFromDpcLevel = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"ExAcquireSpinLockSharedAtDpcLevel");
    RtBlock.ExAcquireSpinLockSharedAtDpcLevel = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"KeEnterCriticalRegion");
    RtBlock.KeEnterCriticalRegion = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"KeLeaveCriticalRegion");
    RtBlock.KeLeaveCriticalRegion = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"KeGetCurrentProcessorNumberEx");
    RtBlock.KeGetCurrentProcessorNumberEx = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"KeQueryActiveProcessorCountEx");
    RtBlock.KeQueryActiveProcessorCountEx = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"KeQueryActiveProcessorCount");
    RtBlock.KeQueryActiveProcessorCount = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"KeIpiGenericCall");
    RtBlock.KeIpiGenericCall = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"MmLockPagableDataSection");
    RtBlock.WtfMmLockPagableDataSection = MmGetSystemRoutineAddress(&str);

    RtlInitUnicodeString(&str, L"RtlLookupFunctionEntry");
    RtBlock.RtlLookupFunctionEntry = MmGetSystemRoutineAddress(&str);

}

VOID FalconUnload()
{
    if (RtBlock.PhysicalMemoryRanges)
    {
        ExFreePoolWithTag(RtBlock.PhysicalMemoryRanges, 'FkTX');
        RtBlock.PhysicalMemoryRanges = NULL;
    }

    if (RtBlock.MapperRtbPtr->NtdllWow64Base)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), RtBlock.MapperRtbPtr->NtdllWow64Base);
        RtBlock.MapperRtbPtr->NtdllWow64Base = NULL;
    }

    if (RtBlock.MapperRtbPtr->NtdllWow64SecHandle)
    {
        ZwClose(RtBlock.MapperRtbPtr->NtdllWow64SecHandle);
        RtBlock.MapperRtbPtr->NtdllWow64SecHandle = NULL;
    }

    if (RtBlock.MapperRtbPtr->NtdllWow64Handle)
    {
        ZwClose(RtBlock.MapperRtbPtr->NtdllWow64Handle);
        RtBlock.MapperRtbPtr->NtdllWow64Handle = 0;
    }

    if (RtBlock.MapperRtbPtr->NtdllWow64Path.Buffer)
        ExFreePoolWithTag(RtBlock.MapperRtbPtr->NtdllWow64Path.Buffer, POOLTAGTX);


    if (RtBlock.MapperRtbPtr->NtdllPath.Buffer)
        ExFreePoolWithTag(RtBlock.MapperRtbPtr->NtdllPath.Buffer, POOLTAGTX);

    if (RtBlock.KrnlPath.Buffer)
        ExFreePoolWithTag(RtBlock.KrnlPath.Buffer, POOLTAGTX);

    //if (RtBlock.KernelMappedInitDbgSec)
    //    ExFreePoolWithTag(RtBlock.KernelMappedInitDbgSec, POOLTAGTX);
}