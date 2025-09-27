
#include "NtApi.h"
#include "Mapper.h"
#include "Hash.h"
#include "Global.h"
#include "Search.h"
#include "Thread.h"

NTFUNC NtApi;
SYSCALLRTB SysCallRtb;

u8 SsdtPattern[15] =
{
  0x4C, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0xCC, 0x4C, 0x8D, 0x1D,
  0xCC, 0xCC, 0xCC, 0xCC, 0xF7
};

VOID InitSyscallNumber()
{

#ifdef DEBUG

    ASSERT(NtdllMappedInfo.NtdllWow64Base != 0);
#endif // DEBUG

    if (!NtdllMappedInfo.NtdllWow64Base)
        return;

    ptr base = NtdllMappedInfo.NtdllWow64Base;

    PIMAGE_NT_HEADERS32 pNtheader = (PIMAGE_NT_HEADERS32)RtlImageNtHeader(base);
    u32 exportRva = pNtheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* pExport = (IMAGE_EXPORT_DIRECTORY*)(exportRva + (u8ptr)base);

    if (!pExport->NumberOfNames)
        return;

    u32* pAddressOfFunctiongs = (u32*)(pExport->AddressOfFunctions + (u8ptr)base);
    u32* pAddressOfNames = (u32*)(pExport->AddressOfNames + (u8ptr)base);
    u16* pAddressOfOrinals = (u16*)(pExport->AddressOfNameOrdinals + (u8ptr)base);

    u32 index = 0;
    ONEWAYHASH target = { 0 }, source = { 0 };

    do {

        u8ptr pName = (u8ptr)(pAddressOfNames[index] + (u8ptr)base);
        u8ptr pFunc = (u8ptr)(pAddressOfFunctiongs[pAddressOfOrinals[index]] + (u8ptr)base);

        do {

            Hash(&target, pName);
            InitializeHash(&source, strlen("NtReadVirtualMemory"), 0x0FF236223, 0x0CD98F72A, 0x0C493A13F);

            if (HashCompare(&source, &target))
            {
                NtApi.NtReadVirtualMemorySn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtTerminateProcess"), 0x0AFDAB273, 0x8A5F036E, 0x0C07142F4);

            if (HashCompare(&source, &target))
            {
                NtApi.NtTerminateProcessSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtTerminateThread"), 0x675656B0, 0x1A7C3E22, 0x613ABE0D);

            if (HashCompare(&source, &target))
            {
                NtApi.NtTerminateThreadSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtSuspendProcess"), 0x46DCF3AE, 0x0DB3BC4BD, 0x0D4B2A761);

            if (HashCompare(&source, &target))
            {
                NtApi.NtSuspendProcessSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtQueryVirtualMemory"), 0x26759018, 0x845565B, 0x0F3A9FC2A);

            if (HashCompare(&source, &target))
            {
                NtApi.NtQueryVirtualMemorySn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtSuspendThread"), 0x77DE7CD3, 0x68A1D027, 0x28DF549D);

            if (HashCompare(&source, &target))
            {
                NtApi.NtSuspendThreadSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtResumeThread"), 0xD100CE09, 0x79B3CA17, 0x2281D67B);

            if (HashCompare(&source, &target))
            {
                NtApi.NtResumeThreadSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtProtectVirtualMemory"), 0x93192A88, 0x0E4405D85, 0x2769689B);

            if (HashCompare(&source, &target))
            {
                NtApi.NtProtectVirtualMemorySn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtLockVirtualMemory"), 0x9E24F957, 0xE5293B82, 0x1C436598);

            if (HashCompare(&source, &target))
            {
                NtApi.NtLockVirtualMemorySn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtWriteVirtualMemory"), 0xC4B45AAF, 0x6B83DF7E, 0xB2035240);

            if (HashCompare(&source, &target))
            {
                NtApi.NtWriteVirtualMemorySn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtAllocateVirtualMemory"), 0x2F3CB0F6, 0x89994E37, 0x5A1D302);

            if (HashCompare(&source, &target))
            {
                NtApi.NtAllocateVirtualMemorySn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtWriteFile"), 0x1B9E420B, 0xBD90B1D9, 0xCB270D29);

            if (HashCompare(&source, &target))
            {
                NtApi.NtWriteFileSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtReadFile"), 0x99D54057, 0x44902195, 0xA8879F98);

            if (HashCompare(&source, &target))
            {
                NtApi.NtReadFileSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtQueryAttributesFile"), 0x73E6434C, 0xBC70A5AC, 0x53E619A9);

            if (HashCompare(&source, &target))
            {
                NtApi.NtQueryAttributesFileSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtFlushBuffersFile"), 0xC23A9BA6, 0x829C50AE, 0x854EA084);

            if (HashCompare(&source, &target))
            {
                NtApi.NtFlushBuffersFileSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtCreateProcess"), 0x64A54F69, 0x0AC613B64, 0x7B15833B);

            if (HashCompare(&source, &target))
            {
                NtApi.NtCreateProcessSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtCreateProcessEx"), 0x182D02F2, 0x2B4EC983, 0x469A94E0);

            if (HashCompare(&source, &target))
            {
                NtApi.NtCreateProcessExSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtQueryDirectoryObject"), 0x9005BB77, 0x0F1709B0A, 0x4CF06EA0);

            if (HashCompare(&source, &target))
            {
                NtApi.NtQueryDirectoryObjectSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtDeviceIoControlFile"), 0x9AB49FAF, 0x01F4F15C8, 0x212342EC);

            if (HashCompare(&source, &target))
            {
                NtApi.NtDeviceIoControlFileSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtCancelTimer"), 0xA96FD542, 0x07D16F123, 0xA39EB77E);

            if (HashCompare(&source, &target))
            {
                NtApi.NtCancelTimerSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtReplyWaitReceivePort"), 0x3A009BAF, 0x95A4654A, 0x41EE916D);

            if (HashCompare(&source, &target))
            {
                NtApi.NtReplyWaitReceivePortSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtReplyWaitReceivePortEx"), 0x8BCF8F0, 0x4DF33399, 0xEAE610BB);

            if (HashCompare(&source, &target))
            {
                NtApi.NtReplyWaitReceivePortExSn = __rdu16(pFunc + 0x1);
                break;
            }

            InitializeHash(&source, strlen("NtPowerInformation"), 0x2444B37F, 0x84C2852F, 0xFC415931);

            if (HashCompare(&source, &target))
            {
                NtApi.NtPowerInformationSn = __rdu16(pFunc + 0x1);;
                break;
            }

            InitializeHash(&source, strlen("NtSetSystemInformation"), 0x6EB0D8F3, 0x53766E24, 0x82404E52);

            if (HashCompare(&source, &target))
            {
                NtApi.NtSetSystemInformationSn = __rdu16(pFunc + 0x1);
                break;
            }

        } while (0);

        index++;
    } while (index < pExport->NumberOfNames);
}

NTSTATUS InitSsdtTable()
{

#ifdef DEBUG
    ASSERT(RtBlock.KrnlStart != 0);
#endif // DEBUG

    if (!RtBlock.KrnlStart)
        return STATUS_FAIL_CHECK;


    NTSTATUS st = STATUS_NOT_FOUND;

    IMAGE_NT_HEADERS* ntHeader = RtlImageNtHeader((ptr)RtBlock.KrnlStart);

    if (ntHeader->FileHeader.NumberOfSections)
    {
        u32 idx = 0;
        IMAGE_SECTION_HEADER* secHeader = (IMAGE_SECTION_HEADER*)((u8ptr)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

        do {
            if (!(*(u32ptr)&secHeader->Name[0] ^ 0x7865742E | *(u8ptr)&secHeader->Name[4] ^ 0x74))
                break;
            secHeader++;
            idx++;
        } while (idx < ntHeader->FileHeader.NumberOfSections);

        u32 range = secHeader->Misc.VirtualSize < secHeader->SizeOfRawData ? secHeader->Misc.VirtualSize : secHeader->SizeOfRawData;
        ptr foundPtr = 0;

        st = FindPattern(SsdtPattern, 0xCC, sizeof(SsdtPattern), (const ptr)(secHeader->VirtualAddress + RtBlock.KrnlStart), range, &foundPtr);
        
        if(TRACE(st))
        {
            SysCallRtb.KeServiceDescriptorTable       = (ptr)((u8ptr)foundPtr + __rds32((u8ptr)foundPtr + 0x3) + 0x7);
            SysCallRtb.KeServiceDescriptorTableShadow = (ptr)((u8ptr)foundPtr + __rds32((u8ptr)foundPtr + 0xa) + 0xe);
        }
    }

    return st;
}

PVOID GetSsdtRoutineAddress(ULONG32 num)
{
#ifdef DEBUG

    ASSERT(SysCallRtb.KeServiceDescriptorTableShadow != 0 || SysCallRtb.KeServiceDescriptorTable != 0);
#endif // DEBUG


    KSERVICE_TABLE_DESCRIPTOR* ssdt = SysCallRtb.KeServiceDescriptorTableShadow != 0 ? SysCallRtb.KeServiceDescriptorTableShadow : SysCallRtb.KeServiceDescriptorTable;

    if (ssdt && ssdt->Limit >= num)
        return (u8ptr)ssdt->Base + (__rds32((u8ptr)ssdt->Base + 0x4 * num) >> 4);
    else
        return NULL;
}

PVOID GetSystemRoutineAddress(PVOID moduleBase, PUCHAR funcName)
{
    if (!moduleBase || !funcName)
        return NULL;

    u32 exportRva = 0;
    PIMAGE_NT_HEADERS pNt = RtlImageNtHeader(moduleBase);
    
    if (pNt != NULL)
    {
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            exportRva = \
                ((PIMAGE_NT_HEADERS64)pNt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }
        if (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            exportRva = \
                ((PIMAGE_NT_HEADERS32)pNt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }
    }

    IMAGE_EXPORT_DIRECTORY* pExport = (IMAGE_EXPORT_DIRECTORY*)(exportRva + (u8ptr)moduleBase);

    if (!pExport->NumberOfNames)
        return NULL;

    u32ptr pAddressOfFunctiongs = (u32ptr)(pExport->AddressOfFunctions + (u8ptr)moduleBase);
    u32ptr pAddressOfNames = (u32ptr)(pExport->AddressOfNames + (u8ptr)moduleBase);
    u16ptr pAddressOfOrinals = (u16ptr)(pExport->AddressOfNameOrdinals + (u8ptr)moduleBase);

    u32 index = 0;

    do {

        u8ptr name = (u8ptr)(pAddressOfNames[index] + (u8ptr)moduleBase);

        if (!strcmp(name, funcName))
        {
            return pAddressOfFunctiongs[pAddressOfOrinals[index]] + (u8ptr)moduleBase;
        }

        index++;

    } while (index < pExport->NumberOfNames);

    return NULL;
}

NTSTATUS
NTAPI
KeNtTerminateProcess(
     PVOID ProcessHandle,
     NTSTATUS ExitStatus
)
{
    if (!NtApi.NtTerminateProcess)
        return STATUS_NOT_FOUND;

    u8 preMode = GETPREMODE();
    SETPREMODE(0);

    status st = NtApi.NtTerminateProcess(ProcessHandle, ExitStatus);

    SETPREMODE(preMode);

    return st;
}

NTSTATUS
NTAPI
KeNtSuspendProcess(
    PVOID ProcessHandle
)
{

    if (!NtApi.NtSuspendProcess)
        return STATUS_NOT_FOUND;

    u8 preMode = GETPREMODE();
    SETPREMODE(0);

    status st = NtApi.NtSuspendProcess(ProcessHandle);

    SETPREMODE(preMode);

    return st;
}

NTSTATUS
NTAPI
KeNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
)
{
    if (!NtApi.NtProtectVirtualMemory)
        return STATUS_NOT_FOUND;

    u8 preMode = GETPREMODE();
    SETPREMODE(0);

    status st = \
        NtApi.NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);

    SETPREMODE(preMode);

    return st;
}

VOID InitNtApi()
{
    InitSyscallNumber();
    NTSTATUS st = InitSsdtTable();

    if (NT_SUCCESS(st))
    {
        NtApi.NtAllocateVirtualMemory = GetSsdtRoutineAddress(NtApi.NtAllocateVirtualMemorySn);
        NtApi.NtQueryVirtualMemory = GetSsdtRoutineAddress(NtApi.NtQueryVirtualMemorySn);
        NtApi.NtProtectVirtualMemory = GetSsdtRoutineAddress(NtApi.NtProtectVirtualMemorySn);
        NtApi.NtWriteVirtualMemory = GetSsdtRoutineAddress(NtApi.NtWriteVirtualMemorySn);
        NtApi.NtReadVirtualMemory = GetSsdtRoutineAddress(NtApi.NtReadVirtualMemorySn);
        NtApi.NtLockVirtualMemory = GetSsdtRoutineAddress(NtApi.NtLockVirtualMemorySn);
        NtApi.NtTerminateProcess = GetSsdtRoutineAddress(NtApi.NtTerminateProcessSn);
        NtApi.NtTerminateThread = GetSsdtRoutineAddress(NtApi.NtTerminateThreadSn);
        NtApi.NtSuspendProcess = GetSsdtRoutineAddress(NtApi.NtSuspendProcessSn);
        NtApi.NtResumeThread = GetSsdtRoutineAddress(NtApi.NtResumeThreadSn);
        NtApi.NtSuspendThread = GetSsdtRoutineAddress(NtApi.NtSuspendThreadSn);
        NtApi.NtQueryAttributesFile = GetSsdtRoutineAddress(NtApi.NtQueryAttributesFileSn);
        NtApi.NtFlushBuffersFile = GetSsdtRoutineAddress(NtApi.NtFlushBuffersFileSn);
        NtApi.NtCreateProcess = GetSsdtRoutineAddress(NtApi.NtCreateProcessSn);
        NtApi.NtCreateProcessEx = GetSsdtRoutineAddress(NtApi.NtCreateProcessExSn);
        NtApi.NtQueryDirectoryObject = GetSsdtRoutineAddress(NtApi.NtQueryDirectoryObjectSn);
        NtApi.NtDeviceIoControlFile = GetSsdtRoutineAddress(NtApi.NtDeviceIoControlFileSn);
        NtApi.NtCancelTimer = GetSsdtRoutineAddress(NtApi.NtCancelTimerSn);
        NtApi.NtReplyWaitReceivePort = GetSsdtRoutineAddress(NtApi.NtReplyWaitReceivePortSn);
        NtApi.NtReplyWaitReceivePortEx = GetSsdtRoutineAddress(NtApi.NtReplyWaitReceivePortExSn);
        NtApi.NtPowerInformation = GetSsdtRoutineAddress(NtApi.NtPowerInformationSn);
        NtApi.NtSetSystemInformation = GetSsdtRoutineAddress(NtApi.NtSetSystemInformationSn);
        NtApi.NtWriteFile = GetSsdtRoutineAddress(NtApi.NtWriteFileSn);
        NtApi.NtReadFile = GetSsdtRoutineAddress(NtApi.NtReadFileSn);
    }

    // todo 动态获取其他api地址
    NtApi.NtQuerySystemInformation = GetSystemRoutineAddress((ptr)RtBlock.KrnlStart, "NtQuerySystemInformation");

}