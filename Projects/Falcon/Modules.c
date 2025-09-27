
#include "Modules.h"
#include "Global.h"
#include "PriDefs.h"
#include "Memory.h"
#include "NtApi.h"

typedef struct _KERNELMODULEINIFO
{
    ptr Target; //目标地址
    ptr* OutBase;
    size_t* OutImageSize;
    UNICODE_STRING* OutPath;
    b Result;
}KERNELMODULEINIFO, * KERNELPMODULEINIFO;

b CallbackRoutine(RTL_PROCESS_MODULE_INFORMATION* moduleinfo, ptr routine)
{
    if (RtBlock.KrnlStart || moduleinfo->LoadOrderIndex &&
        (routine < (ptr)((u8ptr)moduleinfo->ImageBase)|| routine >(ptr)(((u8ptr)moduleinfo->ImageBase + moduleinfo->ImageSize)))
        )
    {
        if (!RtBlock.FalconStart)
        {
            if ((u8ptr)CallbackRoutine > (u8ptr)moduleinfo->ImageBase &&
                (u8ptr)CallbackRoutine < (u8ptr)moduleinfo->ImageBase + moduleinfo->ImageSize)
            {
                RtBlock.FalconStart = (u)moduleinfo->ImageBase;
                RtBlock.FalconEnd = (u)moduleinfo->ImageBase + moduleinfo->ImageSize;
            }
        }
    }

    else
    {
        RtBlock.KrnlStart = (u)moduleinfo->ImageBase;
        RtBlock.KrnlEnd = (u)moduleinfo->ImageBase + moduleinfo->ImageSize;

        PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader(moduleinfo->ImageBase);

        if (pNtHeader)
            RtBlock.KrnlCheckSum = pNtHeader->OptionalHeader.CheckSum;

        ANSI_STRING moduleName = { 0 };
        UNICODE_STRING sysroot = { 0 };

        RtlInitAnsiString(&moduleName, &moduleinfo->FullPathName[moduleinfo->OffsetToFileName]);
        ptr buffer = ExAllocatePoolWithTag(PagedPool, MAXIMUM_FILENAME_LENGTH * sizeof(wc), POOLTAGTX);

        if (buffer)
        {
            RtlInitEmptyUnicodeString(&RtBlock.KrnlPath, buffer, MAXIMUM_FILENAME_LENGTH * sizeof(wc));

            RtlInitUnicodeString(&sysroot, L"\\SystemRoot\\System32\\");
            RtlCopyUnicodeString(&RtBlock.KrnlPath, &sysroot);

            RtlInitEmptyUnicodeString(&sysroot, 
                                     (wcptr)((u8ptr)RtBlock.KrnlPath.Buffer + RtBlock.KrnlPath.Length), 
                                     RtBlock.KrnlPath.MaximumLength - RtBlock.KrnlPath.Length
            );

            RtlAnsiStringToUnicodeString(&sysroot, &moduleName, FALSE);
            RtBlock.KrnlPath.Length += sysroot.Length;
        }
    }

    return 0;
}

NTSTATUS EnumModulesWithCallback(ModuleHandler callback, PVOID params)
{
    u32 size = 0;
    ptr lpBuffer = NULL;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    for (size = 0x40000;; size += 0x40000)
    {
        lpBuffer = ExAllocatePoolWithTag(PagedPool, size, POOLTAGTX);

        if (!lpBuffer)
            return status;


        status = ZwQuerySystemInformation(SystemModuleInformation, lpBuffer, size, NULL);

        if (status >= 0)
            break;

        if (lpBuffer)
            ExFreePoolWithTag(lpBuffer, POOLTAGTX);

        if (status != STATUS_INFO_LENGTH_MISMATCH)
            return status;
    }

    RTL_PROCESS_MODULES* pModuleInfo = lpBuffer;


    if (pModuleInfo->NumberOfModules)
    {
        u64 i = 0;

        RTL_PROCESS_MODULE_INFORMATION  module = pModuleInfo->Modules[i];

        while (!callback(&module, params))
        {
            i++;
            module = pModuleInfo->Modules[i];

            if (i >= pModuleInfo->NumberOfModules)
                break;
        }
    }

    ExFreePoolWithTag(lpBuffer, POOLTAGTX);
    return status;
}

NTSTATUS GetLoadedModulesInfo(PVOID buffer, SIZE_T size, PSIZE_T pRetLen)
{
    status st = STATUS_SUCCESS;

    if (RtBlock.PsLoadedModuleList)
    {
        ptr mp = NULL;
        PMDL pmdl = NULL;
        st = MdlMapVirtualMemory(buffer, size, ExGetPreviousMode(), IoWriteAccess, &mp, &pmdl);

        if (!NT_SUCCESS(st))
            return st;

        DbgPrint("PsLoadedModuleList: %llx , Flink: %p\n", RtBlock.PsLoadedModuleList, ((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink);

#ifdef _WIN64
        KLDR_DATA_TABLE_ENTRY64* pModuleInfo = (KLDR_DATA_TABLE_ENTRY64*)(((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink);
#else
        KLDR_DATA_TABLE_ENTRY32* pModuleInfo = (KLDR_DATA_TABLE_ENTRY32*)(((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink);
#endif // _WIN64

        LOADEDMODULEINFO* pCurBuffer = NULL;
        size_t totalSize = 0;
        u32 order = 0, nodeSize = 0;
        u16 maxLen = 0, pathLen = 0;
        
        if (RtBlock.PsLoadedModuleList != (u64)(((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink))
        {
            do {
                pCurBuffer = (LOADEDMODULEINFO*)((u8ptr)mp + totalSize);
                totalSize += sizeof(LOADEDMODULEINFO);
                UNICODE_STRING uniFullPath = { 0 };

                if (totalSize < size)
                {
                    pCurBuffer->Size = 0;
                    pCurBuffer->ModuleBase = pModuleInfo->DllBase;
                    pCurBuffer->MoudleSize = pModuleInfo->SizeOfImage;
                    pCurBuffer->ModuleOrder = order;
                    pCurBuffer->ModuleEntry = pModuleInfo->EntryPoint;
                    pCurBuffer->Path.Length = 0;
                    pCurBuffer->Path.MaximumLength = 0;

                    ++order;

                    if (!pModuleInfo->FullDllName.Buffer)
                    {
                        pCurBuffer->Size = sizeof(LOADEDMODULEINFO);
                        continue;
                    }

                    maxLen = (pModuleInfo->FullDllName.Length == pModuleInfo->FullDllName.MaximumLength) ? (pModuleInfo->FullDllName.MaximumLength + sizeof(wc)) : pModuleInfo->FullDllName.MaximumLength;

                    totalSize += maxLen;

                    if (totalSize < size)
                    {
                        RtlInitEmptyUnicodeString(&uniFullPath, (wcptr)((u8ptr)pCurBuffer + sizeof(LOADEDMODULEINFO)), maxLen);
                        RtlCopyUnicodeString(&uniFullPath, (UNICODE_STRING*)&pModuleInfo->FullDllName);
                        nodeSize = maxLen + sizeof(LOADEDMODULEINFO);
                        pathLen = uniFullPath.Length & ~1;
                        uniFullPath.Buffer[pathLen / sizeof(wc)] = L'\0';
                        pCurBuffer->Path.Length = pathLen;
                        pCurBuffer->Path.MaximumLength = maxLen;
                        pCurBuffer->Path.Buffer = (wcptr)((u8ptr)buffer + totalSize - maxLen);
                        pCurBuffer->Size = nodeSize;
                    }
                }

                else
                {
                    st = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }

#ifdef _WIN64
                pModuleInfo = (KLDR_DATA_TABLE_ENTRY64*)(pModuleInfo->InLoadOrderLinks.Flink);
#else
                pModuleInfo = (KLDR_DATA_TABLE_ENTRY32*)(pModuleInfo->InLoadOrderLinks.Flink);
#endif // _WIN64

            } while ((u64)pModuleInfo != RtBlock.PsLoadedModuleList);

        }

        else
        {
            pCurBuffer = (LOADEDMODULEINFO*)mp;
        }

        if (NT_SUCCESS(st))
            pCurBuffer->Size = 0;

        if (pRetLen)
            *pRetLen = totalSize;

        if (pmdl)
        {
            MmUnlockPages(pmdl);
            IoFreeMdl(pmdl);
        }
    }
    else
    {
        st = STATUS_NOT_FOUND;
    }

    return st;
}

b QuerySpecificKernelModuleInfo(ptr target, ptr* outBase, size_t* outImageSize, UNICODE_STRING* outPath)
{
    b result = FALSE;

    if (!RtBlock.PsLoadedModuleList)
        return result;

    if (target < RtBlock.MmSystemRangeStart ||
        ((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink == (LIST_ENTRY*)RtBlock.PsLoadedModuleList)
        return result;

#ifdef _WIN64
    KLDR_DATA_TABLE_ENTRY64* pModule = (KLDR_DATA_TABLE_ENTRY64*)(((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink);
#else
    KLDR_DATA_TABLE_ENTRY32* pModule = (KLDR_DATA_TABLE_ENTRY32*)(((LIST_ENTRY*)RtBlock.PsLoadedModuleList)->Flink);
#endif // _WIN64

    do
    {
        ptr pModuleEnd = (ptr)(pModule->DllBase + pModule->SizeOfImage);

        if (IsAddressInRange(&target, &((ptr)pModule->DllBase), &pModuleEnd))
            break;

#ifdef _WIN64

        pModule = (KLDR_DATA_TABLE_ENTRY64*)pModule->InLoadOrderLinks.Flink;
#else
        pModule = (KLDR_DATA_TABLE_ENTRY32*)pModule->InLoadOrderLinks.Flink;

#endif // _WIN64

    } while ((u64)pModule != RtBlock.PsLoadedModuleList);

    if (outBase)
        *outBase = (ptr)pModule->DllBase;

    if (outImageSize)
        *outImageSize = pModule->SizeOfImage;

    if (outPath)
        RtlCopyUnicodeString(outPath, (UNICODE_STRING*)&pModule->FullDllName);

    result = TRUE;

    return result;
}

b InterruptQuerySpecificModuleInfoCallback(KERNELMODULEINIFO* info)
{
    b result = QuerySpecificKernelModuleInfo(info->Target, info->OutBase, info->OutImageSize, info->OutPath);
    info->Result = result;
    return result;
}

BOOLEAN QuerySpecificKernelModuleInfoWithDpc(PVOID target, PVOID* outBase, PSIZE_T outImageSize, PUNICODE_STRING outPath)
{
    KERNELMODULEINIFO info;
    info.Target = target;
    info.OutBase = outBase;
    info.OutImageSize = outImageSize;
    info.OutPath = outPath;
    info.Result = FALSE;

    SyncDpcExecuteProxy((ptr)InterruptQuerySpecificModuleInfoCallback, &info);
    return info.Result;
}

PVOID GetModuleBaseByAddress(PVOID target)
{
    ptr pBase = NULL;
    QuerySpecificKernelModuleInfo(target, &pBase, NULL, NULL);
    return pBase;
}

b IsTrustedModule(PCUNICODE_STRING filePath)
{
    ptr fileHandle = NULL;
    ptr sectionHandle = NULL;
    ptr baseAddress = NULL;
    size_t viewSize = 0;
    b bTrusted = FALSE;

    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    InitializeObjectAttributes(&objectAttributes,
        filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status st = ZwCreateFile(&fileHandle,
        0x80000000,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NO_EA_KNOWLEDGE | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (NT_SUCCESS(st))
    {
        InitializeObjectAttributes(&objectAttributes,
            NULL,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        st = ZwCreateSection(&sectionHandle,
            STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY,
            &objectAttributes,
            NULL,
            PAGE_READONLY,
            SEC_COMMIT,
            fileHandle);

        if (NT_SUCCESS(st))
        {
            st = ZwMapViewOfSection(sectionHandle,
                NtCurrentProcess(),
                &baseAddress,
                0,
                0,
                NULL,
                &viewSize,
                ViewUnmap,
                0,
                PAGE_READONLY);

            if (NT_SUCCESS(st))
            {
                if (baseAddress \
                    && viewSize >= sizeof(IMAGE_DOS_HEADER) \
                    && ((PIMAGE_DOS_HEADER)baseAddress)->e_magic == IMAGE_DOS_SIGNATURE \
                    && viewSize >= sizeof(IMAGE_NT_HEADERS) \
                    && RtlImageNtHeader(baseAddress)->Signature == IMAGE_NT_SIGNATURE\
                    && viewSize >= RtlImageNtHeader(baseAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress \
                    + RtlImageNtHeader(baseAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size \
                    && RtlImageNtHeader(baseAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 4 \
                    )
                {
                    u8ptr pSignStart = (u8ptr)baseAddress + RtlImageNtHeader(baseAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    u8ptr pSignString = pSignStart + 0x6;
                    u32 index = 0;

                    do {

                        if (index >= RtlImageNtHeader(baseAddress)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size - 4)
                        {
                            bTrusted = FALSE;
                            break;
                        }

                        if (__rds32(pSignStart + index) == 0xA045503 && !memcmp(pSignString + index, "Microsoft Corporation", __rdu8(pSignStart + index + 5)))
                        {
                            bTrusted = TRUE;
                            break;
                        }

                        index++;

                    } while (TRUE);
                }
            }
        }
    }

    if (baseAddress)
        ZwUnmapViewOfSection(NtCurrentProcess(), baseAddress);

    if (sectionHandle)
        NtClose(sectionHandle);

    if (fileHandle)
        NtClose(fileHandle);

    return bTrusted;
}

NTSTATUS QueryTrustedModule()
{
    status st = STATUS_INVALID_ADDRESS;

    if (!NtApi.NtQuerySystemInformation)
        return st;

    u32 retLen = 0;
    st = NtApi.NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &retLen);

    if (retLen == 0)
        return st;

    ptr pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, ROUND_TO_PAGES(retLen), '0000');

    if (pModuleInfo)
    {

        st = NtApi.NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, ROUND_TO_PAGES(retLen), &retLen);

        if (NT_SUCCESS(st))
        {
            PRTL_PROCESS_MODULES pms = pModuleInfo;

            if (pms->NumberOfModules)
            {
                u32 index = 0;

                do {
                    ANSI_STRING name = { 0 };
                    UNICODE_STRING uname = { 0 };
                    RtlInitAnsiString(&name, pms->Modules[index].FullPathName);

                    if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uname, &name, TRUE)))
                    {
                        if (IsTrustedModule(&uname))
                        {
                            //todo 放到stl中

                        }
                        RtlFreeUnicodeString(&uname);
                    }

                    index++;
                } while (index <= pms->NumberOfModules);
                
            }
        }

        ExFreePoolWithTag(pModuleInfo, '0000');
    }
    else
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return st;
}

NTSTATUS InitSelfAndKrnl()
{
    UNICODE_STRING name = { 0 };
    RtlInitUnicodeString(&name, L"NtOpenFile");
    ptr pNtOpenFile = MmGetSystemRoutineAddress(&name);
    return EnumModulesWithCallback(CallbackRoutine, pNtOpenFile);
}