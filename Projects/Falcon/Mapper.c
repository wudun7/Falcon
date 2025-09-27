
#include "Mapper.h"
#include "Global.h"
#include "File.h"

MAPPERRTB NtdllMappedInfo;

NTSTATUS MapNtdll()
{
    ptr object = NULL;
    UNICODE_STRING wow64 = { 0 };
    RtlInitUnicodeString(&wow64, L"\\SystemRoot\\SysWOW64\\ntdll.dll");

    IO_STATUS_BLOCK block = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    RtlSecureZeroMemory(&objAttr, sizeof(objAttr));
    NTSTATUS status = STATUS_SUCCESS;

    InitializeObjectAttributes(&objAttr, &wow64, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    do {
        status = ZwOpenFile(&NtdllMappedInfo.NtdllWow64Handle, FILE_GENERIC_READ, &objAttr, &block, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);

        if (status == STATUS_SHARING_VIOLATION)
        {
            status = ZwOpenFile(&NtdllMappedInfo.NtdllWow64Handle, FILE_GENERIC_READ, &objAttr, &block, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

            if (!NT_SUCCESS(status))
                break;
        }

        objAttr.ObjectName = NULL;
        status = ZwCreateSection(&NtdllMappedInfo.NtdllWow64SecHandle, SECTION_ALL_ACCESS, &objAttr, 0, PAGE_READONLY, SEC_IMAGE, NtdllMappedInfo.NtdllWow64Handle);

        if (!NT_SUCCESS(status))
            break;

        status = ZwMapViewOfSection(NtdllMappedInfo.NtdllWow64SecHandle, NtCurrentProcess(), &NtdllMappedInfo.NtdllWow64Base, 0, 0, 0, &NtdllMappedInfo.NtdllWow64ViewSize, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);

        if (!NT_SUCCESS(status))
            break;

         ptr buffer = ExAllocatePoolWithTag(PagedPool, MAXIMUM_FILENAME_LENGTH * sizeof(wc), POOLTAGTX);

        if (buffer)
        {
            RtlInitEmptyUnicodeString(&NtdllMappedInfo.NtdllWow64Path, buffer, MAXIMUM_FILENAME_LENGTH * sizeof(wc));

            if (ObReferenceObjectByHandle(NtdllMappedInfo.NtdllWow64Handle, FILE_GENERIC_READ, *IoFileObjectType, KernelMode, &object, 0) >= 0)
            {
                SyncQueryFileDosName(object, &NtdllMappedInfo.NtdllWow64Path);
                ObDereferenceObject(object);
            }
        }

    } while (0);

    do {

        UNICODE_STRING path = { 0 };
        RtlInitUnicodeString(&path, L"\\SystemRoot\\System32\\ntdll.dll");

        RtlSecureZeroMemory(&objAttr, sizeof(objAttr));
        InitializeObjectAttributes(&objAttr, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        ptr hNative = NULL;
        status = ZwOpenFile(&hNative, FILE_GENERIC_READ, &objAttr, &block, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);

        if (status == STATUS_SHARING_VIOLATION)
        {
            status = ZwOpenFile(&hNative, FILE_GENERIC_READ, &objAttr, &block, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

            if (!NT_SUCCESS(status))
                break;
        }

        ptr buffer = ExAllocatePoolWithTag(PagedPool, MAXIMUM_FILENAME_LENGTH * sizeof(wc), POOLTAGTX);

        if (buffer)
        {
            RtlInitEmptyUnicodeString(&NtdllMappedInfo.NtdllPath, buffer, MAXIMUM_FILENAME_LENGTH * sizeof(wc));

            if (ObReferenceObjectByHandle(hNative, FILE_GENERIC_READ, *IoFileObjectType, KernelMode, &object, 0) >= 0)
            {
                SyncQueryFileDosName(object, &NtdllMappedInfo.NtdllPath);
                ObDereferenceObject(object);
            }
        }

        ZwClose(hNative);

    } while (0);

    return status;
}

NTSTATUS MapNtoskrnlFileWithCallback(NTOSMAPPERCALLBACK callback)
{
#ifdef DEBUG
    ASSERT(RtBlock.KrnlPath.Length > 0 && RtBlock.KrnlPath.Buffer > 0);
#endif // DEBUG

    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioBlock;
    InitializeObjectAttributes(&objAttr, &RtBlock.KrnlPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    ptr hNtos = NULL;
    status st = ZwOpenFile(&hNtos, FILE_GENERIC_READ, &objAttr, &ioBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);

    if (st == STATUS_SHARING_VIOLATION)
        st = ZwOpenFile(&hNtos, FILE_GENERIC_READ, &objAttr, &ioBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);

    if (NT_SUCCESS(st))
    {
        ptr hSection = NULL;
        objAttr.ObjectName = NULL;
        st = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttr, 0, PAGE_READONLY, SEC_IMAGE, hNtos);

        if (NT_SUCCESS(st))
        {
            ptr mappedSection = NULL;
            size_t viewSize = 0;
            st = ZwMapViewOfSection(hSection, NtCurrentProcess(), &mappedSection, 0, 0, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);

            if (NT_SUCCESS(st))
            {
                callback(mappedSection, viewSize);
                ZwUnmapViewOfSection(NtCurrentProcess(), mappedSection);
            }

            ZwClose(hSection);
        }

        ZwClose(hNtos);
    }

    return st;
}
