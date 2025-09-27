
#include "File.h"
#include "Global.h"

typedef struct _FILEINFOWORKITEM {
    ptr FileObj;
    PUNICODE_STRING OutPath;
    KEVENT* Event;
    NTSTATUS Status;
}FILEINFOWORKITEM, * PFILEINFOWORKITEM;

NTSTATUS NewFileObject(ptr srcFileObj, ptr srcIndexNum, ptr* dstFileObj)
{
    ptr hDeviceObj = NULL;
    NTSTATUS status = ObOpenObjectByPointer(((PFILE_OBJECT)srcFileObj)->DeviceObject, OBJ_KERNEL_HANDLE, 0, 0, KernelMode, KernelMode, &hDeviceObj);

    if (NT_SUCCESS(status))
    {
        UNICODE_STRING buffer = { 0 };
        buffer.Length = sizeof(LARGE_INTEGER);
        buffer.MaximumLength = sizeof(LARGE_INTEGER);
        buffer.Buffer = srcIndexNum;

        OBJECT_ATTRIBUTES objAttr;
        RtlSecureZeroMemory(&objAttr, sizeof(objAttr));
        InitializeObjectAttributes(&objAttr, &buffer, OBJ_KERNEL_HANDLE, hDeviceObj, NULL);

        ptr hFile = NULL;
        IO_STATUS_BLOCK block = { 0 };
        status = ZwOpenFile(&hFile, GENERIC_READ, &objAttr, &block, FILE_SHARE_READ, FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE);

        if (NT_SUCCESS(status))
        {
            PFILE_OBJECT newObj = NULL;
            status = ObReferenceObjectByHandle(hFile, FILE_READ_ATTRIBUTES|FILE_READ_DATA, *IoFileObjectType, KernelMode, &newObj, NULL);

            if (NT_SUCCESS(status))
                *dstFileObj = newObj;

            ZwClose(hFile);
        }

        ZwClose(hDeviceObj);
    }

    return status;
}

VOID QueryFileDosNameRoutine( ptr param)
{
    PFILEINFOWORKITEM fileInfo = (PFILEINFOWORKITEM)param;
    FILE_INTERNAL_INFORMATION internalInfo = { 0 };
    POBJECT_NAME_INFORMATION dosName = NULL;
    PFILE_OBJECT pFileObj = NULL;
    u32 ret = 0;

    NTSTATUS status = IoQueryFileInformation(fileInfo->FileObj, FileInternalInformation, sizeof(FILE_INTERNAL_INFORMATION), &internalInfo, &ret);

    if (NT_SUCCESS(status))
    {
        status = NewFileObject(fileInfo->FileObj, &internalInfo, &pFileObj);

        if (NT_SUCCESS(status))
        {
            status = IoQueryFileDosDeviceName(pFileObj, &dosName);
            ObfDereferenceObject(pFileObj);

            if (NT_SUCCESS(status))
            {
                RtlCopyUnicodeString(fileInfo->OutPath, &dosName->Name);
                ExFreePoolWithTag(&dosName->Name, 0);
            }
        }

        if (!NT_SUCCESS(status))
        {
            status = IoQueryFileDosDeviceName(fileInfo->FileObj, &dosName);

            if (NT_SUCCESS(status))
            {
                RtlCopyUnicodeString(fileInfo->OutPath, &dosName->Name);
                ExFreePoolWithTag(&dosName->Name, 0);
            }
        }
    }

    fileInfo->Status = status;
    KeSetEvent(fileInfo->Event, FALSE, FALSE);
}

NTSTATUS SyncQueryFileDosName(PVOID fileObj, PUNICODE_STRING out)
{
    KEVENT event = { 0 };
    WORK_QUEUE_ITEM item = { 0 };
    FILEINFOWORKITEM param = { 0 };

    param.FileObj = fileObj;
    param.Event = &event;
    param.OutPath = out;
    param.Status = STATUS_UNSUCCESSFUL;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    item.WorkerRoutine = QueryFileDosNameRoutine;
    item.Parameter = &param;
    item.List.Flink = 0;
    ExQueueWorkItem(&item, DelayedWorkQueue);
    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
    return param.Status;
}
