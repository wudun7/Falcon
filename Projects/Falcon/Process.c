
#include "Process.h"
#include "NtApi.h"
#include "PriDefs.h"
#include "Global.h"


NTSTATUS TerminateProcessByObject(PEPROCESS obj)
{
    NTSTATUS status = STATUS_ACCESS_DENIED;

#ifdef DEBUG

    ASSERT(RtBlock.PsInitialSystemProcess != 0);
#endif // DEBUG

    if (obj != RtBlock.PsInitialSystemProcess){

        ptr pHandle = NULL;
        status = ObOpenObjectByPointer(obj, 0, NULL, 0x29, NULL, KernelMode, &pHandle);

        if (NT_SUCCESS(status))
        {
            KeNtSuspendProcess(pHandle);
            ptr base = PsGetProcessSectionBaseAddress(obj);
            ZwUnmapViewOfSection(pHandle, base);
            status = KeNtTerminateProcess(pHandle, 0);
            ZwClose(pHandle);
        }
    }

    return status;
}

NTSTATUS TerminateProcessById(PVOID pid)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (HandleToULong(pid) > SYSTEMPID)
    {
        PEPROCESS pEprocess = NULL;
        status = PsLookupProcessByProcessId(pid, &pEprocess);

        if (NT_SUCCESS(status))
        {
            status = TerminateProcessByObject(pEprocess);
            ObDereferenceObject(pEprocess);
        }
    }

    return status;
}