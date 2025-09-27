
#include "Neac.h"
#include "PriDefs.h"
#include "Process.h"
#include "Global.h"
#include "Thread.h"
#include "Memory.h"
#include "SysPool.h"
#include "Space.h"
#include "Modules.h"


NTSTATUS NeacGetProcessInfomation(PVOID pid)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PROCESSINFO pi = { 0 };

    if (HandleToULong(pid) > SYSTEMPID)
    {
        PEPROCESS p = NULL;
        status = PsLookupProcessByProcessId(pid, &p);

        if (NT_SUCCESS(status))
        {
            pi.ParentId = HandleToULong(PsGetProcessInheritedFromUniqueProcessId(p));
            pi.CreateTime = PsGetProcessCreateTimeQuadPart(p);

            ptr hp = NULL;
            OBJECT_ATTRIBUTES objAttr = { 0 };
            CLIENT_ID cid = { pid,0 };
            PROCESS_SESSION_INFORMATION sessionInfo;

            InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            status  = ZwOpenProcess(&hp, PROCESS_QUERY_INFORMATION, &objAttr, &cid);

            if (NT_SUCCESS(status))
            {

                status = ZwQueryInformationProcess( hp,
                                                    ProcessSessionInformation,
                                                    &sessionInfo,
                                                    sizeof(sessionInfo),
                                                    0
                );

                if (NT_SUCCESS(status))
                    pi.SessionId = sessionInfo.SessionId;

                u32 critical = 0;
                ZwQueryInformationProcess(hp, ProcessBreakOnTermination, &critical, sizeof(u32), 0);
                pi.IsCritical = (critical != 0);

                KERNEL_USER_TIMES  times = { 0 };

                status = ZwQueryInformationProcess(hp, ProcessTimes, &times, sizeof(times), 0);

                if (NT_SUCCESS(status))
                {
                    pi.KernelTime = times.KernelTime;
                    pi.UserTime = times.UserTime;
                }
                ZwClose(hp);
            }

            pi.Is64 = (PsGetProcessWow64Process(p) == 0);
            pi.DebugPort = (u64)PsGetProcessDebugPort(p);

            ObDereferenceObject(p);
        }
    }

    return status;
}

NTSTATUS NeacGetProcessExitStatus(PROCESSEXITSTATUS* buffer, u64 bufSize, u64ptr retLen)
{
    UNREFERENCED_PARAMETER(bufSize);
    
    PEPROCESS p = NULL;
    NTSTATUS  status = PsLookupProcessByProcessId(buffer->Pid, &p);

    if (NT_SUCCESS(status))
    {
        status = PsGetProcessExitStatus(p);
        ObDereferenceObject(p);
    }

    buffer->ExitStatus = status;

    if (retLen)
        *retLen = 0x4;
    
    return status;
}

NTSTATUS NeacTerminateProcess(PVOID pid)
{
    return TerminateProcessById(pid);
}

NTSTATUS NeacGetProcessBase(PVOID pid)
{
    PEPROCESS p = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &p);
    ptr  base = NULL;

    if (NT_SUCCESS(status))
    {
        base = PsGetProcessSectionBaseAddress(p);
        ObDereferenceObject(p);
    }
    return status;
}

NTSTATUS NeacGetThreadProcessAndPid(PVOID tid)
{
    status st = STATUS_INVALID_PARAMETER;
    PETHREAD t = NULL;
    PEPROCESS p = NULL;
    u32 pid = 0;

    st = PsLookupThreadByThreadId(tid, &t);
    
    if (NT_SUCCESS(st))
    {
#ifdef _WIN64
        p = (PEPROCESS)__rds64((CHAR*)t + 0xb8); // wtf ??
#endif // _WIN64

        pid = HandleToULong(PsGetProcessId(p));
        st = STATUS_SUCCESS;
        ObDereferenceObject(t);
    }
    
    return st;
}

NTSTATUS NeacQueryThreadStackFrame(PVOID tid, PVOID outBuffer, ULONG32 outLen)
{
    status st = STATUS_INVALID_PARAMETER;
    PETHREAD t = NULL;

    if (outLen < sizeof(ptr) || outLen > MAX_CALLERS_BUFFER_SIZE)
        return st;

    st = PsLookupThreadByThreadId(tid, &t);

    if (NT_SUCCESS(st))
    {
        st = STATUS_THREAD_IS_TERMINATING;

        do {

            if (PsIsThreadTerminating(t))
                break;

            u32 cc = outLen / sizeof(ptr);

            ptr* pcb = (ptr*)ExAllocatePoolWithTag(NonPagedPool, (outLen & 0x3F8), POOLTAGTX);
            RtlSecureZeroMemory(pcb, outLen & 0x3F8);

            if (!pcb)
            {
                st = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            st = ThreadStackWalk(t, pcb, &cc);

            if (NT_SUCCESS(st))
            {
                u32 idx = 0;

                do {

                    *((ptr*)outBuffer + idx) = pcb[idx];
                    idx++;

                } while (idx < cc);

                st = STATUS_SUCCESS;
            }

            ExFreePoolWithTag(pcb, POOLTAGTX);

        } while (0);

        ObDereferenceObject(t);
        return st;
    }
    return st;
}

NTSTATUS NeacQueryThreadInfoByThreadId(PVOID tid)
{
    PETHREAD thread = NULL;
    status st = PsLookupThreadByThreadId(tid, &thread);
    ptr hThread = 0;
    ptr startAddress = NULL;
    u32 breakOnTermination = 0;
    KERNEL_USER_TIMES  times;
    LARGE_INTEGER createTime, kernelTime, userTime;
    b isSystemThread = FALSE;
    ptr processId = 0;

    if (NT_SUCCESS(st))
    {
        st = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL, THREAD_ALL_ACCESS, 0, 0, &hThread);

        if (NT_SUCCESS(st))
        {
            ZwQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(ptr), NULL);
            ZwQueryInformationThread(hThread, ThreadBreakOnTermination, &breakOnTermination, sizeof(ptr), NULL);

            if ( NT_SUCCESS(ZwQueryInformationThread(hThread, ThreadTimes, &times, sizeof(times), 0)))
            {
                createTime = times.CreateTime;
                kernelTime = times.KernelTime;
                userTime = times.UserTime;
            }

            isSystemThread = PsIsSystemThread(thread);
            processId = PsGetThreadProcessId(thread);
            ZwClose(hThread);
        }

        ObDereferenceObject(thread);
    }

    if (processId)
    {
        // todo »ØÐ´buffer
    }

    return st;
}

NTSTATUS NeacReadVirtualMemory(PVOID pid, PVOID src, PVOID dst, ULONG32 len, PULONG32 retLen)
{
    NTSTATUS st = STATUS_INVALID_PARAMETER;

    if (HandleToULong(pid) >= SYSTEMPID)
    {
        PEPROCESS psp = NULL;
        st = PsLookupProcessByProcessId(pid, &psp);

        if (NT_SUCCESS(st))
        {
            PEPROCESS pdp = IoGetCurrentProcess();
            u32 readed = 0;

            st = ReadWriteProcessMemory(psp, src, pdp, dst, len, UserMode, &readed);

            if ((st == STATUS_PARTIAL_COPY || NT_SUCCESS(st)) && retLen)
                *retLen = readed;

            ObDereferenceObject(psp);
        }
    }

    return st;
}

NTSTATUS NeacWriteVirtualMemory(PVOID pid, PVOID src, PVOID dst, ULONG32 len, PULONG32 retLen)
{
    NTSTATUS st = STATUS_INVALID_PARAMETER;

    if (HandleToULong(pid) >= SYSTEMPID)
    {
        PEPROCESS pdp = NULL;
        st = PsLookupProcessByProcessId(pid, &pdp);

        if (st >= 0)
        {
            PEPROCESS psp = IoGetCurrentProcess();
            u32 writed = 0;

            st = ReadWriteProcessMemory(psp, src, pdp, dst, len, UserMode, &writed);

            if ((st == STATUS_PARTIAL_COPY || st >= 0) && retLen)
                *retLen = writed;

            ObDereferenceObject(psp);
        }
    }

    return st;
}

NTSTATUS NeacVirtualProtectMemory(PVOID pid, PVOID target, ULONG32 size, ULONG32 newpro)
{
    status st = STATUS_INVALID_PARAMETER;

    if (HandleToULong(pid) >= SYSTEMPID)
    {
        PEPROCESS p = NULL;
        st = PsLookupProcessByProcessId(pid, &p);

        if (NT_SUCCESS(st))
        {
            KAPC_STATE apcState;
            KeStackAttachProcess((PRKPROCESS)p, &apcState);
            ptr base = target;
            size_t region = size;
            u32 oldPro = 0;
            st = KeNtProtectVirtualMemory(NtCurrentProcess(), &base, &region, newpro, &oldPro);
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(p);
        }
    }

    return st;
}

NTSTATUS NeacReadKernelMemory(PVOID target, SIZE_T readSize, PVOID outBuffer, SIZE_T bufferSize, PSIZE_T pReaded)
{
    KPROCESSOR_MODE mode = ExGetPreviousMode();
    size_t toRead = readSize < bufferSize ? readSize : bufferSize;
    ptr pMapped = NULL;
    PMDL pMdl = NULL;
    status st = STATUS_ACCESS_VIOLATION;

    __try {
        ProbeForWrite(outBuffer, bufferSize, 0x1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return st;
    }

    st = MdlMapVirtualMemory(outBuffer, bufferSize, mode, IoWriteAccess, &pMapped, &pMdl);

    if (NT_SUCCESS(st) && pMapped > 0)
    {
        size_t readed = 0;
        st = ReadKernelVirtualMemory(pMapped, target, toRead, &readed);

        if(pReaded)
            *pReaded = readed;

        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
    }

    return st;
}

NTSTATUS NeacWriteKernelMeory(PVOID target, SIZE_T writeSize, PVOID inBuffer, SIZE_T bufferSize)
{
    KPROCESSOR_MODE mode = ExGetPreviousMode();
    size_t toWrite = writeSize < bufferSize ? writeSize : bufferSize;
    ptr pMapped = NULL;
    PMDL pMdl = NULL;
    status st = MdlMapVirtualMemory(inBuffer, toWrite, mode, IoReadAccess, &pMapped, &pMdl);

    if (NT_SUCCESS(st) && pMapped)
    {
        __try {
            if (MmIsAddressValid(target))
                memcpy(target, pMapped, toWrite);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

            st = STATUS_ACCESS_DENIED;
        }

        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
    }

    return st;
}

NTSTATUS NeacSearchPoolImage(PVOID outBuffer, SIZE_T outlen)
{
    u32 retLen = 0;
    return SacnBigPoolAndFindImage(outBuffer, outlen, &retLen);
}

NTSTATUS NeacQueryAddressPoolInfo(PVOID target)
{
    ptr poolstart = NULL;
    size_t poolsize = 0;
    GetPoolInfoByAddress(target, &poolstart, &poolsize);
    status st = STATUS_NOT_FOUND;

    if (poolstart && poolsize)
    {
        u32 pagesize = 0;
        u32 attributes = 0;
        CheckPageSizeWithAttributes(target, &pagesize, &attributes);
        return STATUS_SUCCESS;
    }

    return st;
}

NTSTATUS NeacQueryLoadedModuleListInfo(PVOID buffer, SIZE_T size, PSIZE_T pRetLen)
{
    return GetLoadedModulesInfo(buffer, size, pRetLen);
}

NTSTATUS NeacQueryKernelModuleInfo(PVOID target)
{
    ptr buffer = ExAllocatePoolWithTag(NonPagedPool, 0x400, POOLTAGTX);
    status st = STATUS_INFO_LENGTH_MISMATCH;

    if (buffer)
    {
        UNICODE_STRING modulePath = { 0 };
        RtlInitEmptyUnicodeString(&modulePath, buffer, 0x400);
        ptr outBase = NULL;
        size_t outImageSize = 0;
        QuerySpecificKernelModuleInfoWithDpc(target, &outBase, &outImageSize, &modulePath);

#ifdef DEBUG
        DbgPrint("base: %p imagesize: %x path: %wZ", outBase, outImageSize, modulePath);
#endif // DEBUG

        st = STATUS_SUCCESS;
    }

    if (buffer)
        ExFreePoolWithTag(buffer, POOLTAGTX);

    return st;
}

NTSTATUS NeacQueryFileSize(PUNICODE_STRING path)
{
    size_t fileSize = 0;
    status st = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES obj = { 0 };
    InitializeObjectAttributes(&obj, path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    ptr hFile = NULL;
    IO_STATUS_BLOCK io = { 0 };
    FILE_STANDARD_INFORMATION finfo = { 0 };
    
    st = ZwOpenFile(&hFile, \
                    GENERIC_READ | SYNCHRONIZE, \
                    &obj, \
                    &io, \
                    FILE_SHARE_READ | FILE_SHARE_WRITE, \
                    FILE_SYNCHRONOUS_IO_NONALERT);

    if (st == STATUS_SHARING_VIOLATION)
        st = ZwOpenFile(&hFile, \
                        GENERIC_READ | SYNCHRONIZE, \
                        &obj,\
                        &io, \
                        FILE_SHARE_READ, \
                        FILE_SYNCHRONOUS_IO_NONALERT);

    if (NT_SUCCESS(st))
    {
        st = ZwQueryInformationFile(hFile, &io, &finfo, sizeof(finfo), FileStandardInformation);

        if (NT_SUCCESS(st))
            fileSize = finfo.EndOfFile.QuadPart;

        ZwClose(hFile);
    }

    return st;

}

NTSTATUS NeacQueryFileIndexNumber(PUNICODE_STRING path)
{
    ptr hFile = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    IO_STATUS_BLOCK ioBlock = { 0 };
    status st = ZwOpenFile(&hFile, \
                                 GENERIC_READ | SYNCHRONIZE,\
                                 &objAttr, \
                                 &ioBlock, \
                                 FILE_SHARE_WRITE | FILE_SHARE_READ, \
                                 FILE_SYNCHRONOUS_IO_NONALERT);

    if (st == STATUS_SHARING_VIOLATION)
        st = ZwOpenFile(&hFile, \
                        GENERIC_READ | SYNCHRONIZE, \
                        &objAttr, \
                        &ioBlock, \
                        FILE_SHARE_READ, \
                        FILE_SYNCHRONOUS_IO_NONALERT);

    FILE_INTERNAL_INFORMATION internalInfo = { 0 };
    LARGE_INTEGER index;

    if (NT_SUCCESS(st))
    {
        st = ZwQueryInformationFile(hFile, &ioBlock, &internalInfo, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation);

        if (NT_SUCCESS(st))
            index = internalInfo.IndexNumber;

        ZwClose(hFile);
    }

    return st;
}

NTSTATUS NeacMapCr3(PVOID pid)
{
    PEPROCESS p = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(pid, &p);

    if (NT_SUCCESS(st))
    {
        KAPC_STATE apc = { 0 };
        ptr cr3 = NULL;
        PMMPTE recr3 = NULL;

        KeStackAttachProcess((PRKPROCESS)p, &apc);
        cr3 = (ptr)__readcr3();
        KeUnstackDetachProcess(&apc);
        recr3 = MapPageTableToVirtualAddress((PMMPTE)&cr3);
        ObfDereferenceObject(p);
    }

    return st;
}