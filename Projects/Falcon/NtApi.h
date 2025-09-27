#ifndef _NTAPI_H_
#define _NTAPI_H_



#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#include "LibDefs.h"
#else
#include <Defs.h>
    typedef struct _PS_CREATE_NOTIFY_INFO {
        SIZE_T              Size;
        union {
            ULONG Flags;
            struct {
                ULONG FileOpenNameAvailable : 1;
                ULONG IsSubsystemProcess : 1;
                ULONG Reserved : 30;
            };
        };
        HANDLE              ParentProcessId;
        CLIENT_ID           CreatingThreadId;
        struct _FILE_OBJECT* FileObject;
        PCUNICODE_STRING    ImageFileName;
        PCUNICODE_STRING    CommandLine;
        NTSTATUS            CreationStatus;
    } PS_CREATE_NOTIFY_INFO, * PPS_CREATE_NOTIFY_INFO;
#endif

    typedef VOID(* PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo
        );

	typedef struct _NTFUNC {

        ULONG32 NtAllocateVirtualMemorySn;
        ULONG32 NtQueryVirtualMemorySn;
        ULONG32 NtProtectVirtualMemorySn;
        ULONG32 NtWriteVirtualMemorySn;
        ULONG32 NtReadVirtualMemorySn;
        ULONG32 NtLockVirtualMemorySn;
        ULONG32 NtTerminateProcessSn;
        ULONG32 NtTerminateThreadSn;
        ULONG32 NtSuspendProcessSn;
        ULONG32 NtResumeThreadSn;
        ULONG32 NtSuspendThreadSn;
        ULONG32 NtQueryAttributesFileSn;
        ULONG32 NtFlushBuffersFileSn;
        ULONG32 NtCreateProcessSn;
        ULONG32 NtCreateProcessExSn;
        ULONG32 NtQueryDirectoryObjectSn;
        ULONG32 NtDeviceIoControlFileSn;
        ULONG32 NtCancelTimerSn;
        ULONG32 NtReplyWaitReceivePortSn;
        ULONG32 NtReplyWaitReceivePortExSn;
        ULONG32 NtPowerInformationSn;
        ULONG32 NtSetSystemInformationSn;
        ULONG32 NtWriteFileSn;
        ULONG32 NtReadFileSn;
         
        NTSTATUS
            (NTAPI *NtAllocateVirtualMemory)(
                __in HANDLE ProcessHandle,
                __inout PVOID* BaseAddress,
                __in ULONG_PTR ZeroBits,
                __inout PSIZE_T RegionSize,
                __in ULONG AllocationType,
                __in ULONG Protect
            );
        
        NTSTATUS
            (NTAPI *NtQueryVirtualMemory)(
                __in HANDLE ProcessHandle,
                __in PVOID BaseAddress,
                __in MEMORY_INFORMATION_CLASS MemoryInformationClass,
                __out_bcount(MemoryInformationLength) PVOID MemoryInformation,
                __in SIZE_T MemoryInformationLength,
                __out_opt PSIZE_T ReturnLength
            );

        NTSTATUS 
            (NTAPI *NtProtectVirtualMemory)(
                __in HANDLE ProcessHandle,
                __inout PVOID* BaseAddress,
                __inout PSIZE_T RegionSize,
                __in ULONG NewProtect,
                __out PULONG OldProtect
            );

        NTSTATUS
            (NTAPI *NtWriteVirtualMemory)(
                __in HANDLE ProcessHandle,
                __in_opt PVOID BaseAddress,
                __in_bcount(BufferSize) CONST VOID* Buffer,
                __in SIZE_T BufferSize,
                __out_opt PSIZE_T NumberOfBytesWritten
            );
        
        NTSTATUS
            (NTAPI *NtReadVirtualMemory)(
                __in HANDLE ProcessHandle,
                __in_opt PVOID BaseAddress,
                __out_bcount(BufferSize) PVOID Buffer,
                __in SIZE_T BufferSize,
                __out_opt PSIZE_T NumberOfBytesRead
            );

        NTSTATUS
            (NTAPI *NtLockVirtualMemory)(
                __in HANDLE ProcessHandle,
                __inout PVOID* BaseAddress,
                __inout PSIZE_T RegionSize,
                __in ULONG MapType
            );

        NTSTATUS
            (NTAPI *NtTerminateProcess)(
                __in_opt HANDLE ProcessHandle,
                __in NTSTATUS ExitStatus
            );

        NTSTATUS
            (NTAPI *NtTerminateThread)(
                __in_opt HANDLE ThreadHandle,
                __in NTSTATUS ExitStatus
            );

        NTSTATUS
            (NTAPI *NtSuspendProcess)(
                __in HANDLE ProcessHandle
            );

        NTSTATUS
            (NTAPI *NtResumeThread)(
                __in HANDLE ThreadHandle,
                __out_opt PULONG PreviousSuspendCount
            );

        NTSTATUS
            (NTAPI *NtSuspendThread)(
                __in HANDLE ThreadHandle,
                __out_opt PULONG PreviousSuspendCount
            );

        NTSTATUS
            (NTAPI *NtQueryAttributesFile)(
                __in POBJECT_ATTRIBUTES ObjectAttributes,
                __out PFILE_BASIC_INFORMATION FileInformation
            );
        
        NTSTATUS
            (NTAPI *NtFlushBuffersFile)(
                __in HANDLE FileHandle,
                __out PIO_STATUS_BLOCK IoStatusBlock
            );

        NTSTATUS
            (NTAPI *NtCreateProcess)(
                __out PHANDLE ProcessHandle,
                __in ACCESS_MASK DesiredAccess,
                __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                __in HANDLE ParentProcess,
                __in BOOLEAN InheritObjectTable,
                __in_opt HANDLE SectionHandle,
                __in_opt HANDLE DebugPort,
                __in_opt HANDLE ExceptionPort
            );

        NTSTATUS
            (NTAPI *NtCreateProcessEx)(
                __out PHANDLE ProcessHandle,
                __in ACCESS_MASK DesiredAccess,
                __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                __in HANDLE ParentProcess,
                __in ULONG Flags,
                __in_opt HANDLE SectionHandle,
                __in_opt HANDLE DebugPort,
                __in_opt HANDLE ExceptionPort,
                __in ULONG JobMemberLevel
            );

        NTSTATUS
            (NTAPI *NtQueryDirectoryObject)(
                __in HANDLE DirectoryHandle,
                __out_bcount_opt(Length) PVOID Buffer,
                __in ULONG Length,
                __in BOOLEAN ReturnSingleEntry,
                __in BOOLEAN RestartScan,
                __inout PULONG Context,
                __out_opt PULONG ReturnLength
            );

        NTSTATUS
            (NTAPI *NtDeviceIoControlFile)(
                __in HANDLE FileHandle,
                __in_opt HANDLE Event,
                __in_opt PIO_APC_ROUTINE ApcRoutine,
                __in_opt PVOID ApcContext,
                __out PIO_STATUS_BLOCK IoStatusBlock,
                __in ULONG IoControlCode,
                __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
                __in ULONG InputBufferLength,
                __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
                __in ULONG OutputBufferLength
            );

        NTSTATUS
            (NTAPI *NtCancelTimer)(
                __in HANDLE TimerHandle,
                __out_opt PBOOLEAN CurrentState
            );

        NTSTATUS
            (NTAPI *NtReplyWaitReceivePort)(
                __in HANDLE PortHandle,
                __out_opt PVOID* PortContext,
                __in_opt PPORT_MESSAGE ReplyMessage,
                __out PPORT_MESSAGE ReceiveMessage
            );

        NTSTATUS
            (NTAPI *NtReplyWaitReceivePortEx)(
                __in HANDLE PortHandle,
                __out_opt PVOID* PortContext,
                __in_opt PPORT_MESSAGE ReplyMessage,
                __out PPORT_MESSAGE ReceiveMessage,
                __in_opt PLARGE_INTEGER Timeout
            );

        NTSTATUS
            (NTAPI *NtPowerInformation)(
                __in POWER_INFORMATION_LEVEL InformationLevel,
                __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
                __in ULONG InputBufferLength,
                __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
                __in ULONG OutputBufferLength
            );
        
        NTSTATUS
            (NTAPI *NtSetSystemInformation)(
                __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
                __in_bcount_opt(SystemInformationLength) PVOID SystemInformation,
                __in ULONG SystemInformationLength
            );

        NTSTATUS
            (NTAPI *NtWriteFile)(
                __in HANDLE FileHandle,
                __in_opt HANDLE Event,
                __in_opt PIO_APC_ROUTINE ApcRoutine,
                __in_opt PVOID ApcContext,
                __out PIO_STATUS_BLOCK IoStatusBlock,
                __in_bcount(Length) PVOID Buffer,
                __in ULONG Length,
                __in_opt PLARGE_INTEGER ByteOffset,
                __in_opt PULONG Key
            );

        NTSTATUS
            (NTAPI *NtReadFile)(
                __in HANDLE FileHandle,
                __in_opt HANDLE Event,
                __in_opt PIO_APC_ROUTINE ApcRoutine,
                __in_opt PVOID ApcContext,
                __out PIO_STATUS_BLOCK IoStatusBlock,
                __out_bcount(Length) PVOID Buffer,
                __in ULONG Length,
                __in_opt PLARGE_INTEGER ByteOffset,
                __in_opt PULONG Key
            );
        
        NTSTATUS
            (NTAPI *NtOpenFile)(
                __out PHANDLE FileHandle,
                __in ACCESS_MASK DesiredAccess,
                __in POBJECT_ATTRIBUTES ObjectAttributes,
                __out PIO_STATUS_BLOCK IoStatusBlock,
                __in ULONG ShareAccess,
                __in ULONG OpenOptions
            );

        NTSTATUS
            (NTAPI* NtQuerySystemInformation)(
                __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
                __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
                __in ULONG SystemInformationLength,
                __out_opt PULONG ReturnLength
            );

       NTSTATUS
            (* PsSetLoadImageNotifyRoutine)(
                __in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
            );

       NTSTATUS 
            (* PsSetLoadImageNotifyRoutineEx)(
           PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
           ULONG_PTR                  Flags
       );

       NTSTATUS
           (*PsRemoveLoadImageNotifyRoutine)(
               __in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
           );

       NTSTATUS
           (*PsSetCreateThreadNotifyRoutine)(
               __in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
           );

       NTSTATUS
           (*PsSetCreateProcessNotifyRoutine)(
               __in PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
               __in BOOLEAN Remove
           );

       NTSTATUS 
           (* PsSetCreateProcessNotifyRoutineEx)(
           PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
           BOOLEAN                           Remove
        );

       SIZE_T
           (*RtlCompareMemory)(
               const VOID* Source1,
               const VOID* Source2,
               SIZE_T Length
           );

       VOID
           (NTAPI* RtlCaptureContext)(
               OUT PCONTEXT ContextRecord
           );

       VOID
           (* RtlRestoreContext)(
               IN PCONTEXT ContextRecord,
               IN struct _EXCEPTION_RECORD* ExceptionRecord OPTIONAL
           );

       VOID
            (*KeBugCheckEx)(
           __in ULONG BugCheckCode,
           __in ULONG_PTR P1,
           __in ULONG_PTR P2,
           __in ULONG_PTR P3,
           __in ULONG_PTR P4
           );

       BOOLEAN
            (*ExAcquireRundownProtection)(
           __inout PEX_RUNDOWN_REF RunRef
           );

       BOOLEAN
           (*MmIsAddressValid)(
               __in PVOID VirtualAddress
           );

       KPROCESSOR_MODE
            (*ExGetPreviousMode)(
           VOID
           );
       
       VOID
            (*ExQueueWorkItem)(
           __inout PWORK_QUEUE_ITEM WorkItem,
           __in WORK_QUEUE_TYPE QueueType
           );

       BOOLEAN
            (*KeSetTimer)(
           __inout PKTIMER Timer,
           __in LARGE_INTEGER DueTime,
           __in_opt PKDPC Dpc
           );

       PVOID
           (* IoGetInitialStack)(
               VOID
           );

       NTSTATUS
           (*IofCallDriver)(
               IN PDEVICE_OBJECT DeviceObject,
               IN OUT PIRP Irp
           );

	}NTFUNC,*PNTFUNC;

    typedef struct _SYSCALLRTB {
        KSERVICE_TABLE_DESCRIPTOR* KeServiceDescriptorTable;
        KSERVICE_TABLE_DESCRIPTOR* KeServiceDescriptorTableShadow;
    }SYSCALLRTB,*PSYSCALLRTB;

    PVOID GetSsdtRoutineAddress(ULONG32 num);
    PVOID GetSystemRoutineAddress(PVOID moduleBase, PUCHAR funcName);
    VOID InitNtApi();
    
    NTSTATUS
        NTAPI
        KeNtTerminateProcess(
            PVOID ProcessHandle,
            NTSTATUS ExitStatus
        );

    NTSTATUS
        NTAPI
        KeNtSuspendProcess(
            PVOID ProcessHandle
        );

    NTSTATUS
        NTAPI
        KeNtProtectVirtualMemory(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            PSIZE_T RegionSize,
            ULONG NewProtection,
            PULONG OldProtection
        );

    extern NTFUNC NtApi;
    extern SYSCALLRTB SysCallRtb;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _NTAPI_H_
