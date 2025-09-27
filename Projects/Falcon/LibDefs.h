#ifndef _LIBDEFS_H_
#define _LIBDEFS_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB

#if defined(USE_LPC6432)
#define LPC_CLIENT_ID CLIENT_ID64
#define LPC_SIZE_T ULONGLONG
#define LPC_PVOID ULONGLONG
#define LPC_HANDLE ULONGLONG
#else
#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#endif

    typedef struct _PORT_MESSAGE {
        union {
            struct {
                CSHORT DataLength;
                CSHORT TotalLength;
            } s1;
            ULONG Length;
    } u1;
        union {
            struct {
                CSHORT Type;
                CSHORT DataInfoOffset;
            } s2;
            ULONG ZeroInit;
        } u2;
        union {
            LPC_CLIENT_ID ClientId;
            double DoNotUseThisField;       // Force quadword alignment
        };
        ULONG MessageId;
        union {
            LPC_SIZE_T ClientViewSize;          // Only valid on LPC_CONNECTION_REQUEST message
            ULONG CallbackId;                   // Only valid on LPC_REQUEST message
        };
        //  UCHAR Data[];
    } PORT_MESSAGE, * PPORT_MESSAGE;


    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation,
        SystemProcessorInformation,             // obsolete...delete
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemObsolete0,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemVerifierAddDriverInformation,
        SystemVerifierRemoveDriverInformation,
        SystemProcessorIdleInformation,
        SystemLegacyDriverInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemTimeSlipNotification,
        SystemSessionCreate,
        SystemSessionDetach,
        SystemSessionInformation,
        SystemRangeStartInformation,
        SystemVerifierInformation,
        SystemVerifierThunkExtend,
        SystemSessionProcessInformation,
        SystemLoadGdiDriverInSystemSpace,
        SystemNumaProcessorMap,
        SystemPrefetcherInformation,
        SystemExtendedProcessInformation,
        SystemRecommendedSharedDataAlignment,
        SystemComPlusPackage,
        SystemNumaAvailableMemory,
        SystemProcessorPowerInformation,
        SystemEmulationBasicInformation,
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation,
        SystemLostDelayedWriteInformation,
        SystemBigPoolInformation,
        SystemSessionPoolTagInformation,
        SystemSessionMappedViewInformation,
        SystemHotpatchInformation,
        SystemObjectSecurityMode,
        SystemWatchdogTimerHandler,
        SystemWatchdogTimerInformation,
        SystemLogicalProcessorInformation,
        SystemWow64SharedInformation,
        SystemRegisterFirmwareTableInformationHandler,
        SystemFirmwareTableInformation,
        SystemModuleInformationEx,
        SystemVerifierTriageInformation,
        SystemSuperfetchInformation,
        SystemMemoryListInformation,
        SystemFileCacheInformationEx,
        MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _KSERVICE_TABLE_DESCRIPTOR {
        PULONG_PTR Base;
        PULONG Count;
        ULONG Limit;
        PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

    // --------------------------------------------------------------------
#define _HARDWARE_PTE_WORKING_SET_BITS  11

    typedef struct _RTL_PROCESS_MODULE_INFORMATION {
        HANDLE Section;                 // Not filled in
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR  FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    // ----------------------------------------------------------------------
#ifdef _WIN64

    typedef struct _MMPTE_HARDWARE {
        ULONGLONG Valid : 1;
#if defined(NT_UP)
        ULONGLONG Write : 1;        // UP version
#else
        ULONGLONG Writable : 1;        // changed for MP version
#endif
        ULONGLONG Owner : 1;
        ULONGLONG WriteThrough : 1;
        ULONGLONG CacheDisable : 1;
        ULONGLONG Accessed : 1;
        ULONGLONG Dirty : 1;
        ULONGLONG LargePage : 1;
        ULONGLONG Global : 1;
        ULONGLONG CopyOnWrite : 1; // software field
        ULONGLONG Prototype : 1;   // software field
#if defined(NT_UP)
        ULONGLONG reserved0 : 1;  // software field
#else
        ULONGLONG Write : 1;       // software field - MP change
#endif
        ULONGLONG PageFrameNumber : 28;
        ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
        ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
        ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

    typedef struct _MMPTE {
        union {
            ULONG_PTR Long;
            MMPTE_HARDWARE Hard;
        } u;
} MMPTE;

    typedef MMPTE* PMMPTE;
#endif // _WIN64



#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _LIBDEFS_H_