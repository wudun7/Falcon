#ifndef  _GLOBAL_H_
#define _GLOBAL_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "Mapper.h"
#include "NtApi.h"
#include "Thread.h"
#include "Dpc.h"

#ifdef NOMINILIB
\
#else
#include "..\..\..\WRK\base\ntos\mm\mi.h"
	typedef volatile LONG EX_SPIN_LOCK, * PEX_SPIN_LOCK;
#endif



#define POOLTAGTX 'SBTX'
#define MAX_STACK_CALLERS			  64
#define MAX_CALLERS_BUFFER_SIZE       ((MAX_STACK_CALLERS * sizeof(PVOID)) | 0x7)
#define _WINNT_NT4                    0x0400
#define _WINNT_WIN2K                  0x0500
#define _WINNT_WINXP                  0x0510
#define _WINNT_WS03                   0x0520
#define _WINNT_WIN6                   0x0600
#define _WINNT_VISTA                  0x0600
#define _WINNT_WS08                   0x0600
#define _WINNT_LONGHORN               0x0600
#define _WINNT_WIN7                   0x0610
#define _WINNT_WIN8                   0x0620
#define _WINNT_WINBLUE                0x0630
#define _WINNT_WINTHRESHOLD           0x0A00
#define _WINNT_WIN10                  0x0A00
	
#define MAKE_OS_VERSION(ma, mi) (((ma) << 8) | ((mi) << 4))

#define IsAddressInRange(ptarget, pstart, pend) \
    (*((PVOID*)(ptarget)) >= *((PVOID*)(pstart)) && *((PVOID*)(ptarget)) <= *((PVOID*)(pend)))

extern POBJECT_TYPE* IoFileObjectType;

typedef struct _POOL_BIG_PAGES {
	PVOID Va;
	UINT32 Key;
	UINT32 PoolType;
	SIZE_T NumberOfPages;
} POOL_BIG_PAGES, * PPOOL_BIG_PAGES;

#ifdef _WIN64                                           
C_ASSERT(sizeof(POOL_BIG_PAGES) == sizeof(ULONG_PTR) * 3);
#endif // _WIN64

typedef struct _POOL_BIG_PAGESEX {
	PVOID Va;
	UINT32 Key;
	UINT32 PoolType;
	SIZE_T NumberOfPages;
	SIZE_T Unuse;
} POOL_BIG_PAGESEX, * PPOOL_BIG_PAGESEX;

#ifdef _WIN64                                           
C_ASSERT(sizeof(POOL_BIG_PAGESEX) == sizeof(ULONG_PTR) * 4);
#endif // _WIN64


typedef struct _GRTBLOCK {

	ULONG_PTR KrnlStart;
	ULONG_PTR KrnlEnd;
	ULONG KrnlCheckSum;
	
	ULONG_PTR FalconStart;
	ULONG_PTR FalconEnd;

	UNICODE_STRING KrnlPath;
	
	ULONG32 NtBuildNumber;
	ULONG32 NtVersion;
	
	PEPROCESS PsInitialSystemProcess;
	PVOID MmSystemRangeStart;
	PVOID MmUserProbeAddress;
	UCHAR KeNumberProcessors;
	ULONG32 MiPagingLevels;

	PVOID PhysicalMemoryRanges; //卸载时需要释放

	ULONG64 PspCidTable;
	ULONG64 PsLoadedModuleList;
	ULONG64 MmPfnDatabase;
	ULONG64 MmNonPagedPoolStart;
	ULONG64 MmNonPagedPoolEnd;
	ULONG64 MmPagedPoolStart;
	ULONG64 MmPagedPoolEnd;
	ULONG64 MmAllocatedNonPagedPool;
	ULONG64 MmUnloadedDrivers;
	
#ifdef _WIN64
	ULONG64 PxeBase;
	ULONG64 PpeBase;
	ULONG64 PdeBase;
	ULONG64 PteBase;
#endif // _WIN64

	VOID (*ExReleaseSpinLockSharedFromDpcLevel)(
		PVOID SpinLock
	);
	
	VOID(*ExAcquireSpinLockSharedAtDpcLevel)(
		PVOID SpinLock
		);

	VOID (*KeEnterCriticalRegion)(
			VOID
		);
	
	VOID (*KeLeaveCriticalRegion)(
			VOID
		);
	
	ULONG32 (*KeGetCurrentProcessorNumberEx)(
		PVOID ProcNumber
	);

	ULONG32(*KeQueryActiveProcessorCountEx)(
		USHORT GroupNumber
	);

	ULONG32(*KeQueryActiveProcessorCount)(
		PKAFFINITY ActiveProcessors
	);

	ULONG_PTR (*KeIpiGenericCall)(
		PKIPI_BROADCAST_WORKER BroadcastFunction,
		ULONG_PTR Context
	);

	PVOID (* WtfMmLockPagableDataSection)(
		PVOID AddressWithinSection
	);

	PVOID
	(*RtlLookupFunctionEntry)(
		ULONG64 ControlPc,
		PULONG64 ImageBase,
		PVOID HistoryTable OPTIONAL
		);


	MAPPERRTB* MapperRtbPtr;
	SYSCALLRTB* SysCallRtbPtr;
	THREADRTB* ThreadRtbPtr;
	DPCRTB* DpcRtbPtr;
}GRTBLOCK,*PGRTBLOCK;

extern GRTBLOCK RtBlock;

#define ALL_PROCESSOR_GROUPS        0xffff

#define KECURRENT_PROCESSOR_NUMBER() \
    (RtBlock.KeGetCurrentProcessorNumberEx ? RtBlock.KeGetCurrentProcessorNumberEx(NULL) : KeGetCurrentProcessorNumber())

#define QUERY_ACTIVE_PROCESSOR_COUNT() \
    (RtBlock.KeQueryActiveProcessorCountEx ? RtBlock.KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) : \
     (RtBlock.KeQueryActiveProcessorCount ? RtBlock.KeQueryActiveProcessorCount(0) : RtBlock.KeNumberProcessors))

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // ! _MAPPER_H_
