#ifndef _DPC_H_
#define _DPC_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif

	typedef struct _DPCRTB {
		
		UINT32 CallDpcOffset;

		VOID(*KeGenericCallDpc)(
			__in PKDEFERRED_ROUTINE Routine,
			__in_opt PVOID Context
			);

		VOID
			(*KeSignalCallDpcDone)(
				__in PVOID SystemArgument1
			);

		LOGICAL
			(*KeSignalCallDpcSynchronize)(
				__in PVOID SystemArgument2
			);
	}DPCRTB,*PDPCRTB;

	VOID InitDpcRtb();
	VOID SyncDpcExecuteProxy(PVOID funcPtr, PVOID params);
	VOID SyncIpiExecuteProxy(PVOID funcPtr, PVOID params);
	extern DPCRTB DpcRtb;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _DPC_H_