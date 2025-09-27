#ifndef _THREAD_H_
#define _THREAD_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
	typedef struct _THREADRTB {

		ULONG32 ThreadInitialStackOffset;
		ULONG32 ThreadStackLimitOffset;
		ULONG32 ThreadLockOffset;
		ULONG32 ThreadStackBaseOffset;
		ULONG32 ThreadKernelStackOffset;
		ULONG32 ThreadStateOffset;
		ULONG32 PreModeOffset;

	}THREADRTB,*PTHREADRTB;

	extern THREADRTB ThreadRtb;
	VOID InitThreadOffsets();
	KIRQL LockThread(PETHREAD thread);
	VOID UnlockThread(PETHREAD thread, KIRQL irql);
	NTSTATUS ThreadStackWalk(PETHREAD thread, PVOID* pcallers, PULONG32 pcnt);

#define SETPREMODE(m) __wru8((PUCHAR)KeGetCurrentThread() +  ThreadRtb.PreModeOffset,m)
#define GETPREMODE() __rdu8((PUCHAR)KeGetCurrentThread() +  ThreadRtb.PreModeOffset)
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _THREAD_H_