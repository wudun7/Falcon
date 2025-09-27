#ifndef _PROCESS_H_
#define _PROCESS_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
	
	NTSTATUS TerminateProcessById(PVOID pid);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PROCESS_H_