#ifndef _STACK_H_
#define _STACK_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
    BOOLEAN StackWalk(
        PETHREAD thread,
        PCONTEXT ctx,
        PVOID* callers,
        PULONG32 pCallersCount);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _STACK_H_