#ifndef _POOL_H_
#define _POOL_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
	typedef BOOLEAN(*BigPoolHandler)(PVOID poolAddress, SIZE_T poolSize, BOOLEAN nonpaged, PVOID params);
	NTSTATUS SacnBigPoolAndFindImage(PVOID outBuffer, SIZE_T outlen, PULONG32 pRetLen);
	size_t GetPoolInfoByAddress(PVOID address, PVOID* outPoolStart, PSIZE_T outPoolSize);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _POOL_H_