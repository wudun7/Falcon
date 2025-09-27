#ifndef _NEAC_H_
#define _NEAC_H_



#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
	NTSTATUS NeacGetProcessInfomation(PVOID pid);
	NTSTATUS NeacTerminateProcess(PVOID pid);
	NTSTATUS NeacGetProcessBase(PVOID pid);
	NTSTATUS NeacQueryThreadInfoByThreadId(PVOID tid);
	NTSTATUS NeacQueryThreadStackFrame(PVOID tid, PVOID outBuffer, ULONG32 outLen);
	NTSTATUS NeacReadVirtualMemory(PVOID pid, PVOID src, PVOID dst, ULONG32 len, PULONG32 retLen);
	NTSTATUS NeacWriteVirtualMemory(PVOID pid, PVOID src, PVOID dst, ULONG32 len, PULONG32 retLen);
	NTSTATUS NeacVirtualProtectMemory(PVOID pid, PVOID target, ULONG32 size, ULONG32 newpro);
	NTSTATUS NeacReadKernelMemory(PVOID target, SIZE_T readSize, PVOID outBuffer, SIZE_T bufferSize, PSIZE_T pReaded);
	NTSTATUS NeacWriteKernelMeory(PVOID target, SIZE_T writeSize, PVOID inBuffer, SIZE_T bufferSize);
	NTSTATUS NeacSearchPoolImage(PVOID outBuffer, SIZE_T outlen);
	NTSTATUS NeacQueryAddressPoolInfo(PVOID target);
	NTSTATUS NeacQueryLoadedModuleListInfo(PVOID buffer, SIZE_T size, PSIZE_T pRetLen);
	NTSTATUS NeacQueryKernelModuleInfo(PVOID target);
	NTSTATUS NeacQueryFileSize(PUNICODE_STRING path);
	NTSTATUS NeacQueryFileIndexNumber(PUNICODE_STRING path);
	NTSTATUS NeacMapCr3(PVOID pid);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _NEAC_H_