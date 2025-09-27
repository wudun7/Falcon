#ifndef _MODULES_H_
#define _MODULES_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#include "LibDefs.h"
#else
#include <Defs.h>
#endif

	typedef BOOLEAN(*ModuleHandler)(RTL_PROCESS_MODULE_INFORMATION* moduleinfo, PVOID params);

	NTSTATUS EnumModulesWithCallback(ModuleHandler callback, PVOID params);
	NTSTATUS GetLoadedModulesInfo(PVOID buffer, SIZE_T size, PSIZE_T pRetLen);
	BOOLEAN QuerySpecificKernelModuleInfoWithDpc(PVOID target, PVOID* outBase, PSIZE_T outImageSize, PUNICODE_STRING outPath);
	PVOID GetModuleBaseByAddress(PVOID target);
	NTSTATUS InitSelfAndKrnl();


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _MODULES_H_