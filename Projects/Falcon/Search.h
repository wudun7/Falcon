#ifndef _SEARCH_H_
#define _SEARCH_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
#include "capstone.h"

	NTKERNELAPI
		VOID
		MmUnlockPagableImageSection(
			PVOID ImageSectionHandle
		);

	typedef BOOLEAN(*CAPSTONECALLBACK)(cs_insn* pCsInsn, PVOID pOpcode, SIZE_T opLen, SIZE_T totalInsn, PVOID params,PVOID any);

	NTSTATUS FindPattern(IN PUCHAR pattern, IN BOOLEAN wildcard, IN SIZE_T len, IN PVOID base, IN SIZE_T size, OUT PVOID* ppFound);

	BOOLEAN CapstoneDisasmWithCallback(PVOID start, SIZE_T range, CAPSTONECALLBACK callback, PVOID params, PVOID any);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _SEARCH_H_