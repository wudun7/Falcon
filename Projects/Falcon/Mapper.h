#ifndef  _MAPPER_H_
#define _MAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
	typedef struct _MAPPERRTB {

		PVOID NtdllWow64Handle;
		PVOID NtdllWow64SecHandle;
		PVOID NtdllWow64Base;
		ULONG_PTR NtdllWow64ViewSize;
		UNICODE_STRING NtdllWow64Path;
		UNICODE_STRING NtdllPath;

	}MAPPERRTB, * PMAPPERRTB;

	typedef BOOLEAN(*NTOSMAPPERCALLBACK)(PVOID base, SIZE_T size);
	NTSTATUS MapNtoskrnlFileWithCallback(NTOSMAPPERCALLBACK callback);

	NTSTATUS MapNtdll();

	extern MAPPERRTB NtdllMappedInfo;

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // ! _MAPPER_H_
