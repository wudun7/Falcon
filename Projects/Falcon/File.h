#ifndef  _FILE_H_
#define _FILE_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
    NTSTATUS SyncQueryFileDosName(PVOID fileObj, PUNICODE_STRING out);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // ! _MAPPER_H_
