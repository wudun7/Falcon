#ifndef _PRIDEFS_H_
#define _PRIDEFS_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <Defs.h>

#define SYSTEMPID 4

    /*
    可写+不可执行 （1 + 2 * 1）^1 = 2
    可写+可执行 （1 + 2 * 0）^1 = 0
    不可写+不可执行 （0+2*1）^1 = 3
    不可写+可执行（0+2*0）^1 = 1
    */

    enum {
        PAGE_WRITE_EXECITE,
        PAGE_READ_EXECITE,
        PAGE_READ_WRITE,
        PAGE_ONLY_READ
    };

#include "pshpack4.h"
    typedef struct _PROCESSINFO {
        u32 ParentId;
        u64 CreateTime;
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        u32 SessionId;
        b Is64;
        b IsCritical;
        u64 DebugPort;
    }PROCESSINFO, *PPROCESSINFO;

    typedef struct _PROCESSEXITSTATUS {
        ptr Pid;
        NTSTATUS ExitStatus;
    }PROCESSEXITSTATUS, *PPROCESSEXITSTATUS;

    typedef struct _LOADEDMODULEINFO {
        u32 Size; //node size
        u64 ModuleBase;
        u32 MoudleSize;
        u32 ModuleOrder;
        u64 ModuleEntry;
        UNICODE_STRING Path;
    }LOADEDMODULEINFO, * PLOADEDMODULEINFO;

#include "poppack.h"


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIDEFS_H_