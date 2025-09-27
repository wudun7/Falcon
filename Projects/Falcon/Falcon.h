#ifndef _FALCON_H
#define _FALCON_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#include "NtApi.h"
#include "Modules.h"
#include "Memory.h"
#include "Hook.h"
#include "Hash.h"
#include "Mapper.h"
#include "Process.h"
#include "Thread.h"
#include "Search.h"
#include "Dpc.h"
#include "File.h"
#include "Space.h"
#include "Stack.h"
#include "SysPool.h"

#else
#include <Defs.h>
#endif

	VOID FalconEntry();
	VOID FalconUnload();
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _FALCON_H