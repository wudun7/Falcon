#include "Falcon.h"
#include "Neac.h"
#include "Global.h"
#include "PriDefs.h"
#include "Hook.h"
#include "Space.h"


VOID DriverUnload(PDRIVER_OBJECT obj)
{
	UNREFERENCED_PARAMETER(obj);

	if (RtBlock.PhysicalMemoryRanges)
	{
		ExFreePoolWithTag(RtBlock.PhysicalMemoryRanges, 'FkTX');
		RtBlock.PhysicalMemoryRanges = NULL;
	}

	if (RtBlock.MapperRtbPtr->NtdllWow64Base)
	{
		ZwUnmapViewOfSection(NtCurrentProcess(), RtBlock.MapperRtbPtr->NtdllWow64Base);
		RtBlock.MapperRtbPtr->NtdllWow64Base = NULL;
	}

	if (RtBlock.MapperRtbPtr->NtdllWow64SecHandle)
	{
		ZwClose(RtBlock.MapperRtbPtr->NtdllWow64SecHandle);
		RtBlock.MapperRtbPtr->NtdllWow64SecHandle = NULL;
	}

	if (RtBlock.MapperRtbPtr->NtdllWow64Handle)
	{
		ZwClose(RtBlock.MapperRtbPtr->NtdllWow64Handle);
		RtBlock.MapperRtbPtr->NtdllWow64Handle = 0;
	}

	if (RtBlock.MapperRtbPtr->NtdllWow64Path.Buffer)
		ExFreePoolWithTag(RtBlock.MapperRtbPtr->NtdllWow64Path.Buffer, POOLTAGTX);
	

	if (RtBlock.MapperRtbPtr->NtdllPath.Buffer)
		ExFreePoolWithTag(RtBlock.MapperRtbPtr->NtdllPath.Buffer, POOLTAGTX);
	
	if (RtBlock.KrnlPath.Buffer)
		ExFreePoolWithTag(RtBlock.KrnlPath.Buffer, POOLTAGTX);

	DbgPrint("Driver Uninstall\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(regPath);
	driver->DriverUnload = DriverUnload;
	FalconEntry();
	
	/*
		在这里编写测试代码
	*/

	return STATUS_SUCCESS;

}
