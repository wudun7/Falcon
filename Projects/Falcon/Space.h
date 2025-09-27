#ifndef _SPACE_H_
#define _SPACE_H_

#include "LibDefs.h"
#include "Global.h"
#include "Memory.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
#if defined(NT_UP)
#define MM_PTE_WRITE_MASK         0x2
#else
#define MM_PTE_WRITE_MASK         0x800
#endif

#if defined(NT_UP)
#define MM_PTE_DIRTY_MASK         0x40
#else
#define MM_PTE_DIRTY_MASK         0x42
#endif

#define MM_PTE_VALID_MASK         0x1
#define MM_PTE_READWRITE         MM_PTE_WRITE_MASK
#define MM_PTE_ACCESS_MASK        0x20
#define MM_PTE_WRITE_THROUGH_MASK 0x8
#define MM_PTE_CACHE_DISABLE_MASK 0x10
#define MM_PTE_COPY_ON_WRITE_MASK 0x200

#define MiGetPxeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))
#define MiGetPpeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PPI_SHIFT) & PPI_MASK))
#define MiGetPdeOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PDI_SHIFT) & (PDE_PER_PAGE - 1)))
#define MiGetPteOffset(va) ((ULONG)(((ULONG_PTR)(va) >> PTI_SHIFT) & (PTE_PER_PAGE - 1)))
#define MiGetPxeOffset32(va) ((ULONG)-1)
#define MiGetPpeOffset32(va) ((ULONG)-1)
#define MiGetPdeOffset32(va) (((ULONG)((ULONG_PTR)va)) >> 22)
#define MiGetPteOffset32(va) ((((ULONG)((ULONG_PTR)va)) << 10) >> 22)

	NTSTATUS InitPetBase();
#ifdef _WIN64
	VOID CheckPageSizeWithAttributes(PVOID va, PULONG32 pPageSize, PULONG32 pAttr);
	SIZE_T SimpleGetFunctionSize(PVOID target);
	PMMPTE MapPageTableToVirtualAddress(PMMPTE pt);
	BOOLEAN IsExecutableAddress(PVOID va);

	PMMPTE
		NTAPI
		GetPxeAddress(
			__in PVOID VirtualAddress
		);

	PMMPTE
		NTAPI
		GetPpeAddress(
			__in PVOID VirtualAddress
		);

	PMMPTE
		NTAPI
		GetPdeAddress(
			__in PVOID VirtualAddress
		);

	PMMPTE
		NTAPI
		GetPteAddress(
			__in PVOID VirtualAddress
		);

	PVOID
		NTAPI
		GetVaMappedByPte(
			__in PMMPTE Pte
		);

	PVOID
		NTAPI
		GetVaMappedByPde(
			__in PMMPTE Pde
		);

	PVOID
		NTAPI
		GetVaMappedByPpe(
			__in PMMPTE Ppe
		);

	PVOID
		NTAPI
		GetVaMappedByPxe(
			__in PMMPTE Pxe
		);
#endif // _WIN64


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _SPACE_H_