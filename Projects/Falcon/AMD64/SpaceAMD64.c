
#include "Space.h"
#include "Global.h"


UCHAR PteBasePattern[10] =
{
  0x48, 0x8B, 0x04, 0xD0, 0x48, 0xC1, 0xE0, 0x19, 0x48, 0xBA
};

VOID VaToOffsets(ptr va, u32 pageLevels, u32* ppxeOffset, u32* pppeOffset, u32* ppdeOffset, u32* ppteOffset)
{
    if (pageLevels >= 4)
        *ppxeOffset = MiGetPxeOffset(va);

    if (pageLevels >= 3)
    {
        *pppeOffset = MiGetPpeOffset(va);
        *ppdeOffset = MiGetPdeOffset(va);
        *ppteOffset = MiGetPteOffset(va);
    }
    else
    {
        *ppxeOffset = MiGetPxeOffset32(va);
        *ppxeOffset = MiGetPpeOffset32(va);
        *ppdeOffset = MiGetPdeOffset32(va);
        *ppteOffset = MiGetPteOffset32(va);
    }
}


PMMPTE
NTAPI
GetPxeAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)(RtBlock.PxeBase + MiGetPxeOffset(VirtualAddress));
}

PMMPTE
NTAPI
GetPpeAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)
        (((((INT64)VirtualAddress & VIRTUAL_ADDRESS_MASK)
            >> PPI_SHIFT)
            << PTE_SHIFT) + (INT64)RtBlock.PpeBase);
}

PMMPTE
NTAPI
GetPdeAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)
        (((((INT64)VirtualAddress & VIRTUAL_ADDRESS_MASK)
            >> PDI_SHIFT)
            << PTE_SHIFT) + (INT64)RtBlock.PdeBase);
}

PMMPTE
NTAPI
GetPteAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)
        (((((INT64)VirtualAddress & VIRTUAL_ADDRESS_MASK)
            >> PTI_SHIFT)
            << PTE_SHIFT) + (INT64)RtBlock.PteBase);
}

PVOID
NTAPI
GetVaMappedByPte(
    __in PMMPTE Pte
)
{
    return (PVOID)((((INT64)Pte - (INT64)RtBlock.PteBase) <<
        (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT);
}

PVOID
NTAPI
GetVaMappedByPde(
    __in PMMPTE Pde
)
{
    return GetVaMappedByPte(GetVaMappedByPte(Pde));
}

PVOID
NTAPI
GetVaMappedByPpe(
    __in PMMPTE Ppe
)
{
    return GetVaMappedByPte(GetVaMappedByPde(Ppe));
}

PVOID
NTAPI
GetVaMappedByPxe(
    __in PMMPTE Pxe
)
{
    return GetVaMappedByPde(GetVaMappedByPde(Pxe));
}

VOID ResetPteInvalid(ptr va)
{
    PMMPTE pa = GetPteAddress(va);
    InvalidatePage(pa);
    MmFreeMappingAddress(va, POOLTAGTX);
    return;
}

PMMPTE MapPageTableToVirtualAddress(PMMPTE pt)
{
    ptr mapped = MmAllocateMappingAddress(PAGE_SIZE, POOLTAGTX);

    if (!mapped)
        return NULL;

    PMMPTE pa = GetPteAddress(mapped);

    pa->u.Hard.Valid |= 0x1;
    pa->u.Hard.Writable |= 0x1;
    pa->u.Hard.Global |= 0x1;
    u64 physical = pt->u.Hard.PageFrameNumber << PAGE_SHIFT;
    pa->u.Long = ( physical | (pa->u.Long & 0xFFFF000000000FFFui64));
    __invlpg(mapped);
    return mapped;
}

/*
���noexec
��д+����ִ�� ��1 + 2 * 1��^1 = 2
��д+��ִ�� ��1 + 2 * 0��^1 = 0
����д+����ִ�� ��0+2*1��^1 = 3
����д+��ִ�У�0+2*0��^1 = 1

����noexec
����д 1/true
��д 0/false

*/

u32 CheckRWX(b bCheckNxe, PMMPTE ppdpte, PMMPTE ppde, PMMPTE ppte)
{
    if (bCheckNxe)
    {
        if (ppdpte && ppdpte->u.Hard.LargePage)
        {
            return ((u32)ppdpte->u.Hard.Writable + 2 * (u32)ppdpte->u.Hard.NoExecute) ^ 0x1;
        }
        if (ppde && ppde->u.Hard.LargePage)
        {
            return ((u32)ppde->u.Hard.Writable + 2 * (u32)ppde->u.Hard.NoExecute) ^ 0x1;
        }
        if (ppte)
        {
            return ((u32)ppte->u.Hard.Writable + 2 * (u32)ppte->u.Hard.NoExecute) ^ 0x1;
        }
    }
    if (ppde && ppde->u.Hard.LargePage)
    {
        return ppde->u.Hard.Writable == 0; 
    }
    if (ppte)
    {
        return ppte->u.Hard.Writable == 0;
    }

    return -1;
}

VOID CheckPageSizeWithAttributes(PVOID va, PULONG32 pPageSize, PULONG32 pAttr)
{
    MMPTE cr3;
    cr3.u.Long = __readcr3();
    u32 memattr = 0;
    PMMPTE mappedCr3 = 0, pdptBase = 0, pdBase = 0, ptBase = 0;
    u32 pml4eoffset = 0, pdpteoffset = 0, pdeoffset = 0, pteoffset = 0;

    do {
        VaToOffsets(va, RtBlock.MiPagingLevels, &pml4eoffset, &pdpteoffset, &pdeoffset, &pteoffset);
        mappedCr3 = MapPageTableToVirtualAddress(&cr3);

        if (!mappedCr3)
            break;

        MMPTE pml4e = mappedCr3[pml4eoffset];

        if (!pml4e.u.Hard.Valid)
            break;

        pdptBase = MapPageTableToVirtualAddress(&pml4e);

        if (pdptBase == 0)
            break;

        MMPTE pdpte = pdptBase[pdpteoffset];

        if (!pdpte.u.Hard.Valid)
            break;

        if(!pdpte.u.Hard.LargePage)
        {
            // 4k
            pdBase = MapPageTableToVirtualAddress(&pdpte);

            if (!pdBase)
                break;

            MMPTE pde = pdBase[pdeoffset];
          
            if (!pde.u.Hard.Valid)
                break;

            MMPTE pte = { 0 };

            if (pde.u.Hard.LargePage)
            {
                //2m
                if (pPageSize)
                    *pPageSize = 0x200000;
            }
            else
            {
                ptBase = MapPageTableToVirtualAddress(&pde);

                if (!ptBase)
                    break;

                pte = ptBase[pteoffset];

                if (!pte.u.Hard.Valid)
                    break;

                if (*pPageSize)
                    *pPageSize = PAGE_SIZE;
            }

            memattr = CheckRWX(TRUE, &pdpte, &pde, &pte);
        }
        else
        {
            //1g
            if (*pPageSize)
                *pPageSize = _1gb;

            memattr = CheckRWX(TRUE, &pdpte, NULL, NULL);
        }

    } while (0);


    if (pAttr)
        *pAttr = memattr;

    if (ptBase)
        ResetPteInvalid(ptBase);

    if (pdBase)
        ResetPteInvalid(pdBase);

    if (pdptBase)
        ResetPteInvalid(pdptBase);

    if (mappedCr3)
        ResetPteInvalid(mappedCr3);

    return;
}

size_t SimpleGetFunctionSize(PVOID target) {

    u8ptr pCode = target;
    size_t size = 0;

    while (TRUE) {
        if (MmIsAddressValid(pCode) && *pCode == 0xC3) {
            break;
        }
        size++;
        pCode++;
    }
    return size;
}

b IsExecutableAddress(PVOID va)
{
    if (!MmIsAddressValid(va))
        return FALSE;

    if ((ReadMSR(MSR_EFER) & MSR_NXE) != 0)
    {
        PMMPTE ppde = GetPdeAddress(va);
        PMMPTE ppte = GetPteAddress(va);

        // PMMPTE.u.MMPTE_HARDWARE ���λ��NoExecute�������1����Ϊ����
        // ���pde��NoExecute = 1 �޷�ִ��
        // ����Ǵ�ҳ��pte��NoExecute = 1 Ҳ�޷�ִ��
        if (*(s64*)ppde < 0 || (ppde->u.Hard.LargePage == FALSE && (!ppte || *(s64*)ppte < 0)))
            return FALSE;
    }

    return TRUE;
}

NTSTATUS InitPetBase()
{
    status st = STATUS_UNSUCCESSFUL;

    OSVERSIONINFOW osInfo;
    RtlSecureZeroMemory(&osInfo, sizeof(osInfo));
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    st = RtlGetVersion(&osInfo);

    if (NT_SUCCESS(st))
    {
        if (osInfo.dwMajorVersion < 0xA || osInfo.dwBuildNumber <= 0x37EB)
        {
            RtBlock.PxeBase = (PMMPTE)(0xFFFFF6FB7DBED000);
            RtBlock.PpeBase = (PMMPTE)(0xFFFFF6FB7DA00000);
            RtBlock.PdeBase = (PMMPTE)(0xFFFFF6FB40000000);
            RtBlock.PteBase = (PMMPTE)(0xFFFFF68000000000);
        }
        else
        {
            UNICODE_STRING uniStr;
            RtlInitUnicodeString(&uniStr, L"MmGetVirtualForPhysical");
            ptr mmgvfy = MmGetSystemRoutineAddress(&uniStr);
            st = STATUS_PROCEDURE_NOT_FOUND;

            if (mmgvfy)
            {
                ptr ppteBase = MemoryCompare(mmgvfy, 0x30, PteBasePattern, sizeof(PteBasePattern));

                if (ppteBase)
                {
                    u64 pteBase = *(u64*)((u8ptr)ppteBase + 10);
                    RtBlock.PxeBase = (PMMPTE)(pteBase | (((pteBase >> 39) & 0x1FF) << 30) | (((pteBase >> 39) & 0x1FF) << 21) | (((pteBase >> 39) & 0x1FF) << 12));
                    RtBlock.PpeBase = (PMMPTE)(pteBase | (((pteBase >> 39) & 0x1FF) << 30) | (((pteBase >> 39) & 0x1FF) << 21));
                    RtBlock.PdeBase = (PMMPTE)(pteBase | (((pteBase >> 39) & 0x1FF) << 30));
                    RtBlock.PteBase = (PMMPTE)pteBase;
                }
            }
        }
    }

    return st;
}

