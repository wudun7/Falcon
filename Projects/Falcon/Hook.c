
#include "Hook.h"
#include "capstone.h"
#include "Space.h"
#include "Dpc.h"

#define HIGH_32(addr64) ((u32)(((u64)(addr64)) >> 32))
#define LOW_32(addr64)  ((u32)(((u64)(addr64)) & 0xFFFFFFFF))
// Size of each memory slot.
#if defined(_M_X64) || defined(__x86_64__)
#define MEMORY_SLOT_SIZE 64
#else
#define MEMORY_SLOT_SIZE 32
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define TRAMPOLINE_MAX_SIZE (MEMORY_SLOT_SIZE - sizeof(JMP_ABS))
#else
#define TRAMPOLINE_MAX_SIZE MEMORY_SLOT_SIZE
#endif

b IsCodePadding(ptr target, size_t size)
{
    u8ptr buffer = target;

    if (buffer[0] != 0x00 && buffer[0] != 0x90 && buffer[0] != 0xCC)
        return FALSE;

    for (size_t i = 1; i < size; ++i)
    {
        if (buffer[i] != buffer[0])
            return FALSE;
    }
    return TRUE;
}

b CreateTrampolineFunction(TRAMPOLINE* ct)
{
#if defined(_M_X64) || defined(__x86_64__)
    CALL_ABS call = {
        0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
        0xEB, 0x08,             // EB 08:         JMP +10
        0x0000000000000000ULL   // Absolute destination address
    };
    JMP_ABS jmp = {
        0x68, 0x00000000,          // push LODWORD(*)
        0x042444C7, 0x00000000,    // mov dword ptr ss:[rsp+4],HIDWORD(*)
        0xC3                       // ret
    };
    JCC_ABS jcc = {
        0x70, 0x0E,             // 7* 0E:         J** +16
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
#endif

    u8     oldPos = 0;
    u8     newPos = 0;
    ULONG_PTR jmpDest = 0;     // Destination address of an internal jump.
    b   finished = FALSE; // Is the function completed?
    b   bContinue = TRUE;
#if defined(_M_X64) || defined(__x86_64__)
    u8  instBuf[16];
#endif

    ct->patchAbove = FALSE;
    ct->nIP = 0;
    csh hCsEngine;
    cs_insn* pCsInsn = NULL;
    size_t insnCnt = 0;
    cs_err error = cs_open(CS_ARCH_X86, CS_MODE_64, &hCsEngine);

    do {
        if (error != CS_ERR_OK)
            break;

        if (cs_option(hCsEngine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
            break;

        do {
            u32   copySize = 0;
            ptr    pCopySrc = NULL;
            ULONG_PTR pOldInst = (ULONG_PTR)ct->pTarget + oldPos;
            ULONG_PTR pNewInst = (ULONG_PTR)ct->pTrampoline + newPos;

            if (pCsInsn)
            {
                cs_free(pCsInsn, insnCnt);
                pCsInsn = NULL;
            }

            insnCnt = cs_disasm(hCsEngine, (u8ptr)pOldInst, 0xf, (u64)pOldInst, 0x1, &pCsInsn);

            if (!insnCnt || !pCsInsn || !pCsInsn->detail) {
#ifdef DEBUG
                DbgPrint("insts or inst detail not present\n");
#endif // DEBUG
                break;
            }

            copySize = pCsInsn->size;
            pCopySrc = (ptr)pOldInst;

            if (oldPos > sizeof(JMP_ABS))
            {
                // The trampoline function is long enough.
                // Complete the function with the jump to the target function.
#if defined(_M_X64) || defined(__x86_64__)
                jmp.dummy3 = LOW_32(pOldInst);
                jmp.dummy4 = HIGH_32(pOldInst);
#endif  
                pCopySrc = &jmp;
                copySize = sizeof(jmp);
                finished = TRUE;
            }

#if defined(_M_X64) || defined(__x86_64__)
            else if ((pCsInsn->detail->x86.modrm & 0xc7) == 0x5) {
                u32ptr pRelAddr;
                memcpy(instBuf, (u8ptr)pOldInst, copySize);

                pCopySrc = instBuf;

                // Relative address is stored at (instruction length - immediate value length - 4).
                pRelAddr = (u32ptr)(instBuf + pCsInsn->size - pCsInsn->detail->x86.operands[0].size - 4);
                *pRelAddr
                    = (u32)((pOldInst + pCsInsn->size + pCsInsn->detail->x86.disp) - (pNewInst + pCsInsn->size));

                // Complete the function if JMP (FF /4).
                if (pCsInsn->detail->x86.opcode[0] == 0xFF && (pCsInsn->detail->x86.modrm & 0x38) == 0x20)
                    finished = TRUE;
            }
#endif
            else if (pCsInsn->detail->x86.opcode[0] == 0xe8)
            {
                // Direct relative CALL
                ULONG_PTR dest = pOldInst + pCsInsn->size + pCsInsn->detail->x86.operands[0].imm;
#if defined(_M_X64) || defined(__x86_64__)
                call.address = (u64)dest;
#endif
                pCopySrc = &call;
                copySize = sizeof(call);
            }

            else if ((pCsInsn->detail->x86.opcode[0] & 0xFD) == 0xe9)
            {
                // Direct relative JMP (EB or E9)
                ULONG_PTR dest = pOldInst + pCsInsn->size;

                if (pCsInsn->detail->x86.opcode[0] == 0xEB) // isShort jmp
                    dest += (s8)pCsInsn->detail->x86.operands[0].imm;
                else
                    dest += (s32)pCsInsn->detail->x86.operands[0].imm;

                if ((ULONG_PTR)ct->pTarget <= dest
                    && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
                {
                    if (jmpDest < dest)
                        jmpDest = dest;
                }

                else
                {
#if defined(_M_X64) || defined(__x86_64__)
                    jmp.dummy3 = LOW_32(dest);
                    jmp.dummy4 = HIGH_32(dest);
#endif
                    pCopySrc = &jmp;
                    copySize = sizeof(jmp);

                    // Exit the function if it is not in the branch.
                    finished = (pOldInst >= jmpDest);

                }
            }

            else if ((pCsInsn->detail->x86.opcode[0] & 0xF0) == 0x70 || (pCsInsn->detail->x86.opcode[0] & 0xFC) == 0xE0 || (pCsInsn->detail->x86.opcode[1] & 0xF0) == 0x80)
            {
                // Direct relative Jcc
                ULONG_PTR dest = pOldInst + pCsInsn->size;

                if ((pCsInsn->detail->x86.opcode[0] & 0xF0) == 0x70      // Jcc
                    || (pCsInsn->detail->x86.opcode[0] & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
                    dest += (s8)pCsInsn->detail->x86.operands[0].imm;
                else
                    dest += (s32)pCsInsn->detail->x86.operands[0].imm;

                // Simply copy an internal jump.
                if ((ULONG_PTR)ct->pTarget <= dest
                    && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
                {
                    if (jmpDest < dest)
                        jmpDest = dest;
                }
                else if ((pCsInsn->detail->x86.opcode[0] & 0xFC) == 0xE0)
                {
                    // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
                    bContinue = FALSE;
                    break;
                }

                else
                {
                    u8 cond = ((pCsInsn->detail->x86.opcode[0] != 0x0F ? pCsInsn->detail->x86.opcode[0] : pCsInsn->detail->x86.opcode[1]) & 0x0F);
#if defined(_M_X64) || defined(__x86_64__)
                    // Invert the condition in x64 mode to simplify the conditional jump logic.
                    jcc.opcode = 0x71 ^ cond;
                    jcc.address = (u64)dest;
#endif
                    pCopySrc = &jcc;
                    copySize = sizeof(jcc);
                }
            }

            else if ((pCsInsn->detail->x86.opcode[0] & 0xFE) == 0xC2)
            {
                // RET (C2 or C3)

                // Complete the function if not in a branch.
                finished = (pOldInst >= jmpDest);
            }

            // Can't alter the instruction length in a branch.
            if (pOldInst < jmpDest && copySize != pCsInsn->size)
            {
                bContinue = FALSE;
                break;
            }

            // Trampoline function is too large.
            if ((newPos + copySize) > TRAMPOLINE_MAX_SIZE)
            {
                bContinue = FALSE;
                break;
            }

            // Trampoline function has too many instructions.
            if (ct->nIP >= ARRAYSIZE(ct->oldIPs))
            {
                bContinue = FALSE;
                break;
            }

            ct->oldIPs[ct->nIP] = oldPos;
            ct->newIPs[ct->nIP] = newPos;
            ct->nIP++;

            memcpy((ptr)(ct->pTrampoline + newPos), pCopySrc, copySize);
            newPos += copySize;
            oldPos += pCsInsn->size;

        } while (!finished);

        if (pCsInsn)
            cs_free(pCsInsn, insnCnt);

        if (hCsEngine)
            cs_close(&hCsEngine);

        if (!bContinue)
            return FALSE;

        // Is there enough place for a long jump?
        if (oldPos < sizeof(JMP_REL)
            && !IsCodePadding((u8ptr)ct->pTarget + oldPos, sizeof(JMP_REL) - oldPos))
        {
            // Is there enough place for a short jump?
            if (oldPos < sizeof(JMP_REL_SHORT)
                && !IsCodePadding((u8ptr)ct->pTarget + oldPos, sizeof(JMP_REL_SHORT) - oldPos))
            {
                return FALSE;
            }

            // Can we place the long jump above the function?
            if (!IsExecutableAddress((u8ptr)ct->pTarget - sizeof(JMP_REL)))
                return FALSE;

            if (!IsCodePadding((u8ptr)ct->pTarget - sizeof(JMP_REL), sizeof(JMP_REL)))
                return FALSE;

            ct->patchAbove = TRUE;
        }

    } while (0);

#if defined(_M_X64) || defined(__x86_64__)
    // Create a relay function.
    jmp.dummy3 = LOW_32(ct->pDetour);
    jmp.dummy4 = HIGH_32(ct->pDetour);
    ct->pRelay = (u64)((u8ptr)ct->pTrampoline + newPos);
    memcpy((ptr)ct->pRelay, &jmp, sizeof(jmp));
#endif
    return TRUE;
}

VOID EnableHook(HOOK_ENTRY* entry)
{
    u64 pTrampoline = 0;
    PMDL pMdl = NULL;
    JMP_ABS* pBase = NULL;

    pTrampoline = entry->pDetour;
    pMdl = MmCreateMdl(NULL, (ptr)entry->pTarget, sizeof(JMP_ABS));

    if (pMdl)
    {
        MmBuildMdlForNonPagedPool(pMdl);
        pBase = MmMapLockedPages(pMdl, KernelMode);

        if (pBase)
        {
            pBase->opcode2 = 0x68;
            pBase->dummy3 = LOW_32(pTrampoline);
            pBase->opcode3 = 0x42444C7;
            pBase->dummy4 = HIGH_32(pTrampoline);
            pBase->opcode4 = 0xC3;
            MmUnmapLockedPages(pBase, pMdl);
            entry->isEnabled = TRUE;
            entry->queueEnable = TRUE;
        }
        IoFreeMdl(pMdl);
    }
}

VOID DisableHook(HOOK_ENTRY* entry)
{
    PMDL pMdl = NULL;

    pMdl = MmCreateMdl(NULL, (ptr)entry->pTarget, sizeof(JMP_ABS));

    if (pMdl)
    {
        MmBuildMdlForNonPagedPool(pMdl);
        ptr pBase = MmMapLockedPages(pMdl, KernelMode);

        if (pBase)
        {
            memcpy(pBase, entry->backup, sizeof(entry->backup));
            MmUnmapLockedPages(pBase, pMdl);
        }
        IoFreeMdl(pMdl);
    }
}

VOID EnableHookLL(HOOK_CONTROL* control)
{
    u32 idx = 0;

    if (control->enable)
    {
        if (control->hookCnt)
        {
            do
            {
                EnableHook(&control->pEntry[idx]);
                idx++;
            } while (idx < control->hookCnt);
        }
    }
    else if (control->hookCnt)
    {
        do
        {
            DisableHook(&control->pEntry[idx]);
            idx++;
        } while (idx < control->hookCnt);
    }
}

NTSTATUS MHCreateHook(u64 pTarget, u64 pDetour, ptr* ppOriginal, HOOK_ENTRY* pHook)
{
    status st = STATUS_INSUFFICIENT_RESOURCES;
    ptr trampline = ExAllocatePoolWithTag(NonPagedPool, 0x32, POOLTAGTX);

    if (trampline)
    {
        TRAMPOLINE ct = { 0 };

        ct.pTarget = pTarget;
        ct.pDetour = pDetour;
        ct.pTrampoline = (u64)trampline;

        if (CreateTrampolineFunction(&ct))
        {
            pHook->pTarget = ct.pTarget;
#if defined(_M_X64) || defined(__x86_64__)
            pHook->pDetour = ct.pRelay;
#else
            pHook->pDetour = ct.pDetour;
#endif
            pHook->pTrampoline = ct.pTrampoline;
            pHook->patchAbove = ct.patchAbove;
            pHook->isEnabled = FALSE;
            pHook->queueEnable = FALSE;
            pHook->nIP = ct.nIP;
            memcpy(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
            memcpy(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

            if (ct.patchAbove)
            {
                memcpy(
                    pHook->backup,
                    (u8ptr)pTarget - sizeof(JMP_REL),
                    sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
            }
            else
            {
                memcpy(pHook->backup, (ptr)pTarget, sizeof(JMP_ABS));
            }

            if (ppOriginal != NULL)
                *ppOriginal = (ptr)pHook->pTrampoline;

            st = STATUS_SUCCESS;
        }
        else
        {
            ExFreePoolWithTag(trampline, POOLTAGTX);
            st = STATUS_UNSUCCESSFUL;
        }

    }
    return st;
}

unsigned char MinHook(unsigned long long pTarget, unsigned long long pDetour, void** ppOriginal, HOOK_ENTRY* hookEntry)
{
    status st = MHCreateHook(pTarget, pDetour, ppOriginal, hookEntry);
    HOOK_CONTROL hookCtl = { 0 };

    if (NT_SUCCESS(st))
    {
        hookCtl.pEntry = hookEntry;
        hookCtl.hookCnt = 1;
        hookCtl.enable = TRUE;

        SyncDpcExecuteProxy((ptr)EnableHookLL, &hookCtl);
    }

    return hookEntry->isEnabled;
}

void MinUnHook(HOOK_ENTRY* hookEntry)
{
    HOOK_CONTROL hookCtl = { 0 };
    hookCtl.pEntry = hookEntry;
    hookCtl.hookCnt = 1;
    hookCtl.enable = FALSE;

    SyncDpcExecuteProxy((ptr)EnableHookLL, &hookCtl);
}

