
#include "Search.h"
#include "Modules.h"
#include "Global.h"


/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS FindPattern(IN PUCHAR pattern, IN BOOLEAN wildcard, IN SIZE_T len, IN PVOID base, IN SIZE_T size, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for (u64 i = 0; i < size - len; i++)
    {
        b found = TRUE;
        for (u64 j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((u8ptr)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppFound = (u8ptr)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}


BOOLEAN CapstoneDisasmWithCallback(PVOID start, SIZE_T range, CAPSTONECALLBACK callback, PVOID params,PVOID any)
{
	b result = FALSE, bInitSec = FALSE, bContinue = FALSE;;
	IMAGE_SECTION_HEADER* pSec = NULL;
	u32 numberOfSec = 0;
	csh hCsEngine = 0;
	cs_insn* pCsInsn = NULL;
	size_t insnCnt = 0;
	ptr end = (u8ptr)start + range - 1;
	ptr _start = start;
	ptr pIdStart = NULL, pIdEnd = NULL;
	u64 insnIdx = 1;
	u16 inslen = 0;

	ptr moduleBase = GetModuleBaseByAddress(start);
	IMAGE_NT_HEADERS* pNt = RtlImageNtHeader(moduleBase);

#ifdef DEBUG
	ASSERT(RtBlock.WtfMmLockPagableDataSection != NULL);

#endif // DEBUG


	// ��ҳ
	if (moduleBase &&
		pNt &&
		pNt->FileHeader.NumberOfSections
		)
	{
		pSec = (IMAGE_SECTION_HEADER*)((u8ptr)&pNt->OptionalHeader + pNt->FileHeader.SizeOfOptionalHeader);

		while (1)
		{
			ptr secStart = pSec->VirtualAddress + (u8ptr)moduleBase;

			if (start >= secStart && start < (u8ptr)secStart + pSec->SizeOfRawData && __rdu32(pSec->Name)== 0x54494E49)//init
			{
				
				bInitSec = TRUE;
				break;
			}

			if (start >= secStart && start < (u8ptr)secStart + pSec->SizeOfRawData && __rdu32(pSec->Name) == 0x45474150) //page
				pIdStart = RtBlock.WtfMmLockPagableDataSection(start);

			if (end >= secStart && end < (u8ptr)secStart + pSec->SizeOfRawData && __rdu32(pSec->Name) == 0x45474150) //page
				pIdEnd = RtBlock.WtfMmLockPagableDataSection(end);

			pSec++;
			numberOfSec++;

			if (numberOfSec >= pNt->FileHeader.NumberOfSections)
				break;
		}
	}

	// �޷���init�����ͷţ��ڽ��з����
	if (bInitSec || (cs_open(CS_ARCH_X86, CS_MODE_64, &hCsEngine) != CS_ERR_OK))
		goto EXIT;

	if (cs_option(hCsEngine, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK)
	{
		while (1)
		{
			if (pCsInsn)
			{
				cs_free(pCsInsn, insnCnt);
				pCsInsn = NULL;
			}

			do
			{
				if ((u8ptr)_start + 0xf >= RtBlock.MmUserProbeAddress)
				{
					if (!MmIsAddressValid(_start) || !MmIsAddressValid((u8ptr)_start + 0xf))
						break;
				}
				
				else
				{
					__try {
						ProbeForRead(_start, 0xf, 1);
					}

					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						result = FALSE;
						goto EXIT;
					}
				}

				insnCnt = cs_disasm(hCsEngine, _start, 0xf, (u64)_start, 1, &pCsInsn);

				if (insnCnt)
				{
					inslen = pCsInsn->size;
					// ����callback
					if (callback)
						result = callback(pCsInsn, _start, inslen, insnIdx, params, any);

					if (result)
					{
						bContinue = FALSE;
						break;
					}

					if (!inslen)
						break;

					bContinue = TRUE;
					_start = (u8ptr)_start + inslen;
					insnIdx++;
				}
				else
				{
					bContinue = FALSE;
					break;
				}
			} while (0);

			if (!bContinue || _start > (u8ptr)start + range)
				break;
		}
	}

EXIT:
	if (pCsInsn)
	{
		cs_free(pCsInsn, insnCnt);
		pCsInsn = NULL;
	}

	if (hCsEngine)
		cs_close(&hCsEngine);

	if (pIdStart)
		MmUnlockPagableImageSection(pIdStart);

	if (pIdEnd)
		MmUnlockPagableImageSection(pIdEnd);

	return result;
}
