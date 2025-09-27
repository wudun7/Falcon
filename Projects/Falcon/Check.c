#include "Check.h"
#include "Global.h"
#include "Space.h"
#include <Zydis/Zydis.h>


b CheckHalGetRealClockHooked(ptr va)
{
	size_t size = SimpleGetFunctionSize(va);
	ZydisDisassembledInstruction insn = { 0 };
	ZyanU64 hookedVa = 0;
	b hooked = FALSE;

	if (MmIsAddressValid(va))
	{
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)va, va, size, &insn)))
		{
			if (insn.info.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
			{
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn.info, &insn.operands[1], (ZyanU64)va, &hookedVa)))
				{
					// todo:判断hookedVa是否在可信模块中
					hooked = TRUE;
				}
			}
			else
			{
				hooked = FALSE;
			}
		}
	}

	return hooked;
}
