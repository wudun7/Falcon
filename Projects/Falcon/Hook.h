#ifndef _HOOK_H
#define _HOOK_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif
#include "pshpack1.h"

    // 8-bit relative jump.
    typedef struct _JMP_REL_SHORT
    {
        unsigned char  opcode;      // EB xx: JMP +2+xx
        unsigned char  operand;
    } JMP_REL_SHORT, * PJMP_REL_SHORT;

    typedef struct _JCC_ABS
    {
        unsigned char  opcode;      // 7* 0E:         J** +16
        unsigned char  dummy0;
        unsigned char  dummy1;      // FF25 00000000: JMP [+6]
        unsigned char  dummy2;
        unsigned int dummy3;
        unsigned long long address;     // Absolute destination address
    } JCC_ABS;


    typedef struct _JMP_ABS
    {
        unsigned char opcode2;
        unsigned int dummy3;
        unsigned int opcode3;
        unsigned int dummy4;
        unsigned char opcode4;
    } JMP_ABS, * PJMP_ABS;


    // 64-bit indirect absolute call.
    typedef struct _CALL_ABS
    {
        unsigned char  opcode0;     // FF15 00000002: CALL [+6]
        unsigned char  opcode1;
        unsigned int dummy0;
        unsigned char  dummy1;      // EB 08:         JMP +10
        unsigned char  dummy2;
        unsigned long long address;     // Absolute destination address
    } CALL_ABS;

    // 32-bit direct relative jump/call.
    typedef struct _JMP_REL
    {
        unsigned char  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
        unsigned int operand;     // Relative destination address
    } JMP_REL, * PJMP_REL, CALL_REL;

#include "poppack.h"

    typedef struct _TRAMPOLINE
    {
        unsigned long long pTarget;         // [In] Address of the target function.
        unsigned long long pDetour;         // [In] Address of the detour function.
        unsigned long long pTrampoline;     // [In] Buffer address for the trampoline and relay function.

#if defined(_M_X64) || defined(__x86_64__)
        unsigned long long pRelay;          // [Out] Address of the relay function.
#endif
        unsigned char   patchAbove;      // [Out] Should use the hot patch area?
        unsigned int   nIP;             // [Out] Number of the instruction boundaries.
        unsigned char  oldIPs[32];       // [Out] Instruction boundaries of the target function.
        unsigned char  newIPs[32];       // [Out] Instruction boundaries of the trampoline function.
    } TRAMPOLINE, * PTRAMPOLINE;


    // Hook information.
    typedef struct _HOOK_ENTRY
    {
        unsigned long long pTarget;             // Address of the target function.
        unsigned long long pDetour;             // Address of the detour or relay function.
        unsigned long long pTrampoline;         // Address of the trampoline function.
        unsigned char  backup[sizeof(JMP_ABS)];           // Original prologue of the target function.

        unsigned char  patchAbove : 1;     // Uses the hot patch area.
        unsigned char  isEnabled : 1;     // Enabled.
        unsigned char  queueEnable : 1;     // Queued for enabling/disabling when != isEnabled.

        unsigned int nIP : 4;             // Count of the instruction boundaries.
        unsigned char  oldIPs[32];           // Instruction boundaries of the target function.
        unsigned char  newIPs[32];           // Instruction boundaries of the trampoline function.
    } HOOK_ENTRY, * PHOOK_ENTRY;

    typedef struct _HOOK_CONTROL {
        HOOK_ENTRY* pEntry;
        unsigned int hookCnt;
        unsigned char enable;
    }HOOK_CONTROL, * PHOOK_CONTROL;

    unsigned char MinHook(unsigned long long pTarget, unsigned long long pDetour, void** ppOriginal, HOOK_ENTRY* hookEntry);
    void MinUnHook(HOOK_ENTRY* hookEntry);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _HOOK_H