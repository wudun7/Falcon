#ifndef _HASH_
#define _HASH_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef NOMINILIB
#include <ntifs.h>
#else
#include <Defs.h>
#endif

    typedef struct _ONEWAYHASH {
        ULONG64 StrLen;
        ULONG32 Hash1;
        ULONG32 Hash2;
        ULONG32 Hash3;
    }ONEWAYHASH,*PONEWAYHASH;


#define InitializeHash( h, l, h1, h2, h3 ) { \
    (h)->StrLen = l;             \
    (h)->Hash1 = h1;             \
    (h)->Hash2 = h2;             \
    (h)->Hash3 = h3;             \
    }

    VOID Hash(PONEWAYHASH pHash, PUCHAR str);
    BOOLEAN HashCompare(PONEWAYHASH src, PONEWAYHASH dst);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _HASH_