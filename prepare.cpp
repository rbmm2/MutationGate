#include "stdafx.h"
#include "ssn.h"

#ifdef _PREPARE_

ULONG HashString(PCSTR lpsz, ULONG hash = 0);

void Prepare(_In_ const PCSTR names[])
{
	while (PCSTR name = *names++)
	{
		DbgPrint("#define hash_Nt%s\t\t\t0x%08x\n", name, HashString(name));
	}
}

#endif