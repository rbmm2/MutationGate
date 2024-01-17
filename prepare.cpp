#include "stdafx.h"
#include "ssn.h"

#ifdef _PREPARE_

ULONG HashString(PCSTR lpsz, ULONG hash = 0);

void PrepareCode(_In_ const PCSTR names[])
{
	while (PCSTR name = *names++)
	{
		DbgPrint("NtApi 0%08xh, %s\n", HashString(name), name);
	}
}

void PrepareData(_In_ const PCSTR names[])
{
	while (PCSTR name = *names++)
	{
		DbgPrint("NtImp %s\n", name);
	}
}

void Prepare(_In_ const PCSTR names[])
{
	PCSTR name = *names++;

	DbgPrint("#define hash_Nt%s\t\t\t0x%08x\n", name, HashString(name));

	PrepareCode(names);
	PrepareData(names);
}

#endif