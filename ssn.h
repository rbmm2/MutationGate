#pragma once

#include "rtlframe.h"

//#define _PREPARE_

#ifdef _PREPARE_
void Prepare(_In_ const PCSTR names[]);
#endif

struct SSN;

struct SSN_INFO 
{
	PVOID _M_apiAddr;
	SSN* _M_pTable;
	ULONG _M_N;
	ULONG _M_apiSSN;
	ULONG _M_TargetSSN;
};

BOOL GetNtBase(_Out_ HMODULE* phModule);

void UserEntry(const SSN_INFO* pi);