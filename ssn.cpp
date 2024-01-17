#include "stdafx.h"
#include "ssn.h"

struct SSN  
{
	ULONG hash;
	union {
		ULONG Address;
		ULONG ssn;
	};

	static int __cdecl Compare(void const* pa, void const* pb)
	{
		ULONG a = reinterpret_cast<const SSN*>(pa)->Address;
		ULONG b = reinterpret_cast<const SSN*>(pb)->Address;

		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}

	static int __cdecl CompareH(void const* pa, void const* pb)
	{
		ULONG a = reinterpret_cast<const SSN*>(pa)->hash;
		ULONG b = reinterpret_cast<const SSN*>(pb)->hash;

		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}
};

ULONG GetZwCount(_In_ PVOID ImageBase, _In_ ULONG NumberOfNames, _In_ PULONG AddressOfNames)
{
	ULONG n = 0;

	do 
	{
		PCSTR name = RtlOffsetToPointer(ImageBase, *AddressOfNames++);

		n += (name[0] == 'Z' && name[1] == 'w');

	} while (--NumberOfNames);

	return n;
}

ULONG HashString(PCSTR lpsz, ULONG hash = 0)
{
	while (char c = *lpsz++) hash = hash * 33 ^ c;
	return hash;
}

BOOL CreateSSNTable(_In_ PVOID ImageBase, _In_ PIMAGE_EXPORT_DIRECTORY pied, _Out_ SSN** ppTable, _Out_ ULONG *pN)
{
	if (ULONG NumberOfNames = pied->NumberOfNames)
	{
		PUSHORT AddressOfNameOrdinals = (PUSHORT)RtlOffsetToPointer(ImageBase, pied->AddressOfNameOrdinals);
		PULONG AddressOfNames = (PULONG)RtlOffsetToPointer(ImageBase, pied->AddressOfNames);
		PULONG AddressOfFunctions = (PULONG)RtlOffsetToPointer(ImageBase, pied->AddressOfFunctions);

		if (ULONG n = GetZwCount(ImageBase, NumberOfNames, AddressOfNames))
		{
			if (SSN* p = new SSN[n])
			{
				*pN = n, *ppTable = p;

				do 
				{
					ULONG rva = *AddressOfNames++;
					PCSTR name = RtlOffsetToPointer(ImageBase, rva);
					USHORT o = *AddressOfNameOrdinals++;

					if (*name++ == 'Z' && *name++ == 'w')
					{
						if (!n--)
						{
							break;
						}

						p->hash = HashString(name), p++->Address = AddressOfFunctions[o];
					}

				} while (--NumberOfNames);

				if (!NumberOfNames)
				{
					qsort(*ppTable, *pN, sizeof(SSN), SSN::Compare);

					return TRUE;
				}

				delete [] *ppTable;
			}
		}
	}

	return FALSE;
}

BOOL InitSysCall(_In_ PIMAGE_DOS_HEADER hmod, _Out_ SSN** ppTable, _Out_ ULONG *pN)
{
	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(hmod, hmod->e_lfanew);

	if (offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT + 1]) <=
		pinth->FileHeader.SizeOfOptionalHeader)
	{
		if (ULONG VirtualAddress = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			if (CreateSSNTable(hmod, (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(hmod, VirtualAddress), ppTable, pN))
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

ULONG SyscallNum(_In_ ULONG hash, _In_ SSN* pTable, _In_ ULONG b) 
{
	ULONG a = 0, o;
	do 
	{
		ULONG h = pTable[o = (a + b) >> 1].hash;

		if (hash == h)
		{
			return pTable[o].ssn;
		}

		if (h < hash) a = o + 1; else b = o;

	} while (a < b);

	__debugbreak();
	return 0;
}

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"
#include "rtlframe.h"

struct SSN_INFO 
{
	PVOID _M_apiAddr;
	SSN* _M_pTable;
	ULONG _M_apiSSN;
	ULONG _M_N;
	ULONG _M_TargetSSN;
};

#define TRACE_FLAG	0x100

LONG NTAPI OnVex(EXCEPTION_POINTERS *ExceptionInfo)
{
	if (STATUS_SINGLE_STEP == ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
		if (SSN_INFO* p = RTL_FRAME<SSN_INFO>::get())
		{
			if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress - (ULONG_PTR)p->_M_apiAddr < 16)
			{
				if (ExceptionInfo->ContextRecord->Rax == p->_M_apiSSN)
				{
					ExceptionInfo->ContextRecord->Rax = p->_M_TargetSSN;

					ExceptionInfo->ContextRecord->EFlags &= ~TRACE_FLAG;
				}
				else
				{
					ExceptionInfo->ContextRecord->EFlags |= TRACE_FLAG;
				}

				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

EXTERN_C_START
PVOID __imp_NtOpenKey=0, __imp_NtQueryValueKey=0, __imp_NtClose=0;
EXTERN_C_END

extern volatile const UCHAR guz = 0;

void Stub()ASM_FUNCTION;

void PrepareCall(RTL_FRAME<SSN_INFO>* prf, void** pimp, ULONG hash)
{
	*pimp = Stub;
	prf->_M_TargetSSN = SyscallNum(hash, prf->_M_pTable, prf->_M_N);
}

#define hash_NtDrawText			0xa5f7373d
#define hash_NtOpenKey			0x334977c3
#define hash_NtQueryValueKey	0x5aabc376
#define hash_NtClose			0x04d4d176

BOOL IsRegSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	ULONG DataLength;
	return pkvpi->Type == REG_SZ && (DataLength = pkvpi->DataLength) && 
		!(DataLength & (sizeof(WCHAR) - 1)) &&
		!*(PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength - sizeof(WCHAR));
}

void NTAPI ep(PIMAGE_DOS_HEADER hmod)
{
#ifdef _PREPARE_

	static const PCSTR hh[] = {
		"DrawText", "OpenKey", "QueryValueKey", "Close", 0
	};

	Prepare(hh);
#endif

	RTL_FRAME<SSN_INFO> rf;

	if (GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
		(PCWSTR)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr, (HMODULE*)&hmod) &&
		InitSysCall(hmod, &rf._M_pTable, &rf._M_N))
	{

		ULONG i = 0, N = rf._M_N;
		SSN* pTable = rf._M_pTable;
		do 
		{
			if (hash_NtDrawText == pTable->hash)
			{
				rf._M_apiAddr = (PBYTE)hmod + pTable->Address;
				rf._M_apiSSN = i;

				pTable = rf._M_pTable, N = rf._M_N, i = 0;

				do 
				{
					pTable++->ssn = i++;
				} while (--N);

				qsort(rf._M_pTable, rf._M_N, sizeof(SSN), SSN::CompareH);

				if (PVOID h = AddVectoredExceptionHandler(TRUE, OnVex))
				{
					NTSTATUS status;
					UNICODE_STRING ObjectName;
					OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
					HANDLE hKey;

					RtlInitUnicodeString(&ObjectName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control");

					PrepareCall(&rf, &__imp_NtOpenKey, hash_NtOpenKey);
					
					if (0 <= (status = NtOpenKey(&hKey, KEY_READ, &oa)))
					{
						RtlInitUnicodeString(&ObjectName, L"SystemStartOptions");

						PVOID stack = alloca(guz);

						union {
							PVOID buf = 0;
							PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi;
						};

						PrepareCall(&rf, &__imp_NtQueryValueKey, hash_NtQueryValueKey);

						ULONG cb = 0, rcb = 0x20;

						do 
						{
							if (cb < rcb)
							{
								cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
							}

							status = NtQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, buf, cb, &rcb);

						} while (STATUS_BUFFER_OVERFLOW == status);

						PrepareCall(&rf, &__imp_NtClose, hash_NtClose);

						NtClose(hKey);

						if (0 <= status)
						{
							if (IsRegSz(pkvpi))
							{
								MessageBoxW(0, (PWSTR)pkvpi->Data, L"SystemStartOptions", MB_ICONINFORMATION);
							}
							else
							{
								status = STATUS_OBJECT_TYPE_MISMATCH;
							}
						}
					}

					if (0 > status)
					{
						PWSTR psz;

						if (FormatMessageW(
							FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_IGNORE_INSERTS,
							hmod, status, 0, (PWSTR)&psz, 0, 0))
						{
							MessageBoxW(0, psz, 0, MB_ICONWARNING);
							LocalFree(psz);
						}
					}

					RemoveVectoredExceptionHandler(h);
				}

				break;
			}

		} while (pTable++, i++, --N);

		delete [] rf._M_pTable;
	}

	ExitProcess(0);
}