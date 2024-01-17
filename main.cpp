#include "StdAfx.h"
#include "ssn.h"

extern volatile const UCHAR guz = 0;

BOOL IsRegSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	ULONG DataLength;
	return pkvpi->Type == REG_SZ && (DataLength = pkvpi->DataLength) && 
		!(DataLength & (sizeof(WCHAR) - 1)) &&
		!*(PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength - sizeof(WCHAR));
}

NTSTATUS ShowStringValue(_In_ PCWSTR pszKey, _In_ PCWSTR pszValue)
{
	NTSTATUS status;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	HANDLE hKey;

	RtlInitUnicodeString(&ObjectName, pszKey);

	if (0 <= (status = NtOpenKey(&hKey, KEY_READ, &oa)))
	{
		RtlInitUnicodeString(&ObjectName, pszValue);

		PVOID stack = alloca(guz);

		union {
			PVOID buf = 0;
			PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi;
		};

		ULONG cb = 0, rcb = 0x20;

		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, buf, cb, &rcb);

		} while (STATUS_BUFFER_OVERFLOW == status);

		NtClose(hKey);

		if (0 <= status)
		{
			if (IsRegSz(pkvpi))
			{
				MessageBoxW(0, (PWSTR)pkvpi->Data, pszValue, MB_ICONINFORMATION);
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

		HMODULE hmod;
		if (GetNtBase(&hmod) && FormatMessageW(
			FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_IGNORE_INSERTS,
			hmod, status, 0, (PWSTR)&psz, 0, 0))
		{
			MessageBoxW(0, psz, pszValue, MB_ICONWARNING);
			LocalFree(psz);
		}
	}

	return status;
}

struct THREAD_DATA  
{
	const SSN_INFO* q;
	PCWSTR pszKey, pszValue;
};

ULONG WINAPI ThreadEntry(THREAD_DATA* ptd)
{
	RTL_FRAME<SSN_INFO> rf;
	*static_cast<SSN_INFO*>(&rf) = *ptd->q;

	return ShowStringValue(ptd->pszKey, ptd->pszValue);
}

void UserEntry(const SSN_INFO* pi)
{
	THREAD_DATA td = { 
		pi, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLabEx"
	};

	if (HANDLE hThread = CreateThread(0, 0, (PTHREAD_START_ROUTINE)ThreadEntry, &td, 0, 0))
	{
		ShowStringValue(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control", L"SystemStartOptions");
		WaitForSingleObject(hThread, INFINITE);
		NtClose(hThread);
	}
}