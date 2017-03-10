// WXPolicyTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

bool TestAlloc(DWORD pageFlags)
{
	bool result = false;
	void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, pageFlags);
	if (mem != NULL)
	{
		result = true;
		VirtualFree(mem, 0, MEM_RELEASE);
	}
	return result;
}

bool TestAllocReadOnly()
{
	return TestAlloc(PAGE_READONLY);
}

bool TestAllocReadWrite()
{
	return TestAlloc(PAGE_READWRITE);
}

bool TestAllocNoAccess()
{
	return TestAlloc(PAGE_NOACCESS);
}

bool TestAllocExec()
{
	return TestAlloc(PAGE_EXECUTE);
}

bool TestAllocExecRead()
{
	return TestAlloc(PAGE_EXECUTE_READ);
}

bool TestAllocExecReadWrite()
{
	return TestAlloc(PAGE_EXECUTE_READWRITE);
}

bool TestAllocUpgrade(DWORD flagFirst, DWORD flagSecond)
{
	bool result = false;
	void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, flagFirst);
	if (mem != NULL)
	{
		DWORD oldProtect = 0;
		if (VirtualProtect(mem, 4096, flagSecond, &oldProtect) == TRUE)
		{
			result = true;
		}

		VirtualFree(mem, 0, MEM_RELEASE);
	}
	return result;
}

bool TestAllocReadOnlyToReadExec()
{
	return TestAllocUpgrade(PAGE_READONLY, PAGE_EXECUTE_READ);
}

bool TestAllocReadOnlyToReadWriteExec()
{
	return TestAllocUpgrade(PAGE_READONLY, PAGE_EXECUTE_READWRITE);
}

bool TestAllocReadWriteToReadExec()
{
	return TestAllocUpgrade(PAGE_READWRITE, PAGE_EXECUTE_READ);
}

bool TestThreeStageUpgrade()
{
	bool result = false;
	void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (mem != NULL)
	{
		DWORD oldProtect = 0;
		if (VirtualProtect(mem, 4096, PAGE_READONLY, &oldProtect) == TRUE)
		{
			if (VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &oldProtect) == TRUE)
			{
				result = true;
			}
		}

		VirtualFree(mem, 0, MEM_RELEASE);
	}
	return result;
}

int main()
{
	LoadLibrary(L"WXPolicyEnforcer.dll");

	printf("Waiting for user input...\n");
	system("PAUSE");

	printf("%-70s", "Testing PAGE_READONLY allocation... ");
	if (TestAllocReadOnly())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_READWRITE allocation... ");
	if (TestAllocReadWrite())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_NOACCESS allocation... ");
	if (TestAllocNoAccess())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_EXECUTE allocation... ");
	if (TestAllocExec())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_EXECUTE_READ allocation... ");
	if (TestAllocExecRead())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_EXECUTE_READWRITE allocation... ");
	if (TestAllocExecReadWrite())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_READONLY to PAGE_EXECUTE_READ protection change... ");
	if (TestAllocReadOnlyToReadExec())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_READONLY to PAGE_EXECUTE_READWRITE protection change... ");
	if (TestAllocReadOnlyToReadWriteExec())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing PAGE_READWRITE to PAGE_EXECUTE_READ protection change... ");
	if (TestAllocReadWriteToReadExec())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");

	printf("%-70s", "Testing three-stage (RW-RO-RX) protection change... ");
	if (TestThreeStageUpgrade())
		printf("[  OK  ]\n");
	else
		printf("[ FAIL ]\n");


	system("PAUSE");

    return 0;
}

