// CapcomLib.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DriverLoader.h"


DECLARE_UNICODE_STRING(strAllocPoolWithTag, L"ExAllocatePoolWithTag");

PVOID NTAPI LoaderPayload(MMGETSYSTEMROUTINEADDRFUNC _MmGetSystemRoutineAddress)
{
	__debugbreak();
	PVOID res = reinterpret_cast<PVOID>(_MmGetSystemRoutineAddress(&strAllocPoolWithTag));


	return nullptr;
}

int main()
{
	DriverLoader loader;
	loader.LoadCapcomService();
	loader.ExecIoCtlWithTrampoline(LoaderPayload);

	getchar();
    return 0;
}

