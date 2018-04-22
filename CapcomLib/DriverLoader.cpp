#include "stdafx.h"
#include "DriverLoader.h"
#include "Util.h"
#include "VulnDrivers\BaseVulnDriver.h"

void DriverLoader::MakeService(const std::wstring& DriverPath, const std::wstring& DisplayName)
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
	hService = CreateService(hSCManager, DisplayName.c_str(), DisplayName.c_str(), SERVICE_START | DELETE | SERVICE_STOP, \
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, csDriverPath, NULL, NULL, NULL, NULL, NULL);

	// If the service already exists on the system, simply use that service instead
	if (!hService)
	{
		hService = OpenService(hSCManager, DisplayName.c_str(), SERVICE_START | DELETE | SERVICE_STOP);
	}

	if (!hService) Util::Exception::ThrowLastError(L"OpenService");

	// Start the service. This ensures that module is loaded.
	StartServiceW(hService, 0, NULL);

	CloseServiceHandle(hService);

	CloseServiceHandle(hSCManager);
}

void DriverLoader::RemoveServiceIfExists(const std::wstring& DisplayName)
{
	SERVICE_STATUS status;

	auto manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (manager == NULL) Util::Exception::ThrowLastError("OpenSCManager");
	
	auto service = OpenService(manager, DisplayName.c_str(), SERVICE_ALL_ACCESS);

	if (service == NULL)
	{
		CloseServiceHandle(manager);
		return;
	}

	if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
	{
		CloseServiceHandle(manager);
		CloseServiceHandle(service);
		return;
	}

	CloseServiceHandle(manager);
	CloseServiceHandle(service);
}
