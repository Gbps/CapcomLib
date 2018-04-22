#pragma once
#include "stdafx.h"
#include "Win32Kernel.h"
#include "PELoader.h"

namespace DriverLoader
{
	// Create registry entries and attempt to load a driver from the given path
	void MakeService(const std::wstring& DriverPath, const std::wstring& DisplayName);

	// Stops the service and unloads the driver
	void RemoveServiceIfExists(const std::wstring& DisplayName);
}


