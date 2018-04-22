#pragma once
#include "stdafx.h"

class IVulnDriver
{
public:

	// Map the driver located at DriverLocation with service display name DisplayName
	virtual bool MapDriver(const std::wstring& DriverLocation, const std::wstring& DisplayName) = 0;

	// Ensure machine is vulnerable, etc.
	// Called before the target driver is prepared to be mapped
	// Return false to stop the loading process
	virtual bool EnsureValidTarget() = 0;

	// Ensure that the vulnerable driver loaded correctly.
	// Typically checking for the existance of a device
	virtual bool EnsureDriverLoaded() = 0;

	// Prepare shellcode and exploit vulnerable driver
	// Throwing an exception will cause a cleanup
	virtual void Exploit() = 0;

	// Unloads vulnerable driver and cleans up
	virtual void Cleanup() = 0;

	// Returns the name of the driver file of this vulnerable driver class
	virtual const std::wstring& GetVulnDriverName() = 0;
};