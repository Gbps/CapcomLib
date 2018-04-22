#pragma once
#include "IVulnDriver.h"
#include "../DriverLoader.h"
#include "../PELoader.h"
#include "../Win32Kernel.h"
#include "../Util.h"

class VulnDriverOptions
{
public:
	// The PEImage to be loaded by the vuln driver, loaded PreExploit is called
	std::unique_ptr<PEImage> Image;

	// Service name created by the loader
	std::wstring ServiceName;
};

class BaseVulnDriver : public IVulnDriver
{
public:
	// Inherited via IVulnDriver
	virtual bool MapDriver(const std::wstring& DriverLocation, const std::wstring& DisplayName) override;

	virtual bool EnsureValidTarget() override;

	virtual void Exploit() override;

	virtual void Cleanup() override;

	virtual const std::wstring& GetVulnDriverName() override;

protected:

	// All options requested by the driver loader for the vulnerable driver to adhere to
	VulnDriverOptions Options;

private:
	const std::wstring m_DriverName = L"Unknown";

};

