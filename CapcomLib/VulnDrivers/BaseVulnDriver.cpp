#include "stdafx.h"
#include "BaseVulnDriver.h"

bool BaseVulnDriver::EnsureValidTarget()
{
	Util::Debug::Print("BaseVulnDriver::EnsureValidTarget\n");

	return true;
}

void BaseVulnDriver::Exploit()
{
	Util::Debug::Print("BaseVulnDriver::Exploit [%S]\n", Options.ServiceName.c_str());
}

void BaseVulnDriver::Cleanup()
{
	Util::Debug::Print("BaseVulnDriver::Cleanup\n");

	// Unload the driver from the system
	DriverLoader::RemoveServiceIfExists(Options.ServiceName);
}

const std::wstring& BaseVulnDriver::GetVulnDriverName()
{
	return m_DriverName;
}

bool BaseVulnDriver::MapDriver(const std::wstring& DriverLocation, const std::wstring& DisplayName)
{
	auto self = dynamic_cast<IVulnDriver*>(this);
	const auto& VulnDriverName = self->GetVulnDriverName();

	Util::Debug::Print("MapVulnDriver :: Begin load '%ws'\n", VulnDriverName.c_str());

	auto path = Util::Path::RelativeToAbsolute(L"/drivers/" + VulnDriverName);

	if (!EnsureValidTarget())
	{
		Util::Debug::Print("MapVulnDriver :: Not a valid target\n");
		return false;
	}

	Util::Debug::Print("MapVulnDriver :: Machine is valid\n");

	// Load and map the target driver
	auto target = std::make_unique<PEImage>(DriverLocation);

	// Create service for vuln driver
	DriverLoader::MakeService(path, DisplayName);

	if (!EnsureDriverLoaded())
	{
		Util::Debug::Print("MapVulnDriver :: Driver did not load properly\n");
		Cleanup();
		return false;
	}

	Util::Debug::Print("MapVulnDriver :: Service loaded [%S]\n", DisplayName.c_str());

	// Setup options so the BaseVulnDriver has access to 
	Options.Image = move(target);
	Options.ServiceName = DisplayName;

	try
	{
		Exploit();
		Util::Debug::Print("MapVulnDriver :: Exploit successful\n");
	}
	catch (std::exception e)
	{
		// Ask driver to clean up resources then rethrow
		Cleanup();
		throw e;
	}

	// Cleanup and finish
	Cleanup();

	return true;
}
