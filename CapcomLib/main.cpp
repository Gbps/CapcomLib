// CapcomLib.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DriverLoader.h"
#include "PELoader.h"
#include "PEFile.h"
#include "KernelHelp.h"

#include "VulnDrivers\CapcomDriver.h"
int main()
{
	try
	{
		CapcomDriver driver;
		driver.MapDriver(Util::Path::RelativeToAbsolute(L"TestDriver.sys"), L"Capcom");
	}
	catch (std::exception e)
	{
		Util::Debug::Print("[EXCEPTION] %s\n", e.what());
	}
	
	
	getchar();
    return 0;
}

 