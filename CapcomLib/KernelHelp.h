#pragma once

#include "stdafx.h"
#include "Win32Kernel.h"

#define K_GetRoutine(_NAME) \
	KernelHelp::GetRoutineAddr<_NAME##Func>(_MmGetSystemRoutineAddress, L#_NAME)

class KernelHelp
{
public:
	KernelHelp();
	~KernelHelp();


	/// Grabs a function address in the kernel using MmGetSystemRoutineAddress
	template<class T>
	static T GetRoutineAddr(MmGetSystemRoutineFunc _MmGetSystemRoutine, const TCHAR* RoutineName)
	{
		UNICODE_STRING LocalRoutineName = {};
		RtlInitUnicodeString(&LocalRoutineName, RoutineName);
		return reinterpret_cast<T>(_MmGetSystemRoutine(&LocalRoutineName));
	}

};

