#pragma once

#include "stdafx.h"

// Auto deleter for C++ smart pointers for Win32 Handles
struct Win32HandleDeleter
{
	void operator()(HANDLE handle)
	{
		if (handle != nullptr)
		{
			::CloseHandle(handle);
		}
	}
};

// C++ Smart Pointer for Win32 Handles
using unique_handle = std::unique_ptr<void, Win32HandleDeleter>;

// Auto deleter for C++ smart pointers for Win32 LoadLibrary
struct Win32ModuleDeleter
{
	void operator()(HMODULE handle)
	{
		if (handle != nullptr)
		{
			::FreeLibrary(handle);
		}
	}
};

// C++ Smart Pointer for Win32 Handles
using unique_module = std::unique_ptr<void, Win32ModuleDeleter>;

// Auto deleter for C++ smart pointers for VirtualAlloc memory
struct VirtualFreeDeleter
{
	void operator()(LPVOID mem)
	{
		if (mem != nullptr)
		{
			auto ret = ::VirtualFree(mem, 0, MEM_RELEASE);

			// Should this throw an exception?
			if (!ret) throw std::runtime_error("VirtualFree failure");
		}
	}
};

// C++ Smart Pointer for VirtualAlloc memory
template<typename PtrType = VOID>
using unique_virtalloc = std::unique_ptr<PtrType, VirtualFreeDeleter>;

// Creates an ownership-managed object that creates a UNICODE_STRING from a wstring
template <class StrClass>
class Win32STLUnicodeString : public UNICODE_STRING
{
public:
	StrClass innerStr;

	Win32STLUnicodeString(const StrClass& _innerStr)
	{
		innerStr = _innerStr;
		::RtlInitUnicodeString(this, innerStr.c_str());
	}
};
