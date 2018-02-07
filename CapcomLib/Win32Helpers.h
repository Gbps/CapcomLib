#pragma once

#include "stdafx.h"

// Auto deleter for C++ smart pointers for Win32 Handles
struct Win32HandleDeleter
{
	void operator()(HANDLE handle)
	{
		if (handle != nullptr)
		{
			CloseHandle(handle);
		}
	}
};

// C++ Smart Pointer for Win32 Handles
using unique_handle = std::unique_ptr<void, Win32HandleDeleter>;

// Creates an ownership-managed object that creates a UNICODE_STRING from a wstring
template <class StrClass>
class Win32STLUnicodeString : public UNICODE_STRING
{
public:
	StrClass innerStr;

	Win32STLUnicodeString(const StrClass& _innerStr)
	{
		innerStr = _innerStr;
		RtlInitUnicodeString(this, innerStr.c_str());
	}
};
