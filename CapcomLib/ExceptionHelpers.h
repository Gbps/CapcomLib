#pragma once
#include "stdafx.h"

// Throws a C-style formatted std::runtime_error
template<typename ... Args>
PVOID ThrowFmtError(const std::string& format, Args ... args)
{
	SIZE_T size = snprintf(nullptr, 0, format.c_str(), args ...) + 1;
	std::unique_ptr<char[]> buf(new char[size]);
	snprintf(buf.get(), size, format.c_str(), args ...);
	auto outMsg = std::string(buf.get(), buf.get() + size - 1);

	throw std::runtime_error(outMsg.c_str());
}

// Throws a C-style formatted std::runtime_error
template<typename ... Args>
PVOID ThrowLdrError(const std::string& format, Args ... args)
{
	auto newfmt = "[PELoader] "s + format;
	SIZE_T size = snprintf(nullptr, 0, newfmt.c_str(), args ...) + 1;
	std::unique_ptr<char[]> buf(new char[size]);
	snprintf(buf.get(), size, newfmt.c_str(), args ...);
	auto outMsg = std::string(buf.get(), buf.get() + size - 1);

	throw std::runtime_error(outMsg.c_str());
}

// Throw the error message for GetLastError
VOID ThrowLdrLastError(const std::wstring & funcname);

// Throw the error message for GetLastError on invalid handle
VOID ThrowLdrLastErrorOnInvalidHandle(const std::wstring & funcname, HANDLE handle);