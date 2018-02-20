#pragma once
#include "stdafx.h"

// Maximum size returned from stdstrerror
const auto STRERROR_MAXSIZE = 5000ULL;

// Prints a Win32 error and exits the console program
// https://github.com/iceb0y/ntdrvldr/blob/master/main.c
VOID PrintErrorAndExit(wchar_t *Function, ULONG dwErrorCode);

// Returns an std::string version of strerror of up to STRERROR_MAXSIZE size
std::string stdstrerror(int errnum);

// Pointer type conversion with no offset
template<typename TargetType>
TargetType MakePointer(void* anyptr)
{
	return reinterpret_cast<TargetType>(anyptr);
}

// Pointer type conversion with byte offset
template<typename TargetType>
TargetType MakePointer(void* anyptr, SIZE_T offset)
{
	return reinterpret_cast<TargetType>(reinterpret_cast<SIZE_T>(anyptr) + offset);
}

// pls
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECIATION_WARNING

// Convert string to wstring
inline std::wstring multi2wide(const std::string& str, UINT codePage = CP_THREAD_ACP)
{
	if (str.empty())
	{
		return std::wstring();
	}

	int required = ::MultiByteToWideChar(codePage, 0, str.data(), static_cast<int>(str.size()), NULL, 0);
	if (0 == required)
	{
		return std::wstring();
	}

	std::wstring str2;
	str2.resize(required);

	int converted = ::MultiByteToWideChar(codePage, 0, str.data(), static_cast<int>(str.size()), &str2[0], static_cast<int>(str2.capacity()));
	if (0 == converted)
	{
		return std::wstring();
	}

	return str2;
}