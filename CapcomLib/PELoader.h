#pragma once

#include "stdafx.h"

// A reflexive PE loader
// Provides general interfaces for interacting with PE files in memory
// Based off of ReactOS code and reinterpreted for C++ :)
class PELoader
{
public:
	PELoader(const std::wstring& Filename);
	PELoader(SIZE_T ImageBase);
	~PELoader();

	VOID LoadFromFile(const std::wstring& filename);

	// True if the PE file exists in memory
	VOID CheckValidBase();

	// Gets the base of the module
	PVOID GetPEBase();

	// Verifies and returns PIMAGE_NT_HEADERS for PE file
	PIMAGE_NT_HEADERS GetNTHeaders();

private:
	// Pointer to the base of the module loaded in memory if the file already exists in memory
	PBYTE m_InMemoryBase = NULL;

	// When loaded from a file, the memory of the file is stored here
	std::unique_ptr<std::vector<char>> m_Image;

	// Throws a C-style formatted std::runtime_error
	template<typename ... Args>
	PVOID ThrowLdrError(const std::string& format, Args ... args)
	{
		auto newfmt = "[PELoader] "s + format;
		SIZE_T size = snprintf(nullptr, 0, newfmt.c_str(), args ...) + 1; // Extra space for '\0'
		unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, newfmt.c_str(), args ...);
		auto outMsg = string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside

		throw runtime_error(outMsg.c_str());
	}

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
};

