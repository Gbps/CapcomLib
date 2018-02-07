#pragma once

#include "stdafx.h"
#include "Win32Helpers.h"
#include "Helpers.h"

// A very simple reflexive PE loader
// Doesn't do anything fancy (.NET, SxS, AppCompat, or APISet)
// Based off of some ReactOS code and reinterpreted for C++ :)
class PELoader
{
public:
	// Load a PE file from the path specified by Filename
	PELoader(const std::wstring& Filename);

	// If PE file already exists in memory, load by passing the address of the base of the image
	PELoader(SIZE_T ImageBase);

	~PELoader();

	// Loads the PE file from a file given by Filename
	VOID DoLoadFromFile(const std::wstring& Filename);

	// True if the PE file exists in memory
	VOID DoValidBaseCheck();

	// Relocates PE file (for dll-type files)
	VOID DoRelocateImage();

	// Returns true if the NtHeaders have the given flag
	BOOL HasNtHeaderFlag(WORD Flag);

	// Gets the base of the module
	PVOID GetLoadedBase();

	// Gets the image base of the module from the PE
	LONGLONG GetPEImageBase();

	// Gets the data directory entry in the NtHeaders
	PIMAGE_DATA_DIRECTORY GetPEDataDirectoryEntry(WORD DirectoryEnum);

	// Verifies and returns PIMAGE_NT_HEADERS for PE file
	PIMAGE_NT_HEADERS GetNtHeaders();

private:

	// Handle to the underlying PE file
	unique_handle m_FileHandle;

	// Handle to the underlying file mapping
	unique_handle m_FileMapping;

	// Pointer to the base of the module loaded in memory if the file already exists in memory
	PVOID m_InMemoryBase = NULL;

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

	// Throws the error message for GetLastError. Includes the given funcname in the message.
	VOID ThrowLdrLastError(const std::wstring& funcname);

	// Ensures a valid handle, otherwise throws a loader error for the given funcname
	VOID ThrowLdrLastErrorOnInvalidHandle(const std::wstring& funcname, HANDLE handle);

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

