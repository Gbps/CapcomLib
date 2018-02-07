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

	// Gets the base of the module mapping
	PVOID GetLoadedBase();

	// Gets the base of the PE file loaded in memory. Only call for manually mapped images.
	PVOID GetPEBase();

	// Gets the ImageBase field of the module from the PE
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

	// Pointer to the base of the PE file (not mapped!) in memory
	PVOID m_FileMemoryBase = NULL;

	// Pointer to manually mapped memory during loading
	unique_virtalloc m_InMemoryManual;

	// Allocates memory to perform manual section mapping
	VOID AllocManualMap();
};

