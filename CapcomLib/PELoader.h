#pragma once

#include "stdafx.h"
#include "Win32Helpers.h"
#include "Helpers.h"
#include "PEFile.h"
#include "Win32Kernel.h"

class PELoader;

// For ordinal/address exports
class PEFileExport
{
public:

	PEFileExport() {}

	PEFileExport(SIZE_T address, WORD ordinal)
	{
		Address = address;
		Ordinal = ordinal;
	}

	SIZE_T Address = 0;
	WORD Ordinal = -1;
};

// For ordinal/address imports
class PEFileImport
{
public:

	PEFileImport() {}

	PEFileImport(const std::string& name, WORD ordinal)
	{
		Name = name;
		Ordinal = ordinal;
	}

	std::string Name;
	WORD Ordinal = -1;
};


// Hashmap of exports from a module
using exports_hashmap = std::unordered_map<std::string, PEFileExport>;

// Import list
using imports_list = std::list<PEFileImport>;

// Pair of (KLoadedImageBase, PELoader)
using loaded_kmodule_entry = std::pair<PVOID, std::shared_ptr<PELoader>>;

// A very simple reflexive PE loader
// Doesn't do anything fancy (.NET, SxS, AppCompat, or APISet)
// Based off of some ReactOS code and reinterpreted for C++ :)
class PELoader
{
public:
	// Load a PE file from the path specified by Filename
	PELoader(const std::wstring& Filename);

	// PE file is already loaded
	PELoader(std::unique_ptr<PEFile> LoadedFile);

	~PELoader();

	// Maps a PE file into memory as a loaded image. 
	// Maps the entire image into a flat area of memory. 
	// Does not create separate allocations for each section.
	// Useful for driver modules because their sections are mapped flat with the PE
	HMODULE MapFlat(DWORD flProtect = PAGE_EXECUTE_READWRITE, BOOL shouldCopyHeaders = TRUE, BOOL loadAsDataFile = FALSE);

	// Gets a pointer to the end of mapped memory
	template<typename TargetPtr>
	auto GetMappedEnd() const
	{
		return MakePointer<TargetPtr>(m_Mem.get(), m_MemSize);
	}

	// Gets a pointer to the beginning of mapped memory
	template<typename TargetPtr = PVOID>
	auto GetMappedBase() const
	{
		return MakePointer<TargetPtr>(m_Mem.get());
	}

	// Calculate an offset from the base of mapped memory
	template<typename TargetPtr = PVOID>
	TargetPtr FromRVA(SIZE_T Offset) const
	{
		auto ptr = MakePointer<TargetPtr>(m_Mem.get(), Offset);
		if (ptr >= GetMappedEnd<TargetPtr>() || ptr < m_Mem.get())
		{
			ThrowLdrError("FromRVA: Invalid mapped address");
		}
		return ptr;
	}

private:
	// Use VirtualAlloc to allocate memory to map the entire image
	// NOTE: This is a flat allocator. The image will be in one large mapped
	// section. At the moment, this is preferrable for the task at hand!
	VOID AllocFlat(DWORD flProtect = PAGE_EXECUTE_READWRITE);

	// Relocates an image in memory by fixing up each address specified in the PE
	VOID DoRelocateImage();

	// Process the Blocks field of a single IMAGE_BASE_RELOCATION
	auto ProcessRelocationBlocks(PWORD BlocksAddress, PULONG RelocBaseAddress, SIZE_T RelocDelta, SIZE_T Count);

	// Safe copy to mapped sections
	VOID _MapSafeCopy(PBYTE TargetVA, PBYTE SourceVA, SIZE_T Size);

	// Uses undocumented NtQuerySystemInformation to leak addresses of system modules
	auto GetSystemModules();

	// Resolves import for manually mapped image
	auto DoImportResolve(BOOL IsDriver = FALSE);

	// Loads a kernel module off of the disk by name, using information from NTQSI
	// Returns a pair of the ImageBase and the loaded kernel module (unmapped)
	loaded_kmodule_entry FindAndLoadKernelModule(const modules_map & SysModules, std::string ModuleName);

	// Finds a loaded kernel module by name, loads it, and finds the export address to pre-link modules before mapping.
	PVOID PELoader::FindAndLoadKernelExport(
		std::shared_ptr<PELoader> ModulePE,
		PVOID KernelLoadedBase,
		std::string ImportName,
		int Ordinal = -1 );

	// Loads all export entires for this module. Will load additional modules if necessary for forward imports
	const exports_hashmap& PELoader::GetExports();

	// Resolve imports for a PE in a flat mapped address space in prepartion to be copied into kernel space
	void DoImportResolveKernel(IMAGE_DATA_DIRECTORY &ImageDDir);

private:
	// Loaded and parsed PE File
	std::unique_ptr<PEFile> m_PE;

	// Memory of the manually mapped image
	unique_virtalloc<> m_Mem;

	// Size of manually memory mapped image
	SIZE_T m_MemSize;

	// All export entries resolved for this module
	exports_hashmap m_Exports;

	// All import entries resolved for this module
	imports_list m_Imports;
};
