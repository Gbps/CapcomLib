#pragma once

#include "stdafx.h"
#include "Win32Helpers.h"
#include "Helpers.h"
#include "PEFile.h"
#include "Win32Kernel.h"

class PEImage;

// Pair of (KLoadedImageBase, PEImage)
using loaded_kmodule_entry = std::pair<PVOID, std::shared_ptr<PEImage>>;

// A very simple reflexive PE loader
// Doesn't do anything fancy (.NET, SxS, AppCompat, or APISet)
// Based off of some ReactOS code and reinterpreted for C++ :)
class PEImage
{
public:
	// Load a PE file from the path specified by Filename
	PEImage(const std::wstring& Filename);

	// PE file is already loaded
	PEImage(std::unique_ptr<PEFile> LoadedFile);

	~PEImage();

	// Maps and links a module in preparation to be copied directly to the kernel
	HMODULE MapForKernel();

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

	// If this module is already loaded in memory elsewhere (like the kernel), returns its base address
	auto GetActualBase() const
	{
		return m_ActualBaseAddress;
	}

	// Gets the entry point RVA
	auto GetEntryPointRVA() const
	{
		return m_PE->GetEntryPointRVA();
	}

	// Gets the total size of the entire mapped region
	auto GetMappedSize() const
	{
		return m_PE->GetSizeOfImage();
	}

private:

	// Maps a PE file into memory as a loaded image. 
	// Maps the entire image into a flat area of memory. 
	// Does not create separate allocations for each section.
	// Useful for driver modules because their sections are mapped flat with the PE
	HMODULE MapFlat(BOOL isForKernel = TRUE, PVOID loaderBase = 0, BOOL loadAsDataFile = FALSE);

	// Use VirtualAlloc to allocate memory to map the entire image
	// NOTE: This is a flat allocator. The image will be in one large mapped
	// section. At the moment, this is preferrable for the task at hand!
	VOID AllocFlat();

	// Relocates an image in memory by fixing up each address specified in the PE
	VOID DoRelocateImage();

	// Process the Blocks field of a single IMAGE_BASE_RELOCATION
	auto ProcessRelocationBlocks(PWORD BlocksAddress, PULONG RelocBaseAddress, SIZE_T RelocDelta, SIZE_T Count);

	// Safe copy to mapped sections
	VOID _MapSafeCopy(PBYTE TargetVA, PBYTE SourceVA, SIZE_T Size);

	// Uses NtQuerySystemInformation to get addresses of system modules
	void GetSystemModules();

	// Resolves import for manually mapped image
	void PEImage::LinkImage(BOOL IsKernel);
	
	// Loads a kernel module off of the disk by name, using information from NTQSI
	std::shared_ptr<PEImage> PEImage::FindOrMapKernelDependency(std::string ModuleName);

	// Finds the export RVA of either a name or ordinal import
	PVOID PEImage::FindImport(
		const char* ImportName,
		int Ordinal);

	// Get actual mapped address of export by name
	PVOID PEImage::GetExportByName(const char* ImportName);

	// Get actual mapped address of export by ordinal
	PVOID PEImage::GetExportByOrdinal(WORD InputOrdinal);

private:
	// Loaded and parsed PE File
	std::unique_ptr<PEFile> m_PE;

	// Memory of the manually mapped image
	unique_virtalloc<> m_Mem;

	// Size of manually memory mapped image
	SIZE_T m_MemSize;

	// Actual base address for linking modules in-place
	PVOID m_ActualBaseAddress;

	// Other modules loaded and mapped for the linking process only
	static std::unordered_map<std::string, std::shared_ptr<PEImage>> MappedModules;

	// Modules of the current system when the linking process begins
	static modules_map KernelModules;
};
