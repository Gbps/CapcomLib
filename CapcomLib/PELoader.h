#pragma once

#include "stdafx.h"
#include "Win32Helpers.h"
#include "Helpers.h"
#include "PEFile.h"

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
	HMODULE MapFlat(DWORD flProtect = PAGE_EXECUTE_READWRITE, BOOL shouldCopyHeaders = TRUE);

	// Gets a pointer to the end of mapped memory
	template<typename TargetPtr>
	auto GetMappedEnd() const
	{
		return MakePointer<TargetPtr>(m_Mem.get(), m_MemSize);
	}

	// Gets a pointer to the beginning of mapped memory
	template<typename TargetPtr>
	auto GetMappedBase() const
	{
		return MakePointer<TargetPtr>(m_Mem.get());
	}

	// Calculate an offset from the base of mapped memory
	template<typename TargetPtr>
	TargetPtr OffsetFromMappedBase(SIZE_T Offset) const
	{
		auto ptr = MakePointer<TargetPtr>(m_Mem.get(), Offset);
		if (ptr >= GetMappedEnd<TargetPtr>() || ptr < m_Mem.get())
		{
			ThrowLdrError("OffsetFromMappedBase: Invalid mapped address");
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
private:
	// Loaded and parsed PE File
	std::unique_ptr<PEFile> m_PE;

	// Memory of the manually mapped image
	unique_virtalloc m_Mem;

	// Size of manually memory mapped image
	SIZE_T m_MemSize;
};

