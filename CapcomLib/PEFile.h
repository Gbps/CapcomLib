#pragma once
#include "stdafx.h"
#include "Win32Helpers.h"
#include "ExceptionHelpers.h"
#include "Helpers.h"

class PEFileSection;

// Describes a raw PE file in mapped into memory
class PEFile
{
	friend class PEFileSection;
public:
	// Load PE file from a file by mapping the file into the process VA
	PEFile(const std::wstring& Filename);

	// If the PE file is already in memory, use this one
	PEFile(PVOID PEFileMemoryBase, SIZE_T PEFileMemorySize);

	// Get the total size of the image after mapping
	SIZE_T GetTotalMappedSize();

	// Get sections to map memory of PE
	auto GetSections() const
	{
		return m_MemSections;
	}

	~PEFile();


	// Calculate an offset from the base of the file
	template<typename TargetPtr>
	TargetPtr OffsetFromBase(SIZE_T Offset) const
	{
		auto ptr = MakePointer<TargetPtr>(m_FileMemoryBase, Offset);
		if (ptr >= m_FileMemoryEnd || ptr < m_FileMemoryBase)
		{
			ThrowLdrError("OffsetFromBase: Invalid file offset");
		}
		return ptr;
	}

	// Get a reference to the base of the headers
	auto GetHeadersBase() const
	{
		return reinterpret_cast<const PIMAGE_DOS_HEADER&>(m_FileMemoryBase);
	}

	// Gets the size of all headers
	auto GetHeadersSize() const
	{
		return m_SizeOfHeaders;
	}

private:
	// Map a PE file into memory
	VOID LoadFromFile(const std::wstring & Filename);

	// Parses the PE file structure
	VOID ParsePE();

private:
	// Handle to the underlying PE file
	unique_handle m_FileHandle;

	// Handle to the underlying PE file mapping
	unique_handle m_FileMapping;

	// Pointer to the base of the PE file (not image mapped!) in memory
	PVOID m_FileMemoryBase;

	// Pointer to the end of the PE file
	PVOID m_FileMemoryEnd;

	// Memory section list for the memory mapper
	std::vector<IMAGE_SECTION_HEADER> m_MemSections;

private:
	
	// PE Structure Elements below
	// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files

	// Is the image 64-bit?
	BOOL m_Is64;

	// Is the image an EXE?
	BOOL m_IsExe;

	/* 
	   The preferred address of the first byte of the image when it is loaded in memory.
	   This value is a multiple of 64K bytes. The default value for DLLs is 0x10000000. 
	   The default value for applications is 0x00400000, except on Windows CE where it is 0x00010000. 
	*/
	ULONGLONG m_ImageBase;
	
	/*
	   The size of the image, in bytes, including all headers. Must be a multiple of SectionAlignment.
	*/
	DWORD m_SizeOfImage;

	/* 
	   The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.
	   * e_lfanew member of DOS_Header
	   * 4 byte signature
	   * size of COFFHeader
	   * size of optional Header
	   * size of all section headers
	*/
	DWORD m_SizeOfHeaders;

	/*
		A pointer to the entry point function, relative to the image base address. 
		For executable files, this is the starting address. For device drivers, this is the address of the initialization function. 
		The entry point function is optional for DLLs. When no entry point is present, this member is zero.
	*/
	DWORD m_AddressOfEntryPointRVA;

	/*
		The DLL characteristics of the image
	*/
	WORD m_DllCharacteristics;


};