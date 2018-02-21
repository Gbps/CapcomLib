#include "stdafx.h"
#include "PEFile.h"
#include "Win32Helpers.h"
#include "Helpers.h"
#include "ExceptionHelpers.h"

using namespace std;


PEFile::PEFile(const std::wstring & Filename)
{
	LoadFromFile(Filename);
	ParsePEHeaders();
}

PEFile::PEFile(PVOID PEFileMemoryBase, SIZE_T PEFileMemorySize)
{
	m_FileMemoryBase = PEFileMemoryBase;
	m_FileMemoryEnd = MakePointer<PVOID>(m_FileMemoryBase, PEFileMemorySize);
	ParsePEHeaders();
}

PEFile::PEFile(unique_module Module)
{
	auto hModule = (HMODULE) Module.get();
	m_LoadedModule = move(Module);
	m_FileMemoryBase = hModule;

	ParsePEHeaders();

	m_FileMemoryEnd = MakePointer<PVOID>(m_FileMemoryBase, GetImageSize());
}

SIZE_T PEFile::GetTotalMappedSize()
{
	// NOTE: Probably can't trust this
	return m_SizeOfImage;
}

PEFile::~PEFile()
{
}

VOID PEFile::LoadFromFile(const wstring& Filename)
{
	// Open file readonly
	auto hFile = unique_handle
	{
		CreateFile(Filename.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, 0, NULL)
	};
	ThrowLdrLastError(L"CreateFile", hFile.get());

	// Get size of the image file
	auto dwFileSizeHigh = DWORD{};
	auto dwFileSizeLow = GetFileSize(hFile.get(), &dwFileSizeHigh);
	if (dwFileSizeLow == INVALID_FILE_SIZE) ThrowLdrLastError(L"GetFileSize");
	
	auto dwFileSize = DWORD64{ dwFileSizeHigh | dwFileSizeLow };

	// Create the file mapping (NOTE: Doing this manually, not as SEC_IMAGE, requires moving the sections manually)
	auto hMap = unique_handle
	{
		CreateFileMapping(hFile.get(), NULL, PAGE_READONLY, 0, 0, NULL)
	};
	ThrowLdrLastError(L"CreateFileMapping", hMap.get());

	// Create the view of the entire file
	auto PEFile = MapViewOfFile(hMap.get(), FILE_MAP_READ, 0, 0, 0);
	ThrowLdrLastError(L"MapViewOfFile", PEFile);

	// Commit the handles
	m_FileHandle = move(hFile);
	m_FileMapping = move(hMap);
	m_FileMemoryBase = PEFile;
	m_FileMemoryEnd = MakePointer<PVOID>(PEFile, dwFileSize);

}



// Loader process based off of Blackbone
// https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/PE/PEImage.cpp
VOID PEFile::ParsePEHeaders()
{
	// Ensure valid base address (i.e. module has been loaded into memory)
	if (!m_FileMemoryBase) ThrowFmtError("No module loaded");

	// DOS headers are at the very beginning of the PE file. Check signature!
	auto DosHeader = MakePointer<PIMAGE_DOS_HEADER>(m_FileMemoryBase);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		ThrowLdrError("Invalid image DOS signature");
	}

	// DOS headers give offset to NT headers
	auto NtHeaderOffset = DosHeader->e_lfanew;

	// Grab NT headers and verify signature
	auto NtHeaders = MakePointer<PIMAGE_NT_HEADERS64>(DosHeader, NtHeaderOffset);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		ThrowLdrError("Invalid image NT signature");
	}


	PIMAGE_SECTION_HEADER pSectionHeaders = nullptr;

	// I like this method of using a lambda for 32/64 switch, so I stole it
	// auto _NtHeaders will be either 32 or 64 bit depending on the optional headers below
	auto ParseHeaderFields = [this, &pSectionHeaders](auto _NtHeaders)
	{
		auto OptHdr = _NtHeaders->OptionalHeader;

		m_ImageBase = OptHdr.ImageBase;
		m_SizeOfImage = OptHdr.SizeOfImage;
		m_SizeOfHeaders = OptHdr.SizeOfHeaders;
		m_AddressOfEntryPointRVA = OptHdr.AddressOfEntryPoint;
		m_DllCharacteristics = OptHdr.DllCharacteristics;

		for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			m_Directories.push_back(_NtHeaders->OptionalHeader.DataDirectory[i]);
		}

		// Section headers follow directly after NtHeaders
		pSectionHeaders = MakePointer<PIMAGE_SECTION_HEADER>(_NtHeaders, sizeof(*_NtHeaders));
	};

	// Load headers depending on 32-bit or 64-bit
	if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		m_Is64 = TRUE;
		ParseHeaderFields(NtHeaders);
	}
	else if(NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		auto NtHeaders32 = MakePointer<PIMAGE_NT_HEADERS32>(NtHeaders);
		m_Is64 = FALSE;
		ParseHeaderFields(NtHeaders32);
	}
	else
	{
		ThrowLdrError("Invalid OptionalHeader.Magic signature");
	}

	// Determine if it's an EXE or DLL
	m_IsExe = !(NtHeaders->FileHeader.Characteristics == IMAGE_FILE_DLL);

	// For relocations
	m_Characteristics = NtHeaders->FileHeader.Characteristics;

	// NOTE: No IL loading

	// Copy over memory map sections into vector
	auto numSections = NtHeaders->FileHeader.NumberOfSections;
	m_MemSections.reserve(numSections);

	for (size_t i = 0; i < numSections; i++, pSectionHeaders++)
	{
		if (pSectionHeaders >= m_FileMemoryEnd) ThrowLdrError("Sections extend past end of file");
		m_MemSections.push_back(*pSectionHeaders);
	}
}
