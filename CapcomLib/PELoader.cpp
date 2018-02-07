#include "stdafx.h"
#include "Helpers.h"
#include "PELoader.h"
#include "Helpers.h"
#include "ExceptionHelpers.h"

using namespace std;


PELoader::PELoader(const std::wstring& Filename)
{
	DoLoadFromFile(Filename);
}

PELoader::PELoader(SIZE_T ImageBase)
{
	m_FileMemoryBase = reinterpret_cast<PBYTE>(ImageBase);
}

PELoader::~PELoader()
{
}
//
//VOID PELoader::DoLoadFromFile(const wstring& Filename)
//{
//	unique_ptr<vector<char>> buf;
//	ifstream fstr;
//	
//	// Enable exceptions on i/o error
//	fstr.exceptions(ifstream::failbit | ifstream::badbit);
//	try
//	{
//		// Open with binary with the cursor at the end (ATE) of the file
//		fstr.open(Filename, ios::binary | ios::ate);
//
//		// Determine how far the stream cursor is (this is the filesize since we started at the end!)
//		auto pos = fstr.tellg();
//
//		// Allocate vector<char> for the file contents
//		buf = make_unique<vector<char>>(pos);
//
//		// Seek to beginning and read the entire file
//		fstr.seekg(0, ios::beg);
//		fstr.read((*buf).data(), pos);
//		fstr.close();
//	}
//	catch (const ifstream::failure& e)
//	{
//		UNREFERENCED_PARAMETER(e);
//		ThrowLdrError("Failed to read file '%ls': %s", Filename.c_str(), stdstrerror(errno).c_str());
//	}
//
//	// Everything is good, change ownership of the file memory to the PELoader object
//	m_Image = move(buf);
//}

VOID PELoader::DoLoadFromFile(const wstring& Filename)
{
	// Open file readonly
	auto hFile = unique_handle
	{
		CreateFile(Filename.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, 0, NULL)
	};
	ThrowLdrLastErrorOnInvalidHandle(L"CreateFile", hFile.get());

	// Create the file mapping (NOTE: Doing this manually, not as SEC_IMAGE, requires moving the sections manually)
	auto hMap = unique_handle
	{
		CreateFileMapping(hFile.get(), NULL, PAGE_READONLY, 0, 0, NULL)
	};
	ThrowLdrLastErrorOnInvalidHandle(L"CreateFileMapping", hMap.get());

	// Create the view of the entire file
	auto PEFile = MapViewOfFile(hMap.get(), FILE_MAP_READ, 0, 0, 0);
	ThrowLdrLastErrorOnInvalidHandle(L"MapViewOfFile", PEFile);

	// Commit the handles
	m_FileHandle = move(hFile);
	m_FileMapping = move(hMap);
	m_FileMemoryBase = PEFile;
}

VOID PELoader::DoValidBaseCheck()
{
	if (!GetLoadedBase())
	{
		ThrowLdrError("Invalid Base Address: %p. Did you load the module yet?", m_FileMemoryBase);
	}
}

VOID PELoader::DoRelocateImage()
{
	auto BaseAddress = GetLoadedBase();
	if (!HasNtHeaderFlag(IMAGE_FILE_RELOCS_STRIPPED))
	{
		// No relocation information in the PE file
		// That means that we can load it into any base without fixups
		return;
	}
	else
	{
		// Must iterate through relocations in PE and fix addresses

		// Relocation data directory section
		auto RelocDDir = GetPEDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		
		if (RelocDDir->VirtualAddress == 0 || RelocDDir->Size == 0)
		{
			ThrowLdrError("Relocation data directory VA/Size was 0! VA=%p, Size=%p", 
				RelocDDir->VirtualAddress, RelocDDir->Size);
		}
		auto ImageBase = GetPEImageBase();
		//auto RelocDelta = MakePointer<ULONG_PTR>(BaseAddress, -ImageBase);
		auto RelocDir = MakePointer<PIMAGE_BASE_RELOCATION>(BaseAddress, RelocDDir->VirtualAddress);
		auto RelocEnd = MakePointer<PIMAGE_BASE_RELOCATION>(RelocDir, RelocDDir->Size);

		if (RelocDir >= RelocEnd)
		{
			ThrowLdrError("Base relocation entry table was 0 or negative size!");
		}
	}
	return;
}

BOOL PELoader::HasNtHeaderFlag(WORD Flag)
{
	return (GetNtHeaders()->FileHeader.Characteristics & Flag);
}

PVOID PELoader::GetLoadedBase()
{
	return m_FileMemoryBase;
}

PVOID PELoader::GetPEBase()
{
	if (!m_FileMemoryBase) ThrowLdrError("GetPEBase called with no PE file loaded!");
	return m_FileMemoryBase;
}

LONGLONG PELoader::GetPEImageBase()
{
	return GetNtHeaders()->OptionalHeader.ImageBase;
}

PIMAGE_DATA_DIRECTORY PELoader::GetPEDataDirectoryEntry(WORD DirectoryEnum)
{
	return &GetNtHeaders()->OptionalHeader.DataDirectory[DirectoryEnum];
}

PIMAGE_NT_HEADERS PELoader::GetNtHeaders()
{
	// Ensure valid base address (i.e. module has been loaded into memory)
	DoValidBaseCheck();

	// DOS headers are at the very beginning of the PE file. Check signature!
	auto DosHeader = MakePointer<PIMAGE_DOS_HEADER>(GetLoadedBase());
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		ThrowLdrError("Invalid image DOS signature!\n");
	}

	// DOS headers give offset to NT headers
	auto NtHeaderOffset = DosHeader->e_lfanew;

	// Grab NT headers and verify signature
	auto NtHeaders = MakePointer<PIMAGE_NT_HEADERS>(DosHeader, NtHeaderOffset);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		ThrowLdrError("Invalid image NT signature!\n");
	}

	return NtHeaders;
}

VOID PELoader::AllocManualMap()
{

}
