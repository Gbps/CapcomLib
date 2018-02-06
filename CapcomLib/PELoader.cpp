#include "stdafx.h"
#include "Helpers.h"
#include "PELoader.h"

using namespace std;


PELoader::PELoader(const std::wstring& Filename)
{
	LoadFromFile(Filename);
}

PELoader::PELoader(SIZE_T ImageBase)
{
	m_InMemoryBase = reinterpret_cast<PBYTE>(ImageBase);
}

PELoader::~PELoader()
{
}

VOID PELoader::LoadFromFile(const wstring& Filename)
{
	unique_ptr<vector<char>> buf;
	ifstream fstr;
	
	// Enable exceptions on i/o error
	fstr.exceptions(ifstream::failbit | ifstream::badbit);
	try
	{
		// Open with binary with the cursor at the end (ATE) of the file
		fstr.open(Filename, ios::binary | ios::ate);

		// Determine how far the stream cursor is (this is the filesize since we started at the end!)
		auto pos = fstr.tellg();

		// Allocate vector<char> for the file contents
		buf = make_unique<vector<char>>(pos);

		// Seek to beginning and read the entire file
		fstr.seekg(0, ios::beg);
		fstr.read((*buf).data(), pos);
		fstr.close();
	}
	catch (const ifstream::failure& e)
	{
		UNREFERENCED_PARAMETER(e);
		ThrowLdrError("Failed to read file '%ls': %s", Filename.c_str(), stdstrerror(errno).c_str());
	}

	// Everything is good, change ownership of the file memory to the PELoader object
	m_Image = move(buf);
}

VOID PELoader::CheckValidBase()
{
	if (!GetPEBase())
	{
		ThrowLdrError("Invalid Base Address: %p. Did you load the module yet?\n", m_InMemoryBase);
	}
}

PVOID PELoader::GetPEBase()
{
	// If the module was loaded from a file, its contents will be in m_Image
	if (m_Image)
	{
		return m_Image.get()->data();
	}
	else if (m_InMemoryBase)
	{
		return m_InMemoryBase;
	}
	else
	{
		return nullptr;
	}
}

PIMAGE_NT_HEADERS PELoader::GetNTHeaders()
{
	// Ensure valid base address (i.e. module has been loaded into memory)
	CheckValidBase();

	// DOS headers are at the very beginning of the PE file. Check signature!
	auto DosHeader = MakePointer<PIMAGE_DOS_HEADER>(GetPEBase());
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

