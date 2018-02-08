#include "stdafx.h"
#include "Helpers.h"
#include "PELoader.h"
#include "Helpers.h"
#include "ExceptionHelpers.h"

using namespace std;


PELoader::PELoader(const std::wstring& Filename)
{
	m_PE = make_unique<PEFile>(Filename);
}

PELoader::PELoader(unique_ptr<PEFile> LoadedFile)
{
	m_PE = move(LoadedFile);
}

PELoader::~PELoader()
{
}

VOID PELoader::_MapSafeCopy(PBYTE TargetVA, PBYTE SourceVA, SIZE_T Size)
{
	auto targetEnd = TargetVA + Size;

	if (TargetVA > GetMappedEnd<PBYTE>() || TargetVA < GetMappedBase<PBYTE>())
	{
		ThrowLdrError("TargetVA is outside mapped section!");
	}

	if (targetEnd > GetMappedEnd<PBYTE>() || targetEnd < TargetVA)
	{
		ThrowLdrError("SourceVA is outside of mapped section!");
	}

	RtlCopyMemory(TargetVA, SourceVA, Size);
}

HMODULE PELoader::MapFlat(DWORD flProtect, BOOL shouldCopyHeaders)
{
	// Ensure we've allocated space for the entire image
	AllocFlat(flProtect);

	if (shouldCopyHeaders)
	{
		// Copy the section headers
		auto HeadersBase = m_PE->GetHeadersBase();
		auto HeadersSize = m_PE->GetHeadersSize();

		_MapSafeCopy(GetMappedBase<PBYTE>(), MakePointer<PBYTE>(HeadersBase), HeadersSize);
	}

	// Copy each section into its preferred location
	// NOTE: Does not check for overlapping sections
	auto memSections = m_PE->GetSections();
	for (const auto& sec : memSections)
	{
		auto secData = m_PE->OffsetFromBase<PBYTE>(sec.PointerToRawData);
		auto targetVA = OffsetFromMappedBase<PBYTE>(sec.VirtualAddress);

		_MapSafeCopy(targetVA, secData, sec.SizeOfRawData);
	}

	return GetMappedBase<HMODULE>();
}

VOID PELoader::AllocFlat(DWORD flProtect)
{
	if (m_Mem) return;

	auto totalSize = m_PE->GetTotalMappedSize();

	auto alloc = unique_virtalloc
	{
		VirtualAllocEx(GetCurrentProcess(), NULL, totalSize, MEM_RESERVE | MEM_COMMIT, flProtect)
	};
	if(!alloc) ThrowLdrLastError(L"VirtualAllocEx");

	m_Mem = move(alloc);
	m_MemSize = totalSize;
}

//
//VOID PELoader::DoRelocateImage()
//{
//	auto BaseAddress = GetLoadedBase();
//	if (!HasNtHeaderFlag(IMAGE_FILE_RELOCS_STRIPPED))
//	{
//		// No relocation information in the PE file
//		// That means that we can load it into any base without fixups
//		return;
//	}
//	else
//	{
//		// Must iterate through relocations in PE and fix addresses
//
//		// Relocation data directory section
//		auto RelocDDir = GetPEDataDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC);
//		
//		if (RelocDDir->VirtualAddress == 0 || RelocDDir->Size == 0)
//		{
//			ThrowLdrError("Relocation data directory VA/Size was 0! VA=%p, Size=%p", 
//				RelocDDir->VirtualAddress, RelocDDir->Size);
//		}
//		auto ImageBase = GetPEImageBase();
//		//auto RelocDelta = MakePointer<ULONG_PTR>(BaseAddress, -ImageBase);
//		auto RelocDir = MakePointer<PIMAGE_BASE_RELOCATION>(BaseAddress, RelocDDir->VirtualAddress);
//		auto RelocEnd = MakePointer<PIMAGE_BASE_RELOCATION>(RelocDir, RelocDDir->Size);
//
//		if (RelocDir >= RelocEnd)
//		{
//			ThrowLdrError("Base relocation entry table was 0 or negative size!");
//		}
//	}
//	return;
//}