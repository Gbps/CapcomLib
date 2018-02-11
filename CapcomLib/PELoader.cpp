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

	// Do relocations if necessary
	DoRelocateImage();

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

auto PELoader::ProcessRelocationBlocks(PWORD BlocksAddress, PULONG RelocBaseAddress, SIZE_T RelocDelta, SIZE_T Count)
{
	auto CurrentBlock = BlocksAddress;
	for (SIZE_T i = 0; i < Count; i++)
	{
		// 4-bits Type, 12-bits Offset
		auto OffsetType = *CurrentBlock;

		// Offset from the RelocBaseAddress to apply Delta
		auto Offset = OffsetType & 0xFFF;

		// Relocation Type
		auto Type = OffsetType >> 12;

		// Target to apply the relocation
		auto RealTargetShortPtr = MakePointer<PSHORT>(RelocBaseAddress, Offset);
		auto RealTargetLongPtr = MakePointer<PULONG>(RealTargetShortPtr);
		auto RealTargetLongLongPtr = MakePointer<PULONGLONG>(RealTargetShortPtr);

		// From ReactOS (Just want to make sure I get this exactly right)
		switch (Type)
		{
		case IMAGE_REL_BASED_ABSOLUTE:
			break;

		case IMAGE_REL_BASED_HIGH:
			*RealTargetShortPtr = HIWORD(MAKELONG(0, *RealTargetShortPtr) + (RelocDelta & 0xFFFFFFFF));
			break;

		case IMAGE_REL_BASED_LOW:
			*RealTargetShortPtr = *RealTargetShortPtr + LOWORD(RelocDelta & 0xFFFF);
			break;

		case IMAGE_REL_BASED_HIGHLOW:
			*RealTargetLongPtr = *RealTargetLongPtr + (RelocDelta & 0xFFFFFFFF);
			break;

		case IMAGE_REL_BASED_DIR64:
			*RealTargetLongLongPtr = *RealTargetLongLongPtr + RelocDelta;
			break;

		default:
			ThrowLdrError("Given relocation type was not supported (0x%llX)", Type);
			break;
		}

		// Go to the next block
		CurrentBlock++;
	}
	return (PIMAGE_BASE_RELOCATION)CurrentBlock;
}

VOID PELoader::DoRelocateImage()
{
	auto BaseAddress = GetMappedBase<PBYTE>();
	if (m_PE->HasFileCharacteristic(IMAGE_FILE_RELOCS_STRIPPED))
	{
		// File does not have relocations
		return;
	}
	else
	{
		const auto& RelocDDir = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_BASERELOC);

		if (RelocDDir.VirtualAddress == 0 || RelocDDir.Size == 0)
		{
			ThrowLdrError("Relocation data directory VA/Size was 0! VA=%p, Size=%p", 
				RelocDDir.VirtualAddress, RelocDDir.Size);
		}

		// The Delta to add to each relocation entry address to relocate
		auto RelocDelta = MakePointer<LONGLONG>(BaseAddress - m_PE->GetImageBase());

		// Sanity check. Relocations do not have to be applied.
		if (RelocDelta == 0)
		{
			return;
		}

		auto RelocDir = MakePointer<PIMAGE_BASE_RELOCATION>(BaseAddress, RelocDDir.VirtualAddress);
		auto RelocEnd = MakePointer<PIMAGE_BASE_RELOCATION>(RelocDir, RelocDDir.Size);

		if (RelocDir >= RelocEnd)
		{
			ThrowLdrError("Base relocation entry table was 0 or negative size!");
		}

		// Iterate through each base directory, then fix each block list inside the base directory
		// NtHeadersDirectory -> PIMAGE_BASE_RELOCATION[] -> Blocks[]

		while (RelocDir < RelocEnd && RelocDir->SizeOfBlock > 0)
		{
			// Number of relocations in this IMAGE_BASE_RELOCATION
			auto Count = (RelocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

			// Address to offset from for the relocation blocks
			auto Address = MakePointer<PULONG>(BaseAddress, RelocDir->VirtualAddress);

			// Address of the Blocks which contain the Type|Address bitfields
			auto BlocksAddress = MakePointer<PWORD>(RelocDir, sizeof(IMAGE_BASE_RELOCATION));

			// Process each entry in the block
			RelocDir = ProcessRelocationBlocks(BlocksAddress, Address, RelocDelta, Count);
		}
	}

	return;
}
