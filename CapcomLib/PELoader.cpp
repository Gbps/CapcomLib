#include "stdafx.h"
#include "Helpers.h"
#include "PELoader.h"
#include "Helpers.h"
#include "ExceptionHelpers.h"
#include "Win32Kernel.h"

using namespace std;

#pragma comment(lib,"ntdll.lib")

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

auto PELoader::GetSystemModules()
{
	// Try a size and then increase if necessary
	auto initialSize = 0x10000;
	auto actualSize = ULONG{};
	auto ModuleInfo = unique_virtalloc<_RTL_PROCESS_MODULES>
	{
		reinterpret_cast<PRTL_PROCESS_MODULES>
		(
			VirtualAlloc(NULL, initialSize, MEM_COMMIT, PAGE_READWRITE)
		)
	};

	if (!ModuleInfo) ThrowLdrLastError(L"VirtualAlloc");

	auto res = NtQuerySystemInformation(SystemModuleInformation, ModuleInfo.get(), initialSize, &actualSize);
	if (res == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Release old ModuleInfo and allocate one with actual size
		ModuleInfo = unique_virtalloc<_RTL_PROCESS_MODULES>
		{
			reinterpret_cast<PRTL_PROCESS_MODULES>
			(
				VirtualAlloc(NULL, actualSize, MEM_COMMIT, PAGE_READWRITE)
			)
		};
		if (!ModuleInfo) ThrowLdrLastError(L"VirtualAlloc");

		// Query again
		res = NtQuerySystemInformation(SystemModuleInformation, ModuleInfo.get(), initialSize, &actualSize);
	}

	auto outVec = vector<RTL_PROCESS_MODULE_INFORMATION>{};
	for (auto i = 0ULL; i < ModuleInfo->NumberOfModules; i++)
	{
		outVec.push_back(ModuleInfo->Modules[i]);
	}

	return outVec;
}

auto PELoader::DoImportResolve(BOOL IsDriver)
{
	auto ImageDDir = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (ImageDDir.Size == 0 || ImageDDir.VirtualAddress == 0)
	{
		// No imports... go figure
		return;
	}

	if (!IsDriver)
	{
		ThrowLdrError("Ring3 not supported yet!");
	}

	DoImportResolveKernel(ImageDDir);
}

PVOID PELoader::FindAndLoadKernelExport(const vector<RTL_PROCESS_MODULE_INFORMATION>& SysModules, 
	const char* ModuleName, 
	int Ordinal = -1,
	const char* ImportName = NULL)
{
	// TODO: Check if it's in the loaded module list

	for (const auto& mod : SysModules)
	{
		auto offFileName = mod.OffsetToFileName;
		auto fullName = mod.FullPathName;
		auto nameStr = fullName + offFileName;

		// If strings are equal
		/*auto handleBase = unique_module
		{
			LoadLibraryExA(fullName, NULL, LOAD_LIBRARY_AS_DATAFILE)
		};
		ThrowLdrLastError(L"LoadLibraryExA", handleBase.get());*/

	}
}

void PELoader::DoImportResolveKernel(IMAGE_DATA_DIRECTORY &ImageDDir)
{
	// First entry in import descriptor table
	auto CurImportEntry = MakePointer<PIMAGE_IMPORT_DESCRIPTOR>(GetMappedBase<>(), ImageDDir.VirtualAddress);

	// Use NtQuerySystemInformation to grab base addresses of necessary modules
	auto SysModules = GetSystemModules();

	// Go through each entry until Name is NULL (the all-null entry that acts as the terminator)
	// NOTE: 64-bit only
	for (; CurImportEntry->Name; CurImportEntry++)
	{
		// Name of the module to import from ex. 'ntoskrnl.exe'
		auto ModuleName = FromRVA<char*>(CurImportEntry->Name);

		// The address of the table of thunks containing the IAT entry to place the resolved function once when we get it
		auto IATThunk = FromRVA<IMAGE_THUNK_DATA*>(CurImportEntry->FirstThunk);

		// The address of the table of Name/Ordinal thunks. 
		// If it's import by ordinal, the ordinal will be there.
		// If it's import by name, a pointer to the name will be there.
		auto NameThunk = FromRVA<IMAGE_THUNK_DATA*>(CurImportEntry->OriginalFirstThunk);

		if (CurImportEntry->OriginalFirstThunk == 0)
		{
			// No separate name table
			NameThunk = IATThunk;
		}

		// Loop through both tables until null terminated
		while (NameThunk->u1.AddressOfData)
		{
			auto ordinal = -1;
			auto isOrdinalImport = NameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG;
			const char* name;

			if (isOrdinalImport)
			{
				// Import by ordinal
				ordinal = NameThunk->u1.Ordinal & 0xFFFF;
			}
			else
			{
				// Import by name
				name = FromRVA<IMAGE_IMPORT_BY_NAME*>(NameThunk->u1.AddressOfData)->Name;
			}

			if (NameThunk == IATThunk)
			{
				// Single table
				NameThunk++;
			}
			else
			{
				// Two tables
				NameThunk++;
				IATThunk++;
			}
		}

	}
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
		auto targetVA = FromRVA<PBYTE>(sec.VirtualAddress);

		_MapSafeCopy(targetVA, secData, sec.SizeOfRawData);
	}

	// Do relocations if necessary
	DoRelocateImage();

	// Resolves imports
	DoImportResolve(TRUE);

	return GetMappedBase<HMODULE>();
}

VOID PELoader::AllocFlat(DWORD flProtect)
{
	if (m_Mem) return;

	auto totalSize = m_PE->GetTotalMappedSize();

	auto alloc = unique_virtalloc<>
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
