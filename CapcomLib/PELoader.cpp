#include "stdafx.h"
#include "Helpers.h"
#include "PELoader.h"
#include "Helpers.h"
#include "ExceptionHelpers.h"

using namespace std;

#pragma comment(lib,"ntdll.lib")

// Other modules loaded and mapped for the linking process only
std::unordered_map<std::string, std::shared_ptr<PEImage>> PEImage::MappedModules;

// Modules of the current system when the linking process begins
modules_map PEImage::KernelModules;

PEImage::PEImage(const std::wstring& Filename)
{
	m_PE = make_unique<PEFile>(Filename);
}

PEImage::PEImage(unique_ptr<PEFile> LoadedFile)
{
	m_PE = move(LoadedFile);
}

PEImage::~PEImage()
{
}

HMODULE PEImage::MapForKernel()
{
	return MapFlat(TRUE, FALSE, FALSE);
}

VOID PEImage::_MapSafeCopy(PBYTE TargetVA, PBYTE SourceVA, SIZE_T Size)
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

void PEImage::GetSystemModules()
{
	if (PEImage::KernelModules.size() > 0)
	{
		// Don't update more than once
		return;
	}

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

	PEImage::KernelModules.reserve(ModuleInfo->NumberOfModules);

	for (auto i = 0ULL; i < ModuleInfo->NumberOfModules; i++)
	{
		// Get just the file ImportName of each module
		auto mod = ModuleInfo->Modules[i];
		auto fullName = mod.FullPathName;
		auto name = mod.FullPathName + mod.OffsetToFileName;

		auto strName = string{ name };
		std::transform(strName.begin(), strName.end(), strName.begin(), [](UCHAR c) { return ::tolower(c); });

		// Add it by value to the vector
		PEImage::KernelModules[name] = ModuleInfo->Modules[i];
	}
}

shared_ptr<PEImage> PEImage::FindOrMapKernelDependency(string ModuleName)
{
	// Lowercase name
	std::transform(ModuleName.begin(), ModuleName.end(), ModuleName.begin(), [](UCHAR c) { return ::tolower(c); });

	// If it's been loaded already, use that one.
	auto LoadedMod = PEImage::MappedModules.find(ModuleName);
	if (LoadedMod != PEImage::MappedModules.end())
	{
		Util::DebugPrint("[CACHED]\n");
		return shared_ptr<PEImage>(LoadedMod->second);
	}

	// Find the modules from NTQSI output
	auto SysMod = PEImage::KernelModules.find(ModuleName);
	if (SysMod == PEImage::KernelModules.end())
	{
		ThrowLdrError("Driver attempted to import from an unloaded kernel module '%s'. "
			"Loading kernel imports at runtime is not supported!",
			ModuleName.c_str());
	}

	// If there's not already a loaded module, find and load the module from the kernel that will resolve the link

	// This is ugly as hell right here.
	// NTQSI will return NT namespaces '\SystemRoot\system32\ntoskrnl.exe'
	// We convert that to wide character -> L'\SystemRoot\system32\ntoskrnl.exe'
	// Then we use internal APIs to convert this to a DOS name -> '\\?\C:\Windows\System32\ntoskrnl.exe'
	// Then convert to wide character -> L'\\?\C:\Windows\System32\ntoskrnl.exe'
	auto SysModule = SysMod->second;
	auto FullNameNative = SysModule.FullPathName;
	auto wFullNameNative = multi2wide(FullNameNative);

	auto FullNameNtPath = NtNativeToWin32(wFullNameNative);
	if (FullNameNtPath.length() == 0)
	{
		ThrowLdrError("Failed to get full path for '%s'", FullNameNative);
	}

	auto wFullName = multi2wide(FullNameNtPath);

	// Load PE from disk
	auto ModulePE = make_shared<PEImage>( wFullName );

	// Map the module flat
	// loaderBase = SysModule.ImageBase -- Our module is actually mapped in the kernel, so when we resolve exports
	//                                     we want to resolve to the kernel address, not our locally mapped one
	auto res = ModulePE->MapFlat(TRUE, SysModule.ImageBase, TRUE);

	Util::DebugPrint("[MAPPED %p => %p]\n", SysModule.ImageBase, res);

	return ModulePE;
}

SIZE_T PEImage::FindImport(
	std::string ImportName,
	int Ordinal)
{
	std::transform(ImportName.begin(), ImportName.end(), ImportName.begin(), [](UCHAR c) { return ::tolower(c); });

	// Load exports
	const auto& exports = GetExports();

	// Import by name
	if (Ordinal == -1)
	{
		// Find an export name that matches the import
		auto findExport = exports.find(ImportName);
		if (findExport != exports.end())
		{
			// Return pointer offset from the image loaded in kernel already
			return findExport->second.Address;
		}
		else
		{
			// Could not find import
			return NULL;
		}
	}
	// Import by ordinal
	else
	{
		auto findExport = find_if(exports.begin(), exports.end(), [&Ordinal](const auto& e) { return e.second.Ordinal == Ordinal; });
		if (findExport != exports.end())
		{
			// Return pointer offset from the image loaded in kernel already
			return findExport->second.Address;
		}
		else
		{
			// Could not find import
			return NULL;
		}
	}
	return NULL;
}

const exports_hashmap& PEImage::GetExports()
{
	// Already resolved
	if (m_Exports.size() > 0)
	{
		return m_Exports;
	}

	const auto& ExportDDir = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);

	// No exports
	if (ExportDDir.VirtualAddress == 0 || ExportDDir.Size == 0)
	{
		return m_Exports;
	}

	auto ExportDir = FromRVA<PIMAGE_EXPORT_DIRECTORY>(ExportDDir.VirtualAddress);

	// List of function addresses accessed by ordinal
	auto FuncList = FromRVA<DWORD*>(ExportDir->AddressOfFunctions);

	// List of function names accessed top down
	auto NameList = FromRVA<DWORD*>(ExportDir->AddressOfNames);

	// List of ordinals accessed top down
	auto NameOrdinalList = FromRVA<WORD*>(ExportDir->AddressOfNameOrdinals);

	// Clear old entries if they exist
	m_Exports.clear();

	// Pre-allocate memory
	m_Exports.reserve(ExportDir->NumberOfFunctions);

	// Number of export by ordinal only
	WORD i = 0;
	for (; i < (ExportDir->NumberOfFunctions - ExportDir->NumberOfNames); i++)
	{
		auto func = FuncList[i];

		// Extreme hack to make a valid std::string that won't interfere with the other strings
		// C++11 wew
		auto temp = std::string{ 2 };
		*(WORD*)(&temp[0]) = i;

		auto funcAddr = (SIZE_T)((SIZE_T)GetActualBase() + func);
		auto ordinal = i;
		auto entry = PEFileExport{ funcAddr, ordinal };

		m_Exports.emplace(make_pair(temp, entry));
	}

	WORD ordinalBase = i+1;

	// For each export, store address of function and ordinal
	for (i = 0; i < ExportDir->NumberOfNames; i++)
	{
		auto name = string{ FromRVA<const char*>(NameList[i]) };
		auto nameOrdinal = NameOrdinalList[i];
		auto func = FuncList[nameOrdinal];

		// Lowercase string
		std::transform(name.begin(), name.end(), name.begin(), [](UCHAR c) { return ::tolower(c); });
		
		// Use actual base, if mapping externally.
		// Otherwise, use our local mapped base.

		auto funcAddr = (SIZE_T)((SIZE_T)GetActualBase() + func);
		auto ordinal = (WORD)(ordinalBase + i);
		auto entry = PEFileExport{ funcAddr, ordinal };

		m_Exports.emplace(make_pair(name, entry));
	}

	return m_Exports;
}

void PEImage::LinkImage(BOOL IsKernel)
{
	// Update the kernel modules list if necessary
	if (IsKernel)
	{
		GetSystemModules();
	}

	const auto& ImportDDir = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_IMPORT);

	// First entry in import descriptor table
	auto CurImportEntry = MakePointer<PIMAGE_IMPORT_DESCRIPTOR>(GetMappedBase<>(), ImportDDir.VirtualAddress);

	// Go through each entry until Name is NULL (the all-null entry that acts as the terminator)
	for (; CurImportEntry->Name; CurImportEntry++)
	{
		// Name of the module to import from ex. 'ntoskrnl.exe'
		auto ModuleName = FromRVA<char*>(CurImportEntry->Name);

		shared_ptr<PEImage> TargetModule;
		if (IsKernel)
		{
			Util::DebugPrint("Import from %s... ", ModuleName);
			TargetModule = FindOrMapKernelDependency(ModuleName);
		}
		else
		{
			throw exception("Not implemented");
		}

		// The address of the table of thunks containing the IAT entry to place the resolved function once when we get it
		auto IATThunk = FromRVA<IMAGE_THUNK_DATA*>(CurImportEntry->FirstThunk);

		// The address of the table of Name/Ordinal thunks. 
		// If it's import by ordinal, the ordinal will be there.
		// If it's import by ImportName, a pointer to the ImportName will be there.
		auto NameThunk = FromRVA<IMAGE_THUNK_DATA*>(CurImportEntry->OriginalFirstThunk);

		if (CurImportEntry->OriginalFirstThunk == 0)
		{
			// No separate ImportName table
			NameThunk = IATThunk;
		}

		// Loop through both tables until null terminated
		while (NameThunk->u1.AddressOfData)
		{
			auto ordinal = -1;
			auto isOrdinalImport = NameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG;
			const char* ImportName;

			if (isOrdinalImport)
			{
				// Import by ordinal
				ordinal = NameThunk->u1.Ordinal & 0xFFFF;
			}
			else
			{
				// Import by ImportName
				ImportName = FromRVA<IMAGE_IMPORT_BY_NAME*>(NameThunk->u1.AddressOfData)->Name;
			}

			if (IsKernel)
			{
				auto addr = TargetModule->FindImport(ImportName, ordinal);
				if (!addr)
				{
					ThrowLdrError("Could not find import ('%s', %i) for module", ImportName, ordinal);
				}
				
				// IAT
				IATThunk->u1.Function = (SIZE_T)addr;

				Util::DebugPrint("\t%s => Addr: 0x%I64X, IAT: %p\n", ImportName, addr - (SIZE_T)TargetModule->GetActualBase(), &IATThunk->u1.Function);
			}
			else
			{
				throw exception("Not implemented");
			}

			if (NameThunk == IATThunk)
			{
				NameThunk++;
			}
			else
			{
				NameThunk++;
				IATThunk++;
			}
		}

	}
}

HMODULE PEImage::MapFlat(BOOL isForKernel, PVOID loaderBase, BOOL loadAsDataFile)
{
	// Ensure we've allocated space for the entire image
	AllocFlat();

	auto HeadersBase = m_PE->GetHeadersBase();
	auto HeadersSize = m_PE->GetHeadersSize();

	// Copy PE headers
	_MapSafeCopy(GetMappedBase<PBYTE>(), MakePointer<PBYTE>(HeadersBase), HeadersSize);

	// Copy each section into its preferred location
	// NOTE: Does not check for overlapping sections
	// When mapping flat, unfilled space between sections will be filled with 00s
	const auto& memSections = m_PE->GetSections();
	for (const auto& sec : memSections)
	{
		auto secData = m_PE->FromOffset<PBYTE>(sec.PointerToRawData);
		auto targetVA = FromRVA<PBYTE>(sec.VirtualAddress);

		_MapSafeCopy(targetVA, secData, sec.SizeOfRawData);
	}

	// Do relocations if necessary
	DoRelocateImage();

	// If there's a custom loader base, set it here
	// Useful if the module is preparing to be mapped elsewhere, like the kernel
	if (loaderBase)
	{
		m_ActualBaseAddress = loaderBase;
	}

	// Rescursively resolves imports when not loaded as a data file
	if (!loadAsDataFile)
	{
		LinkImage(isForKernel);
	}

	return GetMappedBase<HMODULE>();
}


VOID PEImage::AllocFlat()
{
	if (m_Mem) return;

	auto totalSize = m_PE->GetTotalMappedSize();

	auto alloc = unique_virtalloc<>
	{
		VirtualAllocEx(GetCurrentProcess(), NULL, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
	};
	if(!alloc) ThrowLdrLastError(L"VirtualAllocEx");

	m_Mem = move(alloc);
	m_MemSize = totalSize;

	// Can be overwritten later, in the case of kernel exports
	m_ActualBaseAddress = m_Mem.get();
}

auto PEImage::ProcessRelocationBlocks(PWORD BlocksAddress, PULONG RelocBaseAddress, SIZE_T RelocDelta, SIZE_T Count)
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

VOID PEImage::DoRelocateImage()
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
			// No relocations
			return;
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
