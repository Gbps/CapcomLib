#include "stdafx.h"
#include "Util.h"
#include "PELoader.h"
#include "Util.h"

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

VOID PEImage::GenerateSecurityCookie()
{
	const auto& LoadConfigDD = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	if (LoadConfigDD.VirtualAddress == 0 || LoadConfigDD.Size == 0)
	{
		// No load options
		return;
	}

	auto LoadConfigDir = FromRVA<PIMAGE_LOAD_CONFIG_DIRECTORY>(LoadConfigDD.VirtualAddress);

	if (!LoadConfigDir->SecurityCookie)
	{
		// No security cookie
		return;
	}

	// This actually gets relocated... interesting.
	auto SecurityCookie = MakePointer<PSIZE_T>(LoadConfigDir->SecurityCookie);

	// Do we really care about generating the correct 'secure' cookie here? I'm going to say 'no'.
	auto RandomCookie = Util::Random::Generate64();

	*SecurityCookie = RandomCookie;
}

VOID PEImage::_MapSafeCopy(PBYTE TargetVA, PBYTE SourceVA, SIZE_T Size)
{
	auto targetEnd = TargetVA + Size;

	if (TargetVA > GetMappedEnd<PBYTE>() || TargetVA < GetMappedBase<PBYTE>())
	{
		Util::Exception::Throw("TargetVA is outside mapped section!");
	}

	if (targetEnd > GetMappedEnd<PBYTE>() || targetEnd < TargetVA)
	{
		Util::Exception::Throw("SourceVA is outside of mapped section!");
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
	auto ModuleInfo = Util::Win32::unique_virtalloc<_RTL_PROCESS_MODULES>
	{
		reinterpret_cast<PRTL_PROCESS_MODULES>
		(
			VirtualAlloc(NULL, initialSize, MEM_COMMIT, PAGE_READWRITE)
		)
	};

	if (!ModuleInfo) Util::Exception::ThrowLastError(L"VirtualAlloc");

	auto res = NtQuerySystemInformation(SystemModuleInformation, ModuleInfo.get(), initialSize, &actualSize);
	if (res == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Release old ModuleInfo and allocate one with actual size
		ModuleInfo = Util::Win32::unique_virtalloc<_RTL_PROCESS_MODULES>
		{
			reinterpret_cast<PRTL_PROCESS_MODULES>
			(
				VirtualAlloc(NULL, actualSize, MEM_COMMIT, PAGE_READWRITE)
			)
		};
		if (!ModuleInfo) Util::Exception::ThrowLastError(L"VirtualAlloc");

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
		Util::String::ToLower(strName);
	
		// Add it by value to the vector
		PEImage::KernelModules[name] = ModuleInfo->Modules[i];
	}
}

shared_ptr<PEImage> PEImage::FindOrMapKernelDependency(string ModuleName)
{
	//keep uppercase name for find() method in unordered map
	auto ModuleNameCorrect = ModuleName;
	// Lowercase name
	Util::String::ToLower(ModuleName);

	// If it's been loaded already, use that one.
	auto LoadedMod = PEImage::MappedModules.find(ModuleName);
	if (LoadedMod != PEImage::MappedModules.end())
	{
		Util::Debug::Print("[CACHED]\n");
		return shared_ptr<PEImage>(LoadedMod->second);
	}

	// Find the modules from NTQSI output
	auto SysMod = PEImage::KernelModules.find(ModuleNameCorrect);
	if (SysMod == PEImage::KernelModules.end())
	{
		Util::Exception::Throw("Driver attempted to import from an unloaded kernel module '%s'. "
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
	auto wFullNameNative = Util::String::ToUnicode(FullNameNative);

	auto FullNameNtPath = Util::Win32::NtNativeToWin32(wFullNameNative);
	if (FullNameNtPath.length() == 0)
	{
		Util::Exception::Throw("Failed to get full path for '%s'", FullNameNative);
	}

	auto wFullName = Util::String::ToUnicode(FullNameNtPath);

	// Load PE from disk
	auto ModulePE = make_shared<PEImage>( wFullName );

	// Map the module flat
	// loaderBase = SysModule.ImageBase -- Our module is actually mapped in the kernel, so when we resolve exports
	//                                     we want to resolve to the kernel address, not our locally mapped one
	auto res = ModulePE->MapFlat(TRUE, SysModule.ImageBase, TRUE);

	Util::Debug::Print("[MAPPED %p => %p]\n", SysModule.ImageBase, res);

	return ModulePE;
}

PVOID PEImage::FindImport(
	const char* ImportName,
	int Ordinal)
{
	// Import by name
	if (Ordinal == -1)
	{
		return GetExportByName(ImportName);
	}
	// Import by ordinal
	else
	{
		return GetExportByOrdinal(Ordinal);
	}
}

PVOID PEImage::GetExportByName(const char* ImportName)
{
	const auto& ExportDDir = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);

	// No exports
	if (ExportDDir.VirtualAddress == 0 || ExportDDir.Size == 0)
	{
		return NULL;
	}

	auto ExportDir = FromRVA<PIMAGE_EXPORT_DIRECTORY>(ExportDDir.VirtualAddress);

	// List of function addresses accessed by ordinal
	auto FuncList = FromRVA<DWORD*>(ExportDir->AddressOfFunctions);

	// List of function names accessed top down
	auto NameList = FromRVA<DWORD*>(ExportDir->AddressOfNames);

	// List of ordinals accessed top down
	auto NameOrdinalList = FromRVA<WORD*>(ExportDir->AddressOfNameOrdinals);

	DWORD Low = 0, Mid = 0;

	DWORD High = ExportDir->NumberOfNames - 1;

	// Binary search over names
	while(High >= Low)
	{
		Mid = (Low + High) / 2;

		auto name = FromRVA<const char*>(NameList[Mid]);

		// Compare import name
		auto cmp = strcmp(ImportName, name);
		if (cmp < 0)
		{
			High = Mid - 1;
		}
		else if (cmp > 0)
		{
			Low = Mid + 1;
		}
		else
		{
			break;
		}
	}

	// Was it found?
	if (High < Low) return NULL;

	auto nameOrdinal = NameOrdinalList[Mid];

	// Validate ordinal
	if (nameOrdinal >= ExportDir->NumberOfFunctions) return NULL;

	auto func = FuncList[nameOrdinal];

	// Use actual base, if mapping externally.
	// Otherwise, use our local mapped base.
	auto OutputAddress = (SIZE_T)((SIZE_T)GetActualBase() + func);

	return (PVOID)OutputAddress;
}

PVOID PEImage::GetExportByOrdinal(WORD InputOrdinal)
{
	const auto& ExportDDir = m_PE->GetDirectoryEntry(IMAGE_DIRECTORY_ENTRY_EXPORT);

	// No exports
	if (ExportDDir.VirtualAddress == 0 || ExportDDir.Size == 0)
	{
		return NULL;
	}

	auto ExportDir = FromRVA<PIMAGE_EXPORT_DIRECTORY>(ExportDDir.VirtualAddress);

	// List of function addresses accessed by ordinal
	auto FuncList = FromRVA<DWORD*>(ExportDir->AddressOfFunctions);

	// Function address of 
	SIZE_T OutputAddress = 0;

	auto targetOrd = InputOrdinal - ExportDir->Base;

	if (targetOrd >= ExportDir->NumberOfFunctions)
	{
		Util::Exception::Throw("Import by ordinal exceeds number of functions");
	}

	// Ordinal goes directly into func list
	auto func = FuncList[targetOrd];

	// Use actual base, if mapping externally.
	// Otherwise, use our local mapped base.
	OutputAddress = (SIZE_T)((SIZE_T)GetActualBase() + func);
	
	return (PVOID)OutputAddress;
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
			Util::Debug::Print("Import from %s... ", ModuleName);
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

			auto addr = (SIZE_T)TargetModule->FindImport(ImportName, ordinal);
			if (!addr)
			{
				Util::Exception::Throw("Could not find import ('%s', %i) for module", ImportName, ordinal);
			}
				
			// IAT
			IATThunk->u1.Function = (SIZE_T)addr;

			Util::Debug::Print("\t%s => Addr: 0x%I64X, IAT: %p\n", ImportName, addr - (SIZE_T)TargetModule->GetActualBase(), &IATThunk->u1.Function);

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
		// Resolve imports, load dependencies, etc.
		LinkImage(isForKernel);

		// Required for some images
		GenerateSecurityCookie();
	}

	return GetMappedBase<HMODULE>();
}


VOID PEImage::AllocFlat()
{
	if (m_Mem) return;

	auto totalSize = m_PE->GetTotalMappedSize();

	auto alloc = Util::Win32::unique_virtalloc<>
	{
		VirtualAllocEx(GetCurrentProcess(), NULL, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
	};
	if(!alloc) Util::Exception::ThrowLastError(L"VirtualAllocEx");

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
			Util::Exception::Throw("Given relocation type was not supported (0x%llX)", Type);
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
			Util::Exception::Throw("Base relocation entry table was 0 or negative size!");
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
