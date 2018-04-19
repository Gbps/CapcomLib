#pragma once

#include "stdafx.h"
#include "Winternl.h"
#include "Util.h"

namespace Util
{
	namespace Win32
	{
		// Auto deleter for C++ smart pointers for Win32 Handles
		struct Win32HandleDeleter
		{
			void operator()(HANDLE handle)
			{
				if (handle != nullptr)
				{
					::CloseHandle(handle);
				}
			}
		};

		// C++ Smart Pointer for Win32 Handles
		using unique_handle = std::unique_ptr<void, Win32HandleDeleter>;

		// Auto deleter for C++ smart pointers for Win32 LoadLibrary
		struct Win32ModuleDeleter
		{
			void operator()(void* handle)
			{
				if (handle != nullptr)
				{
					::FreeLibrary((HMODULE)handle);
				}
			}
		};

		// C++ Smart Pointer for Win32 Handles
		using unique_module = std::unique_ptr<void, Win32ModuleDeleter>;

		// Auto deleter for C++ smart pointers for VirtualAlloc memory
		struct VirtualFreeDeleter
		{
			void operator()(LPVOID mem)
			{
				if (mem != nullptr)
				{
					auto ret = ::VirtualFree(mem, 0, MEM_RELEASE);

					// Should this throw an exception?
					if (!ret) Util::Exception::ThrowLastError("VirtualFree");
				}
			}
		};

		// C++ Smart Pointer for VirtualAlloc memory
		template<typename PtrType = VOID>
		using unique_virtalloc = std::unique_ptr<PtrType, VirtualFreeDeleter>;

		// Creates an ownership-managed object that creates a UNICODE_STRING from a wstring
		template <class StrClass>
		class UnicodeStringWrapper : public UNICODE_STRING
		{
		public:
			StrClass innerStr;

			UnicodeStringWrapper(const StrClass& _innerStr)
			{
				innerStr = _innerStr;
				::RtlInitUnicodeString(this, innerStr.c_str());
			}
		};

		// Converts a native Nt path into a win32 DOS path
		// Uses internal NtCreateFile to get the file handle for the native path
		// Then uses API function GetFinalPathNameByHandle to get the DOS path
		inline std::string NtNativeToWin32(const std::wstring& NtNativePath)
		{
			DWORD dwRet;
			OBJECT_ATTRIBUTES  objAttr;
			HANDLE handle;
			IO_STATUS_BLOCK    ioStatusBlock = { 0 };

			auto Path = std::string{};
			Path.resize(MAX_PATH);
			auto uniNativePath = UnicodeStringWrapper<std::wstring>{ NtNativePath };

			InitializeObjectAttributes(&objAttr, (PUNICODE_STRING)&uniNativePath,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL, NULL);

			auto ntstatus = NtCreateFile(&handle,
				GENERIC_READ,
				&objAttr,
				&ioStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_NON_DIRECTORY_FILE,
				NULL,
				0);

			if (!NT_SUCCESS(ntstatus))
			{
				return Path;
			}

			dwRet = GetFinalPathNameByHandleA(handle, &Path[0], MAX_PATH, VOLUME_NAME_DOS);
			CloseHandle(handle);
			return Path;
		}
	}
}
