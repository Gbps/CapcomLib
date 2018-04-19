#pragma once
#include "stdafx.h"

// Prints a Win32 error and exits the console program
// https://github.com/iceb0y/ntdrvldr/blob/master/main.c
VOID PrintErrorAndExit(wchar_t *Function, ULONG dwErrorCode);

// Pointer type conversion with no offset
template<typename TargetType>
TargetType MakePointer(void* anyptr)
{
	return reinterpret_cast<TargetType>(anyptr);
}

// Pointer type conversion with no offset
template<typename TargetType>
TargetType MakePointer(SIZE_T anyptr)
{
	return reinterpret_cast<TargetType>(anyptr);
}


// Pointer type conversion with byte offset
template<typename TargetType>
TargetType MakePointer(void* anyptr, SIZE_T offset)
{
	return reinterpret_cast<TargetType>(reinterpret_cast<SIZE_T>(anyptr) + offset);
}

// Header only utility class... should have made this a long time ago
namespace Util
{
	namespace Debug
	{
		// Prints a formatted message only during debug
		inline static void Print(const char* fmt, ...)
		{
#if _DEBUG
			va_list args;
			va_start(args, fmt);
			vprintf(fmt, args);
			va_end(args);
#endif
		}
	};

	namespace String
	{
		// Converts the string to lower case
		inline static void ToLower(std::string& str)
		{
			std::transform(str.begin(), str.end(), str.begin(), [](UCHAR c) { return ::tolower(c); });
		}

		// Convert a wide Unicode string to an UTF8 string
		static inline std::string ToUTF8(const std::wstring &wstr)
		{
			if (wstr.empty()) return std::string();
			int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
			std::string strTo(size_needed, 0);
			WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
			return strTo;
		}

		// Convert an UTF8 string to a wide Unicode String
		static inline std::wstring ToUnicode(const std::string &str)
		{
			if (str.empty()) return std::wstring();
			int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
			std::wstring wstrTo(size_needed, 0);
			MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
			return wstrTo;
		}
	};
	
	namespace Random
	{
		// Not secure
		inline static std::mt19937_64 __random_gen = std::mt19937_64{ std::random_device{}() };

		// Generate a random size_t integer from C++ stl, not secure
		inline static ULONGLONG Generate64()
		{
			return Util::Random::__random_gen();
		}
	};
	
	namespace Path
	{
		// Convert a relative file path to an absolute file path (from the current executable)
		inline static std::wstring RelativeToAbsolute(const std::wstring& RelativePath)
		{
			auto curdir = std::wstring{ };
			auto fpath = std::wstring{ };

			curdir.reserve(MAX_PATH);
			fpath.reserve(MAX_PATH);

			GetModuleFileName(NULL, &curdir[0], MAX_PATH);

			PathRemoveFileSpec(&curdir[0]);

			PathCombine(&fpath[0], &curdir[0], RelativePath.c_str());

			return fpath;
		}
	};

	namespace Exception
	{
		// Throw a C-style formatted exception
		template<typename ... Args>
		static void Throw(const std::string& format, Args ... args)
		{
			SIZE_T size = snprintf(nullptr, 0, format.c_str(), args ...) + 1;
			auto buf = std::string{};
			buf.resize(size);
			snprintf(&buf[0], size, format.c_str(), args ...);
			throw std::runtime_error(buf);
		}

		// Throw an exception given a Win32 error code
		static inline VOID ThrowWin32ErrorCode(const std::wstring& FunctionName, ULONG dwErrorCode)
		{
			LPSTR Buffer;
			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				dwErrorCode,
				LANG_USER_DEFAULT,
				(LPSTR)&Buffer,
				0,
				NULL);

			Util::Exception::Throw("%ws: %s", FunctionName.c_str(), Buffer);
		}

		// Throw an exception given a Win32 error code
		static inline VOID ThrowWin32ErrorCode(const std::string& FunctionName, ULONG dwErrorCode)
		{
			LPSTR Buffer;
			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				dwErrorCode,
				LANG_USER_DEFAULT,
				(LPSTR)&Buffer,
				0,
				NULL);

			Util::Exception::Throw("%s: %s", FunctionName.c_str(), Buffer);
		}

		// Throw GetLastError as exception
		static inline VOID ThrowLastError(const std::wstring& FunctionName)
		{
			Util::Exception::ThrowWin32ErrorCode(Util::String::ToUTF8(FunctionName), GetLastError());
		}

		// Throw GetLastError as exception
		static inline VOID ThrowLastError(const std::string& FunctionName)
		{
			Util::Exception::ThrowWin32ErrorCode(FunctionName, GetLastError());
		}
	};

};