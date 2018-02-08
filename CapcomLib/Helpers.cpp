#include "stdafx.h"
#include "Helpers.h"
#include "ExceptionHelpers.h"

VOID PrintErrorAndExit(
	wchar_t *Function,
	ULONG dwErrorCode
)
{
	LPWSTR Buffer;

	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		LANG_USER_DEFAULT,
		(LPWSTR)&Buffer,
		0,
		NULL);
	fwprintf(stderr, L"%s: %ws", Function, Buffer);
	getchar();
	exit(dwErrorCode);
}

std::string stdstrerror(int errnum)
{
	std::string errmsg;
	errmsg.reserve(STRERROR_MAXSIZE);
	strerror_s(&errmsg[0], STRERROR_MAXSIZE, errnum);
	return errmsg;
}

VOID ThrowLdrLastError(const std::wstring & funcname)
{
	using namespace std::string_literals;

	// Yeah, I'm not using wide-char here :[
	LPSTR Buffer;

	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		LANG_USER_DEFAULT,
		(LPSTR)&Buffer,
		0,
		NULL);

	auto err = "[PELoader] %ls: "s + Buffer;
	ThrowFmtError(err, funcname.c_str());
}

VOID ThrowLdrLastError(const std::wstring & funcname, HANDLE handle)
{
	// Error handle (same check as NT_SUCCESS)
	if (reinterpret_cast<LONGLONG>(handle) > 0ULL) return;

	ThrowLdrLastError(funcname);
}

