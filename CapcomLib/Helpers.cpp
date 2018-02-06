#include "stdafx.h"
#include "Helpers.h"

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

const std::string stdstrerror(int errnum)
{
	std::string errmsg;
	errmsg.reserve(STRERROR_MAXSIZE);
	strerror_s(&errmsg[0], STRERROR_MAXSIZE, errnum);
	return errmsg;
}

