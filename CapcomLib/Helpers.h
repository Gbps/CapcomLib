#pragma once
#include "stdafx.h"

// Maximum size returned from stdstrerror
const auto STRERROR_MAXSIZE = 5000ULL;

// Prints a Win32 error and exits the console program
// https://github.com/iceb0y/ntdrvldr/blob/master/main.c
VOID PrintErrorAndExit(wchar_t *Function, ULONG dwErrorCode);

// Returns an std::string version of strerror of up to STRERROR_MAXSIZE size
std::string stdstrerror(int errnum);