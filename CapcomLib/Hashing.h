#pragma once
#include <string>

using fnv_t = std::size_t;

fnv_t fnv_1a(std::string const& text)
{
	std::size_t hash = 14695981039346656037u;
	for (std::string::const_iterator it = text.begin(), end = text.end();
		it != end; ++it)
	{
		hash ^= *it;
		hash *= 1099511628211u;
	}

	return hash;
}