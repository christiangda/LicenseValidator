#include "Utils.h"

#include <string>
#include <vector>

// Split a string into a vector of strings using a delimiter
std::vector<std::string> ssplit(std::string str, std::string delim)
{
	std::vector<std::string> parts;

	size_t pos;
	while ((pos = str.find(delim)) != std::string::npos)
	{
		parts.push_back(str.substr(0, pos));
		str = str.substr(pos + delim.size());
	}

	parts.push_back(str); // Last word

	return parts;
}

// Replace a substring with another substring
std::string sreplace(std::string str, const std::string &from, const std::string &to)
{
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos)
	{
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}

	return str;
}
