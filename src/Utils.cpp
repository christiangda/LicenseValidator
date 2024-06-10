#include "Utils.h"

#include <iomanip>
#include <iostream>
#include <streambuf>
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

// Print a hex string
void printHex(std::vector<unsigned char> data)
{
	size_t size = data.size();
	size_t offset = 0;
	for (size_t i = 0; i < size; i += 16)
	{
		// Print offset address
		std::cout << std::setfill('0') << std::setw(8) << std::hex << offset;
		std::cout << " ";

		// Print hex representation of 16 bytes
		for (size_t j = 0; j < 16 && i + j < size; ++j)
		{
			std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)data[i + j];
			if (j != 15 && (i + j + 1) % 2 == 0)
			{
				std::cout << " ";
			}
		}
		std::cout << std::endl;
		offset += 16;
	}
}