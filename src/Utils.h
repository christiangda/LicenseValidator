#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

// Split a string into a vector of strings using a delimiter
std::vector<std::string> ssplit(std::string str, std::string delim);

// Replace a substring with another substring
std::string sreplace(std::string str, const std::string &from, const std::string &to);

// Print a hex string
void printHex(const unsigned char *data, size_t size);

#endif // UTILS_H