#ifndef LICENSE_H
#define LICENSE_H

#include <openssl/rsa.h>

#include <string>

// Decode a base64 string
std::string base64Decode(const std::string enc);

// Load a RSA private key from a PEM string
EVP_PKEY *loadRsaPemPubKey(const std::string pubkey);

// Validate a license key
bool verifyLicense(std::vector<unsigned char> licenseContent, std::vector<unsigned char> licenseSignature, const std::string pubkey);

#endif // LICENSE_H