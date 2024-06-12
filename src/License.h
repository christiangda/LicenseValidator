#ifndef LICENSE_H
#define LICENSE_H

#include <openssl/rsa.h>

#include <string>

// Decode a base64 string
std::string base64Decode(const std::string enc);

// Load a RSA private key from a PEM string
EVP_PKEY *loadRsaPemPubKey(const std::vector<unsigned char> pubkey);

// Validate a license key
bool verifyLicense(const std::vector<unsigned char> licenseContent, const std::vector<unsigned char> licenseSignature, const std::vector<unsigned char> pubkey);

#endif // LICENSE_H