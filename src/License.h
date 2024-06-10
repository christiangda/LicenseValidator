#ifndef LICENSE_H
#define LICENSE_H

#include <openssl/rsa.h>

#include <string>

// Decode a base64 string
std::string base64Decode(const std::string enc);

// Load a RSA private key from a PEM string
EVP_PKEY *loadRsaPemPubKey(const std::string pubkey);

// Validate a license key
bool verifyLicense(const unsigned char *licenseContent, size_t licenseContentSize, const unsigned char *licenseSignature, size_t licenseSignatureSize, const std::string pubkey);

#endif // LICENSE_H