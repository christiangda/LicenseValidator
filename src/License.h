#ifndef LICENSE_H
#define LICENSE_H

#include <openssl/rsa.h>

#include <string>

// Decode a base64 string
std::string base64Decode(const std::string enc);

// Load a RSA private key from a PEM string
EVP_PKEY *loadRsaPemPubKey(const std::string enc_pub_key);

// Validate a license key
bool verifyLicense(const std::string licenseContent, const unsigned char *licenseSignature, const std::string enc_pub_key);

#endif // LICENSE_H