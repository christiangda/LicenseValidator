#ifndef LICENSE_H
#define LICENSE_H

#include <openssl/rsa.h>

#include <string>

// Decode a base64 string
std::string base64_decode(const std::string enc);

// Load a RSA private key from a PEM string
EVP_PKEY *load_rsa_pem_pub_key(const std::string enc_pub_key);

#endif // LICENSE_H