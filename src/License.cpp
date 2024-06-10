#include "License.h"

#include <iostream>
#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string>
#include <vector>

#include <boost/beast/core/detail/base64.hpp>

using namespace boost::beast::detail;

// Decode from base64
std::string base64Decode(const std::string enc)
{
	std::string dec;
	std::size_t len = enc.size();
	std::size_t decodedLen = base64::decoded_size(len);
	std::string decoded(decodedLen, '\0');

	auto [out, in] = base64::decode(&decoded[0], enc.c_str(), len);
	dec = decoded.substr(0, out);

	return dec;
}

// Load a RSA public key from a PEM string
EVP_PKEY *loadRsaPemPubKey(const std::string pubkey)
{
	OSSL_DECODER_CTX *dctx;				/* the decoder context */
	EVP_PKEY *pkey = NULL;				/* the decoded key */
	const char *format = "PEM";		/* NULL for any format */
	const char *structure = NULL; /* any structure */
	const char *keytype = "RSA";	/* NULL for any key */

	BIO *bio = BIO_new_mem_buf(pubkey.c_str(), pubkey.size());
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format, structure, keytype, EVP_PKEY_PUBLIC_KEY, NULL, NULL);
	if (dctx == NULL)
	{
		std::cerr << "OSSL_DECODER_CTX_new_for_pkey failed" << std::endl;
		BIO_free_all(bio);
		ERR_print_errors_fp(stdout);
	}

	// Decode the public key from the bio
	if (!OSSL_DECODER_from_bio(dctx, bio))
	{
		std::cerr << "OSSL_DECODER_from_bio failed" << std::endl;
		BIO_free_all(bio);
		OSSL_DECODER_CTX_free(dctx);
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	// pkey is created with the decoded data from the bio
	if (pkey == NULL)
	{
		std::cerr << "Failed to decode public key" << std::endl;
		BIO_free_all(bio);
		OSSL_DECODER_CTX_free(dctx);
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	BIO_free_all(bio);
	OSSL_DECODER_CTX_free(dctx);

	return pkey;
}

// Validate a license key
bool verifyLicense(std::vector<unsigned char> licenseContent, std::vector<unsigned char> licenseSignature, const std::string pubkey)
{
	EVP_PKEY *pkey = loadRsaPemPubKey(pubkey);
	if (pkey == NULL)
	{
		std::cerr << "Failed to load public key" << std::endl;
		ERR_print_errors_fp(stdout);
		return false;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
	{
		std::cerr << "Failed to create EVP_PKEY_CTX" << std::endl;
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	if (EVP_PKEY_verify_init(ctx) <= 0)
	{
		std::cerr << "Failed to initialize EVP_PKEY_CTX" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	// PKCS1 padding scheme
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
	{
		std::cerr << "Failed to set RSA padding" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	// SHA256 digest
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
	{
		std::cerr << "Failed to set signature MD" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	if (EVP_PKEY_verify(ctx, licenseSignature.data(), licenseSignature.size(), licenseContent.data(), licenseContent.size()) <= 0)
	{
		std::cerr << "Failed to verify license" << std::endl;
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	return true;
}