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
EVP_PKEY *loadRsaPemPubKey(const std::vector<unsigned char> pubkey)
{
	OSSL_DECODER_CTX *dctx;					 /* the decoder context */
	EVP_PKEY *pkey = nullptr;				 /* the decoded key */
	const char *format = "PEM";			 /* NULL for any format */
	const char *structure = nullptr; /* any structure */
	const char *keytype = "RSA";		 /* NULL for any key */

	BIO *bio = BIO_new_mem_buf(pubkey.data(), pubkey.size());
	// BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format, structure, keytype, EVP_PKEY_PUBLIC_KEY, NULL, NULL);
	if (dctx == nullptr)
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
		return nullptr;
	}

	// pkey is created with the decoded data from the bio
	if (pkey == nullptr)
	{
		std::cerr << "Failed to decode public key" << std::endl;
		BIO_free_all(bio);
		OSSL_DECODER_CTX_free(dctx);
		ERR_print_errors_fp(stdout);
		return nullptr;
	}

	// check if pkey is a RSA key
	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA)
	{
		std::cerr << "Public key is not RSA" << std::endl;
		BIO_free_all(bio);
		OSSL_DECODER_CTX_free(dctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return nullptr;
	}

	BIO_free_all(bio);
	OSSL_DECODER_CTX_free(dctx);

	return pkey;
}

// Validate a license key
bool verifyLicense(const std::vector<unsigned char> licenseContent, const std::vector<unsigned char> licenseSignature, const std::vector<unsigned char> pubkey)
{
	EVP_PKEY *pkey = loadRsaPemPubKey(pubkey);
	if (pkey == nullptr)
	{
		std::cerr << "Failed to load public key" << std::endl;
		ERR_print_errors_fp(stdout);
		return false;
	}

	EVP_MD_CTX *ctx = nullptr;

	ctx = EVP_MD_CTX_create();
	if (ctx == nullptr)
	{
		std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	// configure digest
	const EVP_MD *md = EVP_get_digestbyname("SHA256");
	if (md == nullptr)
	{
		std::cerr << "Failed to get SHA256 digest" << std::endl;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	int rc = EVP_DigestInit_ex(ctx, md, NULL);
	if (rc != 1)
	{
		std::cerr << "Failed to initialize digest" << std::endl;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
	if (rc != 1)
	{
		std::cerr << "Failed to initialize verify" << std::endl;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	rc = EVP_DigestVerifyUpdate(ctx, licenseContent.data(), licenseContent.size());
	if (rc != 1)
	{
		std::cerr << "Failed to update verify" << std::endl;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	rc = EVP_DigestVerifyFinal(ctx, licenseSignature.data(), licenseSignature.size());
	if (rc != 1)
	{
		std::cerr << "Failed to finalize verify" << std::endl;
		EVP_MD_CTX_destroy(ctx);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	EVP_MD_CTX_destroy(ctx);
	EVP_PKEY_free(pkey);

	return true;
}