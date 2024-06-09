#include "License.h"

#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>

#include <boost/beast/core/detail/base64.hpp>
#include <boost/log/trivial.hpp>
#include <string>

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
EVP_PKEY *loadRsaPemPubKey(const std::string enc_pub_key)
{
	OSSL_DECODER_CTX *dctx;
	EVP_PKEY *pkey = NULL;				/* the decoded key */
	const char *format = "PEM";		/* NULL for any format */
	const char *structure = NULL; /* any structure */
	const char *keytype = "RSA";	/* NULL for any key */

	BIO *bio = BIO_new_mem_buf(enc_pub_key.c_str(), enc_pub_key.size());
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, format, structure, keytype, EVP_PKEY_PUBLIC_KEY, NULL, NULL);
	if (dctx == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "OSSL_DECODER_CTX_new_for_pkey failed";
		BIO_free_all(bio);
		ERR_print_errors_fp(stdout);
	}

	// Decode the public key from the bio
	if (!OSSL_DECODER_from_bio(dctx, bio))
	{
		BOOST_LOG_TRIVIAL(error) << "OSSL_DECODER_from_bio failed";
		BIO_free_all(bio);
		OSSL_DECODER_CTX_free(dctx);
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	// pkey is created with the decoded data from the bio
	if (pkey == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "pkey is NULL";
		BIO_free_all(bio);
		OSSL_DECODER_CTX_free(dctx);
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	BIO_free_all(bio);
	OSSL_DECODER_CTX_free(dctx);

	return pkey;
}

bool verifyLicense(const unsigned char *license, const std::string enc_pub_key)
{
	EVP_PKEY *pkey = loadRsaPemPubKey(enc_pub_key);
	if (pkey == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to load RSA public key";
		ERR_print_errors_fp(stdout);
		return false;
	}

	BIO *bio = BIO_new_mem_buf(&license, sizeof(license));
	if (bio == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to create BIO";
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to create EVP_PKEY_CTX";
		BIO_free_all(bio);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	if (EVP_PKEY_verify_init(ctx) <= 0)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to initialize EVP_PKEY_verify";
		EVP_PKEY_CTX_free(ctx);
		BIO_free_all(bio);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	if (EVP_PKEY_verify(ctx, license, sizeof(license), NULL, 0) <= 0)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to verify license";
		EVP_PKEY_CTX_free(ctx);
		BIO_free_all(bio);
		EVP_PKEY_free(pkey);
		ERR_print_errors_fp(stdout);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	BIO_free_all(bio);
	EVP_PKEY_free(pkey);

	return true;
}