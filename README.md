# license-validator

This is c++ project to validate license files base on the public key

## How to License the software

Create a Private and Public Key pair using the `openssl` tool. The private key will be used to sign the license, and the public key will be used to verify the signature.
The license file will contain information such as the product name, license key, and expiration date. This file will be signed using the private key to generate a signature file.

## Process

### 1. Generate a Private and Public Key

You will need a private key that you will use throughout the process to sign the licenses. The `openssl` tool can be used to generate RSA keys:

```bash
# Generate a private key
openssl genrsa -out private-key-rsa.pem 4096

# Extract the public key from the private key
openssl rsa -in private-key-rsa.pem -pubout -out public-key-rsa.pem
```

### 2. Create License file and Sign it

Once you have generated a private key, you can use it to sign the license:

```bash
# Create a license file with the product na+me, license key, and expiration date
cat > license.txt <<EOF
Product Name: My Product
Device ID: 18443010C117490E00
Expires: 2024-06-30
EOF

# Sign the license data with SHA256 hashing and RSA algorithm
openssl dgst -sha256 -sign private-key-rsa.pem -out license.txt.sha256.sign license.txt
```

This will generate a signature file `license.txt.sha256.sign`, which is binary data that can be used to verify the license.

### 3. License Verification (using openssl)

For license verification, the customer's software needs your public key to verify the signature:

The verification process looks like this:

```bash
# # Sign the file using sha256 digest and PKCS1 padding scheme
openssl dgst -sha256 -verify public-key-rsa.pem -signature license.txt.sha256.sign license.txt
```

If the license is valid, this command will print `Verified OK`. Otherwise, it will print `Verification Failure`.

### 4. Checking Expiration Date

Within your application, you should design a mechanism to fetch the license details, especially the expiration date, from the license file and compare it against the current date to determine whether or not the license has expired.

Remember to securely protect your private key. If it gets into the wrong hands, it can be used to generate fake licenses for your application. Always store your private key in a secure environment.

**Note:** This is a simple example and may not cover all possible corner cases. Make sure to thoroughly test your implementation and consider edge cases such as time zone differences and what happens when the license check fails.

### 5. Packaging and Distribution

We must create a license.key file with the public key and the license file. This file will be used to validate the license.  The format must be as follows:

format: key|{LICENSE_KEY_BASE64}.{LICENSE_KEY_SIGNATURE_BASE64}

```bash
# Create a license.key file with the public key and the license file
cat > license.key <<EOF
key|$(base64 --input license.txt | tr -d '\n').$(base64 --input license.txt.sha256.sign | tr -d '\n')
EOF
```

### 6. License Validation (using the LicenseValidator program)

Install MacOS dependencies:

```bash
brew install cmake
brew install clang
brew install clang-format

brew install boost
brew install openssl
```

Build the LicenseValidator program using the following commands:

```bash
cmake -S . -B build
cmake --build build
```

To run the program, you must pass the license.key and the public key as arguments. The program will validate the license and print the result.

```bash
./build/LicenseValidator --license-key $(cat license.key) --public-key-base64 $(base64 --input public-key-rsa.pem | tr -d '\n')
```

## References

+ [Example C++ Cryptographic Verification](https://github.com/keygen-sh/example-cpp-cryptographic-verification/blob/master/README.md)
+ [OpenSSL libraries](https://www.openssl.org/docs/man3.1/man3/index.html)
+ [Boost libraries](https://www.boost.org/doc/libs/1_85_0/libs/libraries.htm)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
