# license-validator

This is c++ project to validate license files base on the public key

## How to License the software

Yes, you can implement a licensing system to distribute your app using private certificates and the expiration date. This system is often used in professional enterprise software. You can create a unique certificate for each client (identified by some unique property such as Company Name), sign it using your private key, and set an expiration date within the certificate.

Here's an overview of the process:

### 1. Generate a Private and Public Key

You will need a private key that you will use throughout the process to sign the licenses. The `openssl` tool can be used to generate RSA keys:

```bash
# Generate a private key
openssl genrsa -out private-rsa.pem 2048

# Extract the public key from the private key
openssl rsa -in private-rsa.pem -pubout -out public-rsa.pem
```

### 2. Create License file and Sign it

Once you have generated a private key, you can use it to sign the license:

```bash
# Create a license file with the product name, license key, and expiration date
cat > license.txt <<EOF
Product Name: FaceDetector
License Key: 7afcfb0c-da67-4d5d-b1c4-867ff2701f59
Expires: 2024-06-15
EOF

# Sign the license data with SHA256 hashing and RSA algorithm
openssl dgst -sha256 -sign private-rsa.pem -out license.txt.sha256 license.txt
```

This will generate a signature file `license.txt.sha256`, which is binary data that can be used to verify the license.

### 3. License Verification

For license verification, the customer's software needs your public key to verify the signature:

The verification process looks like this:

```bash
openssl dgst -sha256 -verify public-rsa.pem -signature license.txt.sha256 license.txt
```

If the license is valid, this command will print `Verified OK`. Otherwise, it will print `Verification Failure`.

### 4. Checking Expiration Date

Within your application, you should design a mechanism to fetch the license details, especially the expiration date, from the license file and compare it against the current date to determine whether or not the license has expired.

Remember to securely protect your private key. If it gets into the wrong hands, it can be used to generate fake licenses for your application. Always store your private key in a secure environment.

**Note:** This is a simple example and may not cover all possible corner cases. Make sure to thoroughly test your implementation and consider edge cases such as time zone differences and what happens when the license check fails.

### 5. Packaging and Distribution

We must create a licese.base64 file with the public key and the license file. This file will be used to validate the license.  The format must be as follows:

format: key/{BASE64_KEY}.{BASE64_SIGNATURE}

```bash
# Create a license.base64 file with the public key and the license file
cat > license.dat <<EOF
key|$(base64 --input license.txt | tr -d '\n').$(base64 --input license.txt.sha256 | tr -d '\n')
EOF
```

### 6. Run the program

To run the program, you must pass the license.base64 file as an argument. The program will validate the license and print the result.

```bash
./build/LicenseValidator --license-key $(cat license.dat) --public-key-base64 $(base64 --input public-rsa.pem | tr -d '\n')
```
