# license-validator

This is c++ project to validate license files base on the public key

license: IX2QdKcrwEh7zuH1CuASs02DrTHl6MUPfnsm8lTFSX4Gn+pznUd6tf8GMaCB3RlD40ZizPsDFtkkcDyqf58TccC7G7Y66aYuRDPR3V8OCYsxItys5ahBSSjHCeSMPd6DPwi2QhY3x+zDZmQzGJruaRKKk2jVKlTAfiwoYAovcgYVfZ/0JfpP+PgQfQ7nM5VB69xhAlOE2PdYD9AK6vxGDRD20xYwNEKKECCUut+/FvcF6tYZZtujBtt/XhuhwScsD4+rQyMS2U51vRQfL9ZvzPs10Tg0RkqplwgTARAQBSgvBV8rWO0PeZ3gd7LTKc1At15dvvu2ozQCX7cK+bFIZg==

public key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEwNlBJZVJWOTd1ZzRBQzBTUTFrQwpTTDNNNi9sVEVkaTNWOGxOdW83MDFrMjNiVGFHcTRvMTFNZ21tTis4eHNqQTZ5RG4rNjhMcm1qLzRrdWZ4UGlTCnVhL2I1MmJ4TElQcDVEc2hpQXFBNXEzOFdTM0hsYU5hRllJNWI5eklHbDhWVkwwQzArc3A4amdLalphWUVPdlEKc2ZLaDNiSlVuL3pnZ2tySUtLYmVpZG9iNlNSa2dkb2tDeWlPRnpkSkhiNTlJNkxiWDg1TVlHYmduWlBFeGVXLwpzQ3NQMnlUK2M2cWZ0NU9ieFhGMXdISmhMTU5oZkVpdTNmRW9lNXk4Sy9TNjR5RCtRekRmazB6OUJlN1RKbnkvCnVhek5STFlMdGRQOHc3aWhnSVFSQnZ4bk1kZWJjL2xVNUpobFJEVSs4Q3hPYmhsSkxINEJkTXhXOVVrRGJ6V0MKandJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==

## How to License the software

Yes, you can implement a licensing system to distribute your app using private certificates and the expiration date. This system is often used in professional enterprise software. You can create a unique certificate for each client (identified by some unique property such as Company Name), sign it using your private key, and set an expiration date within the certificate.

Here's an overview of the process:

### 1. Generate a Private Key

You will need a private key that you will use throughout the process to sign the licenses. The `openssl` tool can be used to generate RSA keys:

```bash
openssl genrsa -out ~/tmp/private-rsa.pem 2048
```

### 2. Signing the License

Once you have generated a private key, you can use it to sign the license:

```bash
echo "Company Name: Acme Corp\nExpires: 2030-12-31" > ~/tmp/license.txt

# Sign the license data with SHA256 hashing and RSA algorithm
openssl dgst -sha256 -sign ~/tmp/private-rsa.pem -out ~/tmp/license.txt.sha256 ~/tmp/license.txt
```

This will generate a signature file `license.sig`, which is what you will deliver to the customer along with the license text itself.

### 3. License Verification

For license verification, the customer's software needs your public key to verify the signature:

```bash
openssl rsa -in ~/tmp/private-rsa.pem -pubout -out ~/tmp/public-rsa.pem

# openssl pkey -in ~/tmp/private-ed25519.pem -outform PEM -pubout -out ~/tmp/public-ed25519.pem
```

The verification process looks like this:

```bash
openssl dgst -sha256 -verify ~/tmp/public-rsa.pem -signature ~/tmp/license.sig ~/tmp/license.txt
```

If the license is valid, this command will print `Verified OK`. Otherwise, it will print `Verification Failure`.

### 4. Checking Expiration Date

Within your application, you should design a mechanism to fetch the license details, especially the expiration date, from the license file and compare it against the current date to determine whether or not the license has expired.

Remember to securely protect your private key. If it gets into the wrong hands, it can be used to generate fake licenses for your application. Always store your private key in a secure environment.

**Note:** This is a simple example and may not cover all possible corner cases. Make sure to thoroughly test your implementation and consider edge cases such as time zone differences and what happens when the license check fails.
