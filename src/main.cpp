#include <boost/program_options.hpp>

#include <iomanip>
#include <iostream>

#include "Config.h"
#include "License.h"
#include "Utils.h"

namespace po = boost::program_options;

int main(int argc, char **argv)
{
	// Version
	po::options_description helpVersionOptions("Help and Version Options");
	helpVersionOptions.add_options()("help,h", "produce help message");
	helpVersionOptions.add_options()("version,v", "print program version");

	// Global Options
	po::options_description globalOptions("Global Options");
	globalOptions.add_options()("public-key-base64", po::value<std::string>(), "Public key in base64 format");
	globalOptions.add_options()("license-key", po::value<std::string>(), "License key content in format: key|{LICENSE_KEY_BASE64}.{LICENSE_KEY_SIGNATURE_BASE64}");

	po::options_description allOptions;
	allOptions.add(helpVersionOptions);
	allOptions.add(globalOptions);

	// parse the command line options
	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(allOptions).run(), vm);
	po::notify(vm);

	// if no options are provided, show help
	if (argc == 1)
	{
		std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
		std::cout << allOptions << std::endl;
		return EXIT_SUCCESS;
	}

	// check for help and version options
	if (vm.count("help"))
	{
		std::cout << allOptions << std::endl;
		return EXIT_SUCCESS;
	}

	if (vm.count("version"))
	{
		std::cout << "LicenseValidator " << PROJECT_VERSION_MAJOR << "." << PROJECT_VERSION_MINOR << "." << PROJECT_VERSION_PATCH << std::endl;
		return EXIT_SUCCESS;
	}

	// check for required options
	if (!vm.count("public-key-base64"))
	{
		std::cerr << "Public key is required (--public-key-base64)" << std::endl;
		return EXIT_FAILURE;
	}

	if (!vm.count("license-key"))
	{
		std::cerr << "License key is required (--license-key)" << std::endl;
		return EXIT_FAILURE;
	}

	// get the values of the options
	std::string publicKeyBase64 = vm["public-key-base64"].as<std::string>();
	std::string licenseKey = vm["license-key"].as<std::string>();

	// License key has the format: key|{LICENSE_KEY_BASE64}.{LICENSE_KEY_SIGNATURE_BASE64}
	// we need to split the key and signature
	const std::string LICENSE_DELIMITER = "|";
	const std::string LICENSE_KEY_DELIMITER = ".";
	const std::string LICENSE_KEY_PREFIX = "key";

	std::vector<std::string> parts = ssplit(licenseKey, LICENSE_DELIMITER);

	if (parts.size() != 2)
	{
		std::cerr << "Invalid license.key file, no '" << LICENSE_DELIMITER << "' separator" << std::endl;
		return EXIT_FAILURE;
	}
	std::string identifier = parts[0];
	std::string composedKey = parts[1];

	// check the identifier is key
	if (identifier != LICENSE_KEY_PREFIX)
	{
		std::cerr << "Invalid license.key file, invalid identifier, not '" << LICENSE_KEY_PREFIX << "' present" << std::endl;
		return EXIT_FAILURE;
	}

	// split the composed key into key and signature
	std::vector<std::string> keySignature = ssplit(composedKey, LICENSE_KEY_DELIMITER);
	if (keySignature.size() != 2)
	{
		std::cerr << "Invalid license.key file, no '" << LICENSE_KEY_DELIMITER << "' separator" << std::endl;
		return EXIT_FAILURE;
	}
	std::string licenseContentBase64 = keySignature[0];
	std::string licenseSignatureBase64 = keySignature[1];

	// decode (base64) the public key, license content and license signature
	std::string publicKey = base64Decode(publicKeyBase64);
	std::string licenseContent = base64Decode(licenseContentBase64);
	std::string licenseSignature = base64Decode(licenseSignatureBase64);

	// convert the licenseContent and licenseSignature from string to unsigned char *
	std::vector<unsigned char> licenseContentBytes(licenseContent.begin(), licenseContent.end());
	// std::vector<unsigned char> licenseSignatureBytes(licenseSignature.begin(), licenseSignature.end());

	std::string signatureFile = "license.txt.sha256.sign";
	std::vector<unsigned char> licenseSignatureBytes = readFile(signatureFile.c_str());

	// print size of licenseContentBytes and licenseSignatureBytes
	std::cout
			<< "licenseContentBytes.size() = " << licenseContentBytes.size() << std::endl;
	std::cout << "licenseSignatureBytes.size() = " << licenseSignatureBytes.size() << std::endl;

	// size of the licenseContent and licenseSignature
	size_t licenseContentSize = licenseContent.size();
	size_t licenseSignatureSize = licenseSignature.size();

	// show the decoded strings
	std::cout << std::endl;
	std::cout
			<< "Public Key: \n"
			<< publicKey << std::endl;
	std::cout << std::endl;

	std::cout << "License Content: \n"
						<< licenseContent << std::endl;
	std::cout << std::endl;

	std::cout << "License Signature: (hexdump license.txt.sha256.sign)" << std::endl;
	printHex(licenseSignatureBytes);
	std::cout << std::endl;

	// validate the license key
	bool valid = verifyLicense(licenseContentBytes, licenseSignatureBytes, publicKey);

	// show the result
	if (valid)
	{
		std::cout << "License key is valid" << std::endl;
	}
	else
	{
		std::cout << "License key is invalid" << std::endl;
	}

	return EXIT_SUCCESS;
}