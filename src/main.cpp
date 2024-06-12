#include <boost/program_options.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

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
	globalOptions.add_options()("license-key-file", po::value<std::string>(), "License key file in format: key|{LICENSE_KEY_BASE64}.{LICENSE_KEY_SIGNATURE_BASE64}");
	globalOptions.add_options()("public-key-file", po::value<std::string>(), "Public key file.");
	globalOptions.add_options()("debug", po::value<bool>()->default_value(false), "Enable debug mode");

	po::options_description allOptions;
	allOptions.add(helpVersionOptions);
	allOptions.add(globalOptions);

	// parse the command line options
	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(allOptions).run(), vm);
	po::notify(vm);

	// catch the exception of the required options
	try
	{
		po::notify(vm);
	}
	catch (const po::error &e)
	{
		std::cerr << "❌ -> " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

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
	if (!vm.count("license-key-file"))
	{
		std::cerr << "❌ -> License key is required (--license-key-file)" << std::endl;
		return EXIT_FAILURE;
	}

	if (!vm.count("public-key-file"))
	{
		std::cerr << "❌ -> Public key is required (--public-key-file)" << std::endl;
		return EXIT_FAILURE;
	}

	// get the values of the options
	std::string publicKeyFile = vm["public-key-file"].as<std::string>();
	std::vector<unsigned char> publicKeyBytes = readFile(publicKeyFile.c_str());

	std::string publicKey = std::string(publicKeyBytes.begin(), publicKeyBytes.end());

	std::string licenseKeyFile = vm["license-key-file"].as<std::string>();
	std::vector<unsigned char> licenseKeyBytes = readFile(licenseKeyFile.c_str());

	std::string licenseKey = std::string(licenseKeyBytes.begin(), licenseKeyBytes.end());

	// debug mode
	bool debug = vm["debug"].as<bool>();

	// show the license key
	if (debug)
	{
		std::cout << "License key content: " << std::endl;
		std::cout << std::endl;
		std::cout << licenseKey << std::endl;
		std::cout << std::endl;
	}

	// License key has the format: key|{LICENSE_KEY_BASE64}.{LICENSE_KEY_SIGNATURE_BASE64}
	// we need to split the key and signature
	const std::string LICENSE_DELIMITER = "|";
	const std::string LICENSE_KEY_DELIMITER = ".";
	const std::string LICENSE_KEY_PREFIX = "key";

	// get the first line and second line
	std::vector<std::string> licenseKeyLines = ssplit(licenseKey, "\n");
	if (licenseKeyLines.size() != 1)
	{
		std::cerr << "❌ -> Invalid license.key file, does not have the number of lines expected" << std::endl;
		std::cerr << "❌ -> Expected 1 lines, but got " << licenseKeyLines.size() << " lines" << std::endl;
		std::cerr << "❌ -> Please check the file content" << std::endl;
		return EXIT_FAILURE;
	}
	std::string firstLine = licenseKeyLines[0];

	if (debug)
	{
		std::cout << "license.key first line: " << firstLine << std::endl;
		std::cout << std::endl;
	}

	std::vector<std::string> firstLineParts = ssplit(firstLine, LICENSE_DELIMITER);
	if (firstLineParts.size() != 2)
	{
		std::cerr << "❌ -> Invalid license.key file (first line), no '" << LICENSE_DELIMITER << "' separator" << std::endl;
		return EXIT_FAILURE;
	}
	std::string keyIdentifier = firstLineParts[0];
	std::string composedKey = firstLineParts[1];

	// check the identifier is key
	if (keyIdentifier != LICENSE_KEY_PREFIX)
	{
		std::cerr << "❌ -> Invalid license.key file (first line), invalid identifier, not '" << LICENSE_KEY_PREFIX << "' present" << std::endl;
		return EXIT_FAILURE;
	}

	// split the composed key into key and signature
	std::vector<std::string> keySignature = ssplit(composedKey, LICENSE_KEY_DELIMITER);
	if (keySignature.size() != 2)
	{
		std::cerr << "❌ -> Invalid license.key file  (first line), no '" << LICENSE_KEY_DELIMITER << "' separator" << std::endl;
		return EXIT_FAILURE;
	}
	std::string licenseContentBase64 = keySignature[0];
	std::string licenseSignatureBase64 = keySignature[1];

	// decode (base64) the public key, license content and license signature
	std::string licenseContent = base64Decode(licenseContentBase64);
	std::string licenseSignature = base64Decode(licenseSignatureBase64);

	// convert to std::vector<unsigned char> (bytes)
	std::vector<unsigned char> licenseContentBytes = std::vector<unsigned char>(licenseContent.begin(), licenseContent.end());
	std::vector<unsigned char> licenseSignatureBytes = std::vector<unsigned char>(licenseSignature.begin(), licenseSignature.end());

	if (debug)
	{
		// size of the files in bytes
		std::cout << "Number of bytes of the license file: " << licenseContentBytes.size() << std::endl;
		std::cout << "Number of bytes of the license signature file: " << licenseSignatureBytes.size() << std::endl;
		std::cout << "Number of bytes of the public key file:  " << publicKeyBytes.size() << std::endl;
		std::cout << std::endl;

		// print the content
		std::cout << "License content: " << std::endl;
		std::cout << licenseContent << std::endl;
		std::cout << std::endl;

		// this is binary data, so we can't print it as a string
		// std::cout << "License signature: " << std::endl;
		// std::cout << licenseSignature << std::endl;
		// std::cout << std::endl;

		std::cout << "Public key: " << std::endl;
		std::cout << publicKey << std::endl;
		std::cout << std::endl;

		// print the bytes in hex
		std::cout << "License content bytes: " << std::endl;
		printHex(licenseContentBytes);
		std::cout << std::endl;

		std::cout << "License signature bytes: " << std::endl;
		printHex(licenseSignatureBytes);
		std::cout << std::endl;

		std::cout << "Public key bytes: " << std::endl;
		printHex(publicKeyBytes);
		std::cout << std::endl;
	}

	// validate the license key
	bool valid = verifyLicense(licenseContentBytes, licenseSignatureBytes, publicKeyBytes);

	// show the result
	if (valid)
	{
		std::cout << "🔑 -> License key is valid ✅" << std::endl;
	}
	else
	{
		std::cout << "🔑 -> License key is invalid ❌" << std::endl;
	}

	return EXIT_SUCCESS;
}