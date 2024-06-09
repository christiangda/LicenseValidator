#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

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
	globalOptions.add_options()("license-key", po::value<std::string>(), "License key in base64 format");

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

	// License key has the format: key/{BASE64_KEY}.{BASE64_SIGNATURE}
	// we need to split the key and signature
	std::vector<std::string> parts = ssplit(licenseKey, "|");
	if (parts.size() != 0)
	{
		BOOST_LOG_TRIVIAL(info) << "parts.size() = " << parts.size();
		for (auto &part : parts)
		{
			BOOST_LOG_TRIVIAL(info) << "part = " << part;
		}
	}
	if (parts.size() != 2)
	{
		BOOST_LOG_TRIVIAL(error) << "Invalid license.dat file, no '/' separator";
		return EXIT_FAILURE;
	}
	std::string identifier = parts[0];
	std::string composedKey = parts[1];

	// check the identifier is key
	if (identifier != "key")
	{
		BOOST_LOG_TRIVIAL(error) << "Invalid license.dat file, no prefix 'key'";
		return EXIT_FAILURE;
	}

	// split the composed key into key and signature
	std::vector<std::string> keySignature = ssplit(composedKey, ".");
	if (keySignature.size() != 2)
	{
		BOOST_LOG_TRIVIAL(error) << "Invalid license.dat file, no '.' separator";
		return EXIT_FAILURE;
	}
	std::string licenseContentBase64 = keySignature[0];
	std::string licenseSignatureBase64 = keySignature[1];

	// decode the base64 for the public key
	std::string publicKey = base64Decode(publicKeyBase64);
	std::string licenseContent = base64Decode(licenseContentBase64);
	std::string licenseSignature = base64Decode(licenseSignatureBase64);

	// show the decoded strings
	std::cout
			<< "Public Key: \n"
			<< publicKey << std::endl;
	std::cout << "License Content: \n"
						<< licenseContent << std::endl;
	std::cout << "License Signature: \n"
						<< licenseSignature << std::endl;
	std::cout << std::endl;

	// convert the licenseKey from string to unsigned char []
	size_t licenseSignatureLength = licenseSignature.size();
	unsigned char licenseSignatureChar[licenseSignatureLength + 1]; // +1 for the null character

	std::copy(licenseSignature.begin(), licenseSignature.end(), licenseSignatureChar);
	licenseSignatureChar[licenseSignatureLength] = '\0'; // Add null character at the end

	// validate the license key
	bool valid = verifyLicense(licenseContent, licenseSignatureChar, publicKey);

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