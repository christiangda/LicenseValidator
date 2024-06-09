#include <boost/program_options.hpp>

#include <iostream>

#include "Config.h"
#include "License.h"

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
	globalOptions.add_options()("license-key-base64", po::value<std::string>(), "License key in base64 format");

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

	if (!vm.count("license-key-base64"))
	{
		std::cerr << "License key is required (--license-key-base64)" << std::endl;
		return EXIT_FAILURE;
	}

	// get the values of the options
	std::string publicKeyBase64 = vm["public-key-base64"].as<std::string>();
	std::string licenseKeyBase64 = vm["license-key-base64"].as<std::string>();

	// decode the base64 strings
	std::string publicKey = base64Decode(publicKeyBase64);
	std::string licenseKey = base64Decode(licenseKeyBase64);

	// show the decoded strings
	std::cout << "Public Key: " << publicKey << std::endl;
	// std::cout << "License Key: " << licenseKey << std::endl;

	// convert the licenseKey from string to unsigned char []
	size_t length = licenseKey.size();
	unsigned char licenseKeyChar[length + 1]; // +1 for the null character

	std::copy(licenseKey.begin(), licenseKey.end(), licenseKeyChar);
	licenseKeyChar[length] = '\0'; // Add null character at the end

	// validate the license key
	bool valid = verifyLicense(licenseKeyChar, publicKey);

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