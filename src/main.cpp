#include <boost/program_options.hpp>

#include <iostream>

#include "Config.h"

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
	globalOptions.add_options()("license-key", po::value<std::string>(), "License key");

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
		return 0;
	}

	// check for help and version options
	if (vm.count("help"))
	{
		std::cout << allOptions << std::endl;
		return 0;
	}

	if (vm.count("version"))
	{
		std::cout << "LicenseValidator " << PROJECT_VERSION_MAJOR << "." << PROJECT_VERSION_MINOR << "." << PROJECT_VERSION_PATCH << std::endl;
	}
}