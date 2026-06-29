/**
 *	Tempesta Management CLI tool
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <fstream>
#include <iostream>
#include <string>

#include <boost/program_options.hpp>

#include "../lib/error.hh"
#include "../lib/cli/client.hh"
#include "../lib/cli/tempesta_client.hh"

namespace po = boost::program_options;

enum class Command {
	Push,
	Fetch,
	Reload,
	Unknown
};

constexpr Command cmd_to_enum(std::string_view s)
{
	using namespace std::literals;
	if (s == "push"sv)
		return Command::Push;
	else if (s == "fetch"sv)
		return Command::Fetch;
	else if (s == "reload"sv)
		return Command::Reload;
	return Command::Unknown;
}

enum ExitCode {
	Ok		= 0, // Program finished successfully
	Error		= 1, // General execution error
	UsageError	= 2  // Usage error: show help to the user
};

std::string
read_file(const std::string &path)
{
	std::ifstream file(path);
	if (!file.is_open())
		throw Except("Failed to open {}", path);

	std::string res;
	for (std::string line; std::getline(file, line); )
		res += line + "\n";

	return res;
}

void
print_help(std::string_view command, const po::options_description& global_opts,
	   const po::options_description& cmd_opts)
{
	std::cout << "Usage:\n"
		  << "  tfw <command> [command options] [global options]\n\n";

	if (command.empty()) {
		std::cout << "Commands:\n"
			  << "  push      send data to server (--conf <file>, "
			  << "--conf-inline <config>, --patch <file>, "
			  << "--patch-inline <patch>, --tl <program>)\n"
			  // << "  fetch     fetch data from server (-c, -o)\n" TODO: #77
			  << "  reload    reload server config and geolocation DB\n\n";
	}
	else {
		std::cout << "Options for command '" << command << "':\n"
			  << cmd_opts << "\n";
	}

	std::cout << global_opts << std::endl;
}

po::options_description
get_global_options()
{
	po::options_description global("Global options");
	global.add_options()
		("help,h", "show this message and exit")
		("debug,d", po::bool_switch()->default_value(false),
		"run in debugging mode")
		("server,s", po::value<std::string>()->default_value("127.0.0.1"),
		"server address to connect to")
		("port,p", po::value<uint16_t>()->default_value(50051),
		"server port");
	return global;
}

po::options_description
get_command_options(std::string_view command)
{
	po::options_description cmd_opts("");

	switch(cmd_to_enum(command)) {
	case Command::Push:
		cmd_opts.add_options()
			("conf,c", po::value<std::string>(),
			"сonfiguration file to push to the server")
			("conf-inline", po::value<std::string>(),
			"configuration provided inline to push to the server")
			("patch,P", po::value<std::string>(),
			"configuration patch file to push to the server")
			("patch-inline", po::value<std::string>(),
			"configuration diff provided inline to push to the server")
			("tl", po::value<std::string>(),
			"TL program provided inline to push to the server");
		return cmd_opts;
	case Command::Fetch:
		// TODO: #77
		throw Except("Fetch command is not implemented yet");
		cmd_opts.add_options()
			("conf,c", "Fetch configuration from server")
			("output,o", po::value<std::string>(),
			"Path to output file (default: stdout)");
		return cmd_opts;
	case Command::Reload:
		// reload doesn't need any options for now, but we may add them later
		// cmd_opts.add_options()
		//	("geo", "Reload only rules containing geo-names")
		//	("all,a", "Reload all configuration stored on the server (default)");
		return cmd_opts;
	case Command::Unknown:
		throw Except("Unknown or missing command: {}", command);
	default:
		std::unreachable();
	}
}

int
push_data(const po::variables_map &vm)
{
	const char* opts[] = {"conf", "tl", "conf-inline", "patch", "patch-inline"};

	size_t opt_cnt = std::count_if(std::begin(opts), std::end(opts),
                [&](const auto& opt){ return vm.count(opt); });

	if (opt_cnt != 1) {
		std::cerr << "Exactly one of --conf, --conf-inline, --tl, --patch, "
			     "--patch-inline options must be specified\n";
		return ExitCode::UsageError;
	}

	std::unique_ptr<TlProgConf> conf;
	if (vm.count("conf")) {
		std::string prog = read_file(vm["conf"].as<std::string>());
		conf.reset(tcl_parse_full_conf(prog.c_str(), prog.size()));
	}
	if (vm.count("conf-inline")) {
		std::string prog = vm["conf-inline"].as<std::string>();
		conf.reset(tcl_parse_full_conf(prog.c_str(), prog.size()));
	}
	if (vm.count("patch")) {
		std::string prog = read_file(vm["patch"].as<std::string>());
		conf.reset(tcl_parse_patch_conf(prog.c_str(), prog.size()));
	}
	if (vm.count("patch-inline")) {
		std::string prog = vm["patch-inline"].as<std::string>();
		conf.reset(tcl_parse_patch_conf(prog.c_str(), prog.size()));
	}
	if (vm.count("tl")) {
		std::string prog = vm["tl"].as<std::string>();
		conf.reset(tcl_parse_tl(prog.c_str(), prog.size()));
	}

	if (!conf)
		throw Except("Can't load configuration source: {}", tcl_error_str());

	// Compile the read TL program, if any.
	if (tcl_tl_compile(conf.get()))
		throw Except("{}", tcl_error_str());

	Client client(vm);
	if (client.send_configuration(*conf) != 0)
		return ExitCode::Error;

	return ExitCode::Ok;
}

int
fetch_data(const po::variables_map &vm)
{
	//Client client(vm);
	//TODO #77
	return ExitCode::Ok;
}

int
reload_data(const po::variables_map &vm)
{
	Client client(vm);
	return client.send_reload() == 0 ? ExitCode::Ok: ExitCode::Error;
}

int
main(int argc, char **argv)
{
	if (argc < 2) {
		std::cerr << "Error: command or --help is required" << std::endl;
		return ExitCode::UsageError;
	}

	try {
		const std::string_view first_arg = argv[1];
		po::options_description global_opts = get_global_options();

		if (first_arg == "--help" || first_arg == "-h") {
			print_help("", global_opts, po::options_description{});
			return ExitCode::Ok;
		}

		auto cmd_opts = get_command_options(first_arg);

		po::options_description all_opts;
		all_opts.add(global_opts).add(cmd_opts);

		po::variables_map vm;
		po::store(po::parse_command_line(argc - 1, argv + 1, all_opts), vm);
		po::notify(vm);

		if (vm["debug"].as<bool>()) {
#ifdef NDEBUG
			std::cerr << "Warning: Debug messaging will be disabled. "
				<< "Please, compile w/o NDEBUG option."
				<< std::endl;
#else
			tcl_debug(true);
#endif
		}

		if (vm.count("help")) {
			print_help(first_arg, global_opts, cmd_opts);
			return ExitCode::Ok;
		}

		int res = 0;
		switch(cmd_to_enum(first_arg)) {
		case Command::Push:
			res = push_data(vm);
			break;
		case Command::Fetch:
			res = ExitCode::UsageError; // TODO: #77
			break;
			res = fetch_data(vm);
			break;
		case Command::Reload:
			res = reload_data(vm);
			break;
		case Command::Unknown:
			res = ExitCode::UsageError;
			break;
		};

		if (res == ExitCode::UsageError) {
			print_help(first_arg, global_opts, cmd_opts);
			return res;
		}

		return res;
	}
	catch (const po::error &e) {
		// Handle all Boost.Program_options-related errors
		std::cerr << "Command line error: " << e.what() << "\n";
		std::cerr << "Use --help to see valid options." << std::endl;
		return ExitCode::UsageError;
	}
	catch (Exception &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return ExitCode::Error;
	}
	catch (std::exception &e) {
		std::cerr << "Unhandled error: " << e.what() << std::endl;
		return ExitCode::Error;
	}
}
