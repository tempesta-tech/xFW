/**
 *	Tempesta management daemon
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../lib/error.hh"
#include "../lib/log.hh"
#include "../fw/libtus/pidfile.hh"
#include "server.hh"
#include "shutdown.hh"
#include "xfw/xfw.hh"

#include <boost/program_options.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio.hpp>

#include <thread>
#include <string>
#include <memory>
#include <experimental/scope>
#include <signal.h>

namespace po = boost::program_options;
namespace net = boost::asio;

/* Number of threads in which asio io_context will be run */
static constexpr const unsigned thread_pool_num = 2;

/*
 * Note that this "signal handler" called not in signal handler context, but
 * in asio worker thread context where it posted by signal handler as work
 */
void
sig_handler(const boost::system::error_code& ec, int sig_num)
{
	if (ec)
		return;

	TE_DBG("received signal {}", sig_num);
	request_shutdown();
}

int
main(int argc, char* argv[])
{
	std::optional<std::experimental::scope_exit<decltype(&te::log_deinit)>> log_guard;
	try {
		bool foreground = false;
		uint16_t port = 50051;
		uint16_t http_port = 9090;
		std::string listen = "127.0.0.1";
		std::string geoip;
		std::string logfile = "/var/log/tempesta/manager.log";
		std::string pidfile = "/var/run/tempesta_mgr.pid";
		po::options_description desc("Usage: tempesta_mgr [options]");
		desc.add_options()
			("listen,l", po::value<std::string>(&listen)->default_value(
				listen),
			"address to listen on")
			("port,p", po::value<uint16_t>(&port)->default_value(port),
			"grpc port to listen on")
			("http-port", po::value<uint16_t>(&http_port)->default_value(
				http_port),
			"http port to listen on")
			("geoip,G", po::value<std::string>(&geoip),
			"path to a GeoIP database file")
			("log,L", po::value<std::string>(&logfile)->default_value(
				logfile),
			"path to a log-file")
			("pidfile,P", po::value<std::string>(&pidfile)->default_value(
				pidfile),
			"path to a pid-file")
			("help,h", "show this message and exit")
			("foreground,f", po::bool_switch(&foreground)->default_value(
				false),
			"run in debugging mode")
			;

		// Parse config options.
		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return EXIT_SUCCESS;
		}

		// Check configuration.
		if (logfile.empty() || logfile[0] != '/')
			throw Except("the directory path must be absolute for log");

		if (geteuid() != 0) {
			std::cerr << "Please run the daemon as root" << std::endl;
			return EXIT_FAILURE;
		}

		if (!foreground) {
			if (daemon(0, 0) < 0)
				throw Except("Daemonization failed");
		}

		te::log_init(logfile);
		//From here we have to use TE_INF or TE_ERR macros for tracing
		log_guard.emplace(te::log_deinit);

		int pidfile_fd = -1;
		if (!pidfile.empty()) {
			int ret = pidfile_check(pidfile);
			if (ret < 0)
				throw Except("PID file checking failed on ", pidfile);

			pidfile_fd = pidfile_create(pidfile);
			if (pidfile_fd < 0)
				throw Except("Failed to open manager PID file ", pidfile);
		}

		auto pidGuard = std::experimental::scope_exit([&]{
			pidfile_remove(pidfile, pidfile_fd);
		});

		TE_INF("XFW daemon is running");

		net::thread_pool pool(thread_pool_num);
		net::any_io_executor exe = pool.get_executor();
		net::signal_set signals(exe);
		signals.add(SIGTERM);
		signals.add(SIGHUP);
		signals.add(SIGINT);
		signals.add(SIGQUIT);
		signals.add(SIGPIPE);
		signals.add(SIGUSR1);
		signals.add(SIGUSR2);
		signals.async_wait(sig_handler);

		//Can throw during MapsManager construct
		auto server = std::make_shared<TMServer>(exe, vm);
		server->start();

		wait_for_shutdown();

		server->stop();

		pool.stop();
		pool.join();

		return EXIT_SUCCESS;
	}
	catch (const po::error &e) {
		// Handle all Boost.Program_options-related errors
		if (log_guard.has_value()) {
			TE_ERR("Command line error: {}", e.what());
			TE_ERR("Use --help to see valid options");
		}
		else {
			std::cerr << "Command line error: " << e.what() << std::endl;
			std::cerr << "Use --help to see valid options" << std::endl;
		}
		return EXIT_FAILURE;
	}
	catch (const boost::system::system_error& e) {
		if (log_guard.has_value())
			TE_ERR("Error occured: {}", e.what());
		else
			std::cerr << "Error occured: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch (const Exception &e) {
		if (log_guard.has_value())
			TE_ERR("Exception happen: {}", e.what());
		else
			std::cerr << "Exception happen: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch (const std::exception &e) {
		if (log_guard.has_value())
			TE_ERR("Unhandled exception: {}", e.what());
		else
			std::cerr << "Unhandled error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
}
