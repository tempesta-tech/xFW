/**
 *	Tempesta xFW gateway SYN proxy runtime configuration
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <experimental/scope>
#include <fstream>
#include <limits>
#include <sstream>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "../../bpf_uapi/map_names.h"
#include "../../bpf_uapi/synproxy.h"
#include "../../lib/fd_guard.hh"
#include "../../lib/log.hh"
#include "../xfw_update_error.hh"
#include "maps_manager.hh"
#include "synproxy.hh"

extern char **environ;

namespace {

using Tree = boost::property_tree::ptree;
using Scope = XfwConfig::SynproxyFilter;
using Selector = XfwConfig::SynproxySelector;
const std::string state_dir = "/run/tempesta/xfw/synproxy/";
const std::string state_path = state_dir + "state.json";
const std::string pending_path = state_dir + "pending.json";

bool
exists(const std::string &path)
{
	struct stat info;
	if (lstat(path.c_str(), &info) == 0)
		return true;
	verify(errno == ENOENT, "Unable to inspect SYN-proxy state {}", path);
	return false;
}

uint64_t
now_ns()
{
	return std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

FdGuard
lock_lifecycle()
{
	FdGuard fd(open("/run/tempesta/xfw/synproxy.lock",
			O_RDWR | O_CLOEXEC | O_NOFOLLOW));
	struct stat info;
	verify(fstat(fd.get(), &info) == 0 && S_ISREG(info.st_mode)
	       && info.st_uid == 0 && !(info.st_mode & 0022),
	       "Unsafe SYN-proxy lifecycle lock");
	verify(flock(fd.get(), LOCK_EX | LOCK_NB) == 0,
	       "SYN-proxy lifecycle operation is already in progress");
	return fd;
}

void
write_all(int fd, const std::string &text)
{
	size_t offset = 0;
	while (offset < text.size()) {
		ssize_t written = write(fd, text.data() + offset, text.size() - offset);
		if (written < 0 && errno == EINTR)
			continue;
		verify(written > 0, "Unable to write SYN-proxy configuration");
		offset += written;
	}
}

Tree
read_json_file(const std::string &path)
{
	FdGuard fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW), path);
	struct stat info;
	verify(fstat(fd.get(), &info) == 0 && S_ISREG(info.st_mode)
	       && info.st_uid == 0 && !(info.st_mode & 0077)
	       && info.st_size <= 4 * 1024 * 1024,
	       "Unsafe SYN-proxy state file {}", path);
	std::string text;
	char buffer[4096];
	ssize_t count;
	while ((count = read(fd.get(), buffer, sizeof(buffer))) != 0) {
		if (count < 0 && errno == EINTR)
			continue;
		verify(count > 0, "Unable to read SYN-proxy state {}", path);
		text.append(buffer, count);
		verify(text.size() <= 4 * 1024 * 1024, "SYN-proxy state is too large");
	}
	Tree tree;
	std::istringstream input(text);
	boost::property_tree::read_json(input, tree);
	return tree;
}

void
save_json(const std::string &path, const Tree &tree)
{
	std::ostringstream text;
	boost::property_tree::write_json(text, tree, false);
	const std::string temporary = path + ".tmp";
	unlink(temporary.c_str());
	FdGuard fd(open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL
			 | O_CLOEXEC | O_NOFOLLOW, 0600), temporary);
	write_all(fd.get(), text.str());
	verify(fsync(fd.get()) == 0 && rename(temporary.c_str(), path.c_str()) == 0,
	       "Unable to commit SYN-proxy state {}", path);
}

std::string
nft(const std::string &input, bool list = false)
{
	FdGuard source(memfd_create("xfw-synproxy-nft", MFD_CLOEXEC));
	write_all(source.get(), input);
	verify(lseek(source.get(), 0, SEEK_SET) == 0, "Unable to rewind nft input");
	int descriptors[2];
	verify(pipe2(descriptors, O_CLOEXEC) == 0, "Unable to capture nft output");
	FdGuard reader(descriptors[0]);
	std::optional<FdGuard> writer(std::in_place, descriptors[1]);
	posix_spawn_file_actions_t actions;
	verify(posix_spawn_file_actions_init(&actions) == 0, "Unable to initialize nft process");
	int error = posix_spawn_file_actions_adddup2(&actions, source.get(), STDIN_FILENO);
	error = error ?: posix_spawn_file_actions_adddup2(&actions, writer->get(), STDOUT_FILENO);
	error = error ?: posix_spawn_file_actions_adddup2(&actions, writer->get(), STDERR_FILENO);
	char *apply_args[] = {const_cast<char *>("nft"), const_cast<char *>("-f"),
		const_cast<char *>("-"), nullptr};
	char *list_args[] = {const_cast<char *>("nft"), const_cast<char *>("-j"),
		const_cast<char *>("list"), const_cast<char *>("table"),
		const_cast<char *>("inet"), const_cast<char *>("xfw_synproxy"), nullptr};
	pid_t child = -1;
	if (!error)
		error = posix_spawn(&child, "/usr/sbin/nft", &actions, nullptr,
			list ? list_args : apply_args, environ);
	posix_spawn_file_actions_destroy(&actions);
	verify(error == 0, "Unable to execute nft: {}", std::strerror(error));
	bool exited = false;
	auto process_guard = std::experimental::scope_exit([&] {
		if (!exited) {
			kill(child, SIGKILL);
			while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
		}
	});
	/* Close the parent's writer so EOF is observable after the child exits. */
	writer.reset();
	verify(fcntl(reader.get(), F_SETFL, O_NONBLOCK) == 0,
	       "Unable to configure nft output capture");
	std::string output;
	bool eof = false, excessive = false;
	int status = 0;
	uint64_t deadline = now_ns() + 10000000000ULL;
	while (!exited || !eof) {
		char buffer[4096];
		ssize_t count;
		while ((count = read(reader.get(), buffer, sizeof(buffer))) > 0) {
			if (output.size() + count <= 8 * 1024 * 1024)
				output.append(buffer, count);
			else
				excessive = true;
		}
		eof = count == 0;
		if (!exited)
			exited = waitpid(child, &status, WNOHANG) == child;
		if (exited && eof)
			break;
		if (now_ns() >= deadline) {
			throw UpdateError("nft operation timed out; SYN-proxy journal requires reconciliation");
		}
		pollfd event{reader.get(), POLLIN, 0};
		poll(&event, 1, 50);
	}
	verify(!excessive && WIFEXITED(status) && WEXITSTATUS(status) == 0,
	       "nft SYN-proxy operation failed: {}", output);
	return output;
}

Tree
prepared()
{
	struct stat directory, netns;
	verify(lstat(state_dir.c_str(), &directory) == 0 && S_ISDIR(directory.st_mode)
	       && directory.st_uid == 0 && !(directory.st_mode & 0077),
	       "SYN-proxy preparation directory is unavailable or unsafe");
	Tree tree = read_json_file(state_dir + "prepared.json");
	verify(tree.get<bool>("active"), "SYN-proxy startup capability is inactive");
	verify(tree.get<unsigned>("version") == 1
	       && stat("/proc/self/ns/net", &netns) == 0
	       && tree.get<uint64_t>("netns_inode") == netns.st_ino,
	       "SYN-proxy preparation belongs to a different network namespace");
	std::ifstream boot("/proc/sys/kernel/random/boot_id");
	std::string boot_id;
	std::getline(boot, boot_id);
	verify(!boot_id.empty() && tree.get<std::string>("boot_id") == boot_id,
	       "SYN-proxy preparation belongs to a different boot");
	const auto owner = tree.get<std::string>("owner");
	verify(owner.size() >= 16 && owner.size() <= 128
	       && owner.find_first_not_of("0123456789abcdef") == std::string::npos,
	       "Invalid SYN-proxy ownership token");
	Tree table;
	std::istringstream input(nft({}, true));
	boost::property_tree::read_json(input, table);
	bool owned = false;
	for (const auto &entry : table.get_child("nftables")) {
		auto comment = entry.second.get_optional<std::string>("table.comment");
		if (comment && *comment == "xfw-synproxy:" + owner)
			owned = true;
	}
	verify(owned, "SYN-proxy nft table ownership does not match preparation");
	std::ifstream loose("/proc/sys/net/netfilter/nf_conntrack_tcp_loose");
	int value = -1;
	loose >> value;
	verify(value == 0, "SYN proxy requires nf_conntrack_tcp_loose=0");
	return tree;
}

std::string
address(const Selector &selector)
{
	char buffer[INET6_ADDRSTRLEN];
	verify(inet_ntop(selector.ipv6_ ? AF_INET6 : AF_INET,
		selector.addr_.data(), buffer, sizeof(buffer)), "Invalid SYN-proxy address");
	return buffer;
}

Tree
scope_tree(const Scope &scope)
{
	Tree array;
	for (const auto &selector : scope) {
		Tree entry;
		entry.put("address", address(selector));
		entry.put("ipv6", selector.ipv6_);
		entry.put("prefix", unsigned(selector.prefix_));
		entry.put("port", selector.port_);
		array.push_back({"", entry});
	}
	return array;
}

Scope
read_scope(const Tree &array)
{
	Scope scope;
	for (const auto &item : array) {
		const auto &entry = item.second;
		Selector selector;
		selector.ipv6_ = entry.get<bool>("ipv6");
		unsigned prefix = entry.get<unsigned>("prefix");
		unsigned port = entry.get<unsigned>("port");
		verify(prefix <= (selector.ipv6_ ? 128 : 32) && port <= 65535,
		       "Invalid SYN-proxy state selector");
		selector.prefix_ = prefix;
		selector.port_ = port;
		verify(inet_pton(selector.ipv6_ ? AF_INET6 : AF_INET,
			entry.get<std::string>("address").c_str(), selector.addr_.data()) == 1,
		       "Invalid SYN-proxy state address");
		verify(scope.insert(selector).second, "Duplicate SYN-proxy state selector");
	}
	return scope;
}

Scope
unite(Scope scope, const Scope &other)
{
	scope.insert(other.begin(), other.end());
	return scope;
}

/* nft interval sets require a disjoint union, unlike independent LPM rules. */
Scope
nft_scope(const Scope &scope)
{
	Scope result;
	for (const auto &selector : scope) {
		bool covered = false;
		for (const auto &other : scope) {
			if (other == selector || other.ipv6_ != selector.ipv6_
			    || (other.port_ && other.port_ != selector.port_)
			    || other.prefix_ > selector.prefix_)
				continue;
			bool contains = true;
			for (unsigned bit = 0; bit < other.prefix_; bit += 8) {
				uint8_t mask = uint8_t(0xffU << (8 - std::min(8U,
					unsigned(other.prefix_) - bit)));
				if ((other.addr_[bit / 8] & mask)
				    != (selector.addr_[bit / 8] & mask)) {
					contains = false;
					break;
				}
			}
			if (contains) {
				covered = true;
				break;
			}
		}
		if (!covered)
			result.insert(selector);
	}
	return result;
}

} // anonymous namespace

SynproxyManager::Snapshot
SynproxyManager::read_snapshot(const std::string &path)
{
	Tree tree = read_json_file(path);
	verify(tree.get<unsigned>("version") == 1, "Unsupported SYN-proxy state version");
	Snapshot result;
	result.generation = tree.get<uint64_t>("generation");
	result.retired_until_ns = tree.get<uint64_t>("retired_until_ns");
	result.active = read_scope(tree.get_child("active"));
	result.retired = read_scope(tree.get_child("retired"));
	verify(result.active.size() <= XFW_SYNPROXY_MAX_TARGETS
	       && result.retired.size() <= XFW_SYNPROXY_MAX_RETIRED,
	       "SYN-proxy state exceeds selector limits");
	return result;
}

void
SynproxyManager::save_snapshot(const std::string &path, const Snapshot &snapshot)
{
	Tree tree;
	tree.put("version", 1);
	tree.put("generation", snapshot.generation);
	tree.put("retired_until_ns", snapshot.retired_until_ns);
	tree.add_child("active", scope_tree(snapshot.active));
	tree.add_child("retired", scope_tree(snapshot.retired));
	save_json(path, tree);
}

SynproxyManager::SynproxyManager(BpfMapsManager &maps) : maps_(maps)
{
	int capability = bpf_obj_get("/sys/fs/bpf/xfw/" MAP_SYNPROXY_GEN_STR);
	if (capability < 0) {
		verify(errno == ENOENT, "Unable to inspect SYN-proxy capability");
		return;
	}
	close(capability);
	available_ = true;
	auto lock = lock_lifecycle();
	prepared();
	recover();
}

void
SynproxyManager::validate(const Scope &scope) const
{
	verify(scope.empty() || available_,
	       "tcp_synproxy requires gateway deployment with SYN-proxy startup capability");
	verify(scope.size() <= XFW_SYNPROXY_MAX_TARGETS,
	       "SYN-proxy active selector limit exceeded");
	if (available_ && (scope != active_ || exists(pending_path)
			  || (!retired_.empty() && retired_until_ns_ <= now_ns()))) {
		auto lock = lock_lifecycle();
		prepared();
	}
}

void
SynproxyManager::install_nft(const Scope &scope) const
{
	Tree metadata = prepared();
	Scope effective = nft_scope(scope);
	std::ostringstream batch;
	batch << "add set inet xfw_synproxy ingress { type iface_index; }\n"
	      << "flush set inet xfw_synproxy ingress\n";
	std::string interfaces;
	for (const auto &entry : metadata.get_child("ifindexes")) {
		unsigned index = entry.second.get_value<unsigned>();
		char name[IF_NAMESIZE];
		verify(index && if_indextoname(index, name), "Prepared SYN-proxy interface disappeared");
		interfaces += (interfaces.empty() ? "" : ", ") + std::to_string(index);
	}
	verify(!interfaces.empty(), "SYN-proxy preparation contains no interfaces");
	batch << "add element inet xfw_synproxy ingress { " << interfaces << " }\n";
	for (bool ipv6 : {false, true}) {
		for (bool ports : {false, true}) {
			std::string name = ports ? "ports" : "scope";
			name += ipv6 ? "6" : "4";
			batch << "add set inet xfw_synproxy " << name << " { type "
			      << (ipv6 ? "ipv6_addr" : "ipv4_addr")
			      << (ports ? " . inet_service" : "") << "; flags interval; auto-merge; }\n"
			      << "flush set inet xfw_synproxy " << name << "\n";
			std::string elements;
			for (const auto &selector : effective) {
				if (selector.ipv6_ != ipv6 || bool(selector.port_) != ports)
					continue;
				elements += (elements.empty() ? "" : ", ") + address(selector)
					+ "/" + std::to_string(selector.prefix_);
				if (ports)
					elements += " . " + std::to_string(selector.port_);
			}
			if (!elements.empty())
				batch << "add element inet xfw_synproxy " << name << " { " << elements << " }\n";
		}
	}
	batch << "add chain inet xfw_synproxy ack { type filter hook forward priority -10; policy accept; }\n"
	      << "flush chain inet xfw_synproxy ack\n";
	for (bool ipv6 : {false, true}) {
		for (bool ports : {false, true}) {
			std::string match = "meta iif @ingress meta l4proto tcp ct state invalid ";
			match += ipv6 ? "ip6 daddr" : "ip daddr";
			if (ports)
				match += " . tcp dport";
			match += ports ? " @ports" : " @scope";
			match += ipv6 ? "6" : "4";
			batch << "add rule inet xfw_synproxy ack " << match
			      << " tcp flags & (fin | syn | rst | ack) == ack synproxy name \"handoff\"\n"
			      << "add rule inet xfw_synproxy ack " << match << " drop\n";
		}
	}
	nft(batch.str());
}

void
SynproxyManager::finish(const Snapshot &snapshot)
{
	Snapshot complete = snapshot;
	if (!complete.retired.empty() && complete.retired_until_ns == UINT64_MAX)
		complete.retired_until_ns = now_ns() + XFW_SYNPROXY_GRACE_NS;
	maps_.finish_synproxy(complete.generation, complete.retired_until_ns,
		complete.active.size(), complete.retired.size());
	save_snapshot(state_path, complete);
	generation_ = complete.generation;
	retired_until_ns_ = complete.retired_until_ns;
	active_ = complete.active;
	retired_ = complete.retired;
	install_nft(unite(active_, retired_));
	verify(unlink(pending_path.c_str()) == 0 || errno == ENOENT,
	       "Unable to remove SYN-proxy transaction journal");
}

void
SynproxyManager::recover()
{
	uint64_t generation = maps_.synproxy_generation();
	if (exists(pending_path)) {
		Snapshot pending = read_snapshot(pending_path);
		if (pending.generation == generation) {
			if (exists(state_path)) {
				Snapshot committed = read_snapshot(state_path);
				if (committed.generation == generation) {
					verify(committed.active == pending.active
					       && committed.retired == pending.retired,
					       "SYN-proxy committed state differs from its journal");
					/* Preserve an already finalized retirement deadline. */
					finish(committed);
					return;
				}
			}
			finish(pending);
			return;
		}
		verify(generation != UINT64_MAX && pending.generation == generation + 1,
		       "SYN-proxy journal does not match the loaded dataplane");
	}
	Snapshot committed;
	if (exists(state_path))
		committed = read_snapshot(state_path);
	verify(committed.generation == generation,
	       "SYN-proxy state does not match the loaded dataplane");
	finish(committed);
}

void
SynproxyManager::set_config(const Scope &scope)
{
	if (!available_) {
		verify(scope.empty(), "SYN-proxy startup capability is unavailable");
		return;
	}
	if (scope == active_ && !exists(pending_path)
	    && (retired_.empty() || retired_until_ns_ > now_ns()))
		return;
	auto lock = lock_lifecycle();
	prepared();
	if (exists(pending_path) || maps_.synproxy_generation() != generation_)
		recover();
	Scope retired = retired_until_ns_ > now_ns() ? retired_ : Scope{};
	for (const auto &selector : active_)
		if (!scope.contains(selector))
			retired.insert(selector);
	for (const auto &selector : scope)
		retired.erase(selector);
	verify(scope.size() <= XFW_SYNPROXY_MAX_TARGETS
	       && retired.size() <= XFW_SYNPROXY_MAX_RETIRED,
	       "SYN-proxy selector limit exceeded; wait for retired scope to expire");
	if (scope == active_ && retired == retired_)
		return;
	verify(generation_ != UINT64_MAX, "SYN-proxy generation exhausted");
	Snapshot next{generation_ + 1, retired.empty() ? 0 : UINT64_MAX, scope, retired};
	save_snapshot(pending_path, next);
	install_nft(unite(unite(active_, scope), retired));
	maps_.stage_synproxy(next.generation, next.active, next.retired, next.retired_until_ns);
	maps_.publish_synproxy(next.generation);
	/* Publication commits the policy. Cleanup can be completed after a restart. */
	generation_ = next.generation;
	active_ = next.active;
	retired_ = next.retired;
	retired_until_ns_ = next.retired_until_ns;
	try {
		finish(next);
	} catch (const std::exception &error) {
		TE_ERR("SYN-proxy policy committed; cleanup will be retried: {}", error.what());
	}
}
