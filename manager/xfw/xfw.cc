/**
 *	Tempesta xFW management
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "xfw.hh"
#include "../../lib/error.hh"
namespace {

template<typename R>
R
readline(const char *path)
{
	std::ifstream fs{path};
	if (!fs)
		throw Except("Unable to read sysctl value from ", path);

	R r{};
	fs >> r;

	return r;
}

} // anonymous namespace

Xfw::Xfw(std::optional<std::string> &&geodb_path)
	: geodb_path_(std::move(geodb_path))
{
	reload_geodb_if_present();

	if (!readline<int>("/proc/sys/net/ipv4/tcp_syncookies"))
		throw Except("Enable net.ipv4.tcp_syncookies before using "
		             "the SYN-cookie filter");
}

void
Xfw::load_geo_entry(XfwConfig::NetGeo &entry, bool includeIp4, bool includeIp6) const
{
	if (geodb_.empty())
		throw Except("GeoIP filter rules require a loaded GeoIP database");

	entry.net4s_.clear();
	entry.net6s_.clear();

	const IsoCountryId country{
		std::string_view{entry.code_str_, sizeof(entry.code_str_)}
	};
	auto country_ips = geodb_.lookup(country);
	if (!country_ips)
		throw Except("GeoIP database has no networks for country '{}'",
			     entry.code());

	if (includeIp4) {
		entry.net4s_.reserve(country_ips->ip4.size());
		std::transform(country_ips->ip4.begin(), country_ips->ip4.end(),
			std::back_inserter(entry.net4s_), [](const Net4Geo &x) {
				return XfwConfig::Net4Key{{x.prefixlen_}, x.addr_};
			});
	}

	if (includeIp6) {
		entry.net6s_.reserve(country_ips->ip6.size());
		std::transform(country_ips->ip6.begin(), country_ips->ip6.end(),
			std::back_inserter(entry.net6s_), [](const Net6Geo &x) {
				return XfwConfig::Net6Key {
					{x.prefixlen_},
					{ x.addr_[0], x.addr_[1], x.addr_[2], x.addr_[3] }
				};
			});
	}

	TE_INF("Transformed '{}' geoip code into {} subnets", entry.code(),
		entry.net4s_.size() + entry.net6s_.size());
}

/*
 * Configuration is applied per subsystem.
 *
 * Each subsystem is updated using inactive BPF maps and becomes effective
 * only after an atomic switch of active maps inside that subsystem.
 *
 * Ratelimits are handled with a separate staged lifecycle:
 * new ratelimits are installed before subsystem commits, and old inactive
 * ratelimits are removed only after the full configuration update succeeds.
 */
 /* TODO #4:
 * set_config() is NOT transactional across subsystems.
 *
 * This means that if a failure happens in a later subsystem update,
 * earlier subsystems may already be committed to the kernel state.
 *
 * Example:
 *	- src rules successfully committed to kernel state
 *  	- dst rules update fails
 *
 * Result:
 *	- kernel state contains new src rules
 *	- kernel state contains old dst rules
 *	- userspace configuration (config_) is still old because the full
 * update did not complete
 *
 * Therefore userspace config_ may diverge from kernel state in case of
 * partial failure.
 *
 * IMPORTANT:
 * To keep userspace consistent with kernel state, config_ should be
 * updated after each successful subsystem commit, not only at the end.
 */
void
Xfw::set_config(XfwConfig &&config)
{
	// TODO #4:
	// Save successfully applied ratelimits into config_ immediately after
	// not throwing set_ratelimits.
	maps_manager_.set_ratelimits(config.ratelimits_);

	// TODO #4:
	// Persist remaining successfully applied simple rules into config_
	// immediately after not throwing set_simple_rules.
	maps_manager_.set_simple_rules(config);
	
	// TODO #4:
	// Persist successfully applied src rules and corresponding defaults
	// into config_ immediately after not throwing set_src_rules.
	maps_manager_.set_src_rules(config.src_rules_, config.defaults_);

	// TODO #4:
	// Persist successfully applied icmp rules and corresponding defaults
	// into config_ immediately after not throwing set_icmp_rules.
	maps_manager_.set_icmp_rules(config.icmp_rules_, config.defaults_);

	// TODO #4:
	// Persist successfully applied dst rules and corresponding defaults
	// into config_ immediately after not throwing set_dst_rules.
	maps_manager_.set_dst_rules(config.dst_rules_, config.defaults_);

	// TODO #4:
	// Persist successfully applied protected net settings into config_
	// immediately after not throwing set_prot_net_settings.
	maps_manager_.set_prot_net_settings(config.prot_net_);

	// TODO #4:
	// Persist successfully applied TCP RST flag filter into config_
	// immediately after not throwing set_tcp_flag_rule.
	maps_manager_.set_tcp_flag_rule(config.tcp_rst_flag_filter_, XFW_FLAGS_FILTER_RST);

	// TODO #4:
	// Persist successfully applied TCP SYN flag filter into config_
	// immediately after not throwing set_tcp_flag_rule.
	maps_manager_.set_tcp_flag_rule(config.tcp_syn_flag_filter_, XFW_FLAGS_FILTER_SYN);

	// TODO #4:
	// Persist successfully applied TCP anomaly filter into config_
	// immediately after not throwing set_tcp_anomaly_rule.
	maps_manager_.set_tcp_anomaly_rule(config.anomaly_filter_);

	if (!config_.has_value())
		maps_manager_.turn_filtration_on();

	// At this point all kernel updates completed successfully,
	// so we can safely replace the full userspace configuration.
	// TODO #4: remove this line. All assignment has to be finished before.
	config_ = std::move(config);

	// Removes ratelimits explicitly marked for deletion during update.
	//
	// IMPORTANT:
	// Cleanup must happen only AFTER all subsystems successfully switched
	// to the new ratelimit configuration. Otherwise partially updated
	// subsystems may still reference old ratelimit entries.
	config_->ratelimits_.free_inactive();
}
