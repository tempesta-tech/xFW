/*
 *	Tempesta xFW module interfaces
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <boost/core/noncopyable.hpp>
#include <optional>

#include "configuration.hh"
#include "maps_manager.hh"
#include "geoip.hh"

class Xfw : private boost::noncopyable
{
public:
	Xfw(std::optional<std::string> &&geodb_path);
	~Xfw() =default;

	/**
	 * Returns full original configuration without resolved geo-names.
	 */
	const std::optional<XfwConfig>&
	get_config() const noexcept
	{
		return config_;
	}

	/**
	 * Save the provided config to the BPF map, then save that
	 * config as the active one for use in future updates or geo reloads.
	 *
	 * We can't guarantee that the data saved in BPF is fully valid,
	 * because certain errors prevent us from performing a proper rollback.
	 * That's why we apply the whole configuration.
	 *
	 * During this operation geo-addresses will be reloaded.
	 */
	void set_config(XfwConfig &&config);

	/**
	 * Convert geoip rules to ip4/ip6 format and enriches ip4/ip6 fields.
	 */
	void load_geo_entry(XfwConfig::NetGeo &entry, bool includeIp4,
		bool includeIp6) const;

	/** (Re)load GeoIP database from stored path. */
	void
	reload_geodb_if_present()
	{
		if (!geodb_path_.has_value()) {
			TE_INF("GeoDB not set, nothing to load");
			return;
		}

		geodb_.reload(*geodb_path_);
	}

	void
	reload_config_if_present()
	{
		if (!config_.has_value()) {
			TE_INF("There is no config to reload\n");
			return;
		}

		set_config(XfwConfig(config_.value()));
	}

private:
	Country2IpMap				geodb_;
	BpfMapsManager				maps_manager_;
	std::optional<XfwConfig>		config_;
	const std::optional<std::string>	geodb_path_;
};
