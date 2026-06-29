/**
 *	Tempesta Incident Log Plugin Api
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The entire architecture is defined in the BPF map file: incident_log_maps.h.
 */

#include "../../fw/logger/plugin_interface.hh"
#include "../../fw/logger/clickhouse/clickhouse_with_reconnect.hh"
#include "../../fw/logger/clickhouse/lazy_init_clickhouse.hh"

#include "incident_log_processor.hh"

namespace {

TfwLoggerPluginApi plugin_api = {
	.version		= TFW_PLUGIN_VERSION,
	.name			= "incident_log",
	.init			= nullptr,
	.done			= nullptr,
	.create_processor	= nullptr,
	.destroy_processor	= nullptr,
	.has_stopped		= nullptr,
	.request_stop		= nullptr,
	.consume		= nullptr,
	.send			= nullptr
};

int
plugin_init(StopFlag* stop_flag)
{
	return 0;
}

void
plugin_done(void)
{
}

ProcessorInstance
plugin_create_processor(const PluginConfigApi *config, unsigned cpu_id)
{
	assert(config);

	try {
		spdlog::debug("Creating IncidentLogProcessor for CPU: {}", cpu_id);

		ch::ClientOptions options;
		options.SetHost(config->host)
		       .SetPort(config->port)
		       .SetDefaultDatabase(config->db_name)
		       .SetUser(config->user)
		       .SetPassword(config->password);

		auto factory = [opts = std::move(options)]() -> LazyInitClickhouse::Ptr {
			return std::make_unique<ClickhouseWithReconnection>(opts);
		};

		// We are creating a ClickHouse instance here, but later we might
		// decide to share a single instance per CPU across all processors.
		// Passing the ClickHouse instance from outside would save resources:
		// instead of Ncpu * Mplugins workers, we would have just Ncpu workers.
		auto writer = std::make_unique<LazyInitClickhouse>(factory);

		auto processor = std::make_unique<IncidentLogProcessor>(cpu_id,
			std::move(writer), config->table_name, config->max_events);

		return processor.release();
	}
	catch (const Exception &e) {
		spdlog::error("Failed to create IncidentLogProcessor: {}", e.what());
	}
	catch (const std::exception& e) {
		spdlog::error("Failed to create IncidentLogProcessor: {}", e.what());
	}

	return nullptr;
}

void
plugin_destroy_processor(ProcessorInstance processor)
{
	if (!processor)
		return;

	std::unique_ptr<IncidentLogProcessor> p(
		static_cast<IncidentLogProcessor*>(processor));

	spdlog::debug("Destroyed IncidentLogProcessor instance");
}

int
plugin_has_stopped(ProcessorInstance processor)
{
	assert(!!processor);
	auto* p = static_cast<IncidentLogProcessor*>(processor);
	return p->has_stopped();
}

void
plugin_request_stop(ProcessorInstance processor)
{
	assert(!!processor);
	auto* p = static_cast<IncidentLogProcessor*>(processor);
	return p->request_stop();
}

int
plugin_consume(ProcessorInstance processor, size_t *cnt)
{
	assert(!!processor);
	auto* p = static_cast<IncidentLogProcessor*>(processor);
	return p->consume(cnt);
}

int
plugin_send(ProcessorInstance processor, bool force)
{
	assert(!!processor);
	auto* p = static_cast<IncidentLogProcessor*>(processor);
	return p->send(force);
}

void
plugin_populate_api()
{
	plugin_api.init			= plugin_init;
	plugin_api.done			= plugin_done;
	plugin_api.create_processor	= plugin_create_processor;
	plugin_api.destroy_processor	= plugin_destroy_processor;
	plugin_api.has_stopped		= plugin_has_stopped;
	plugin_api.request_stop		= plugin_request_stop;
	plugin_api.consume		= plugin_consume;
	plugin_api.send			= plugin_send;
}

} // anonymous namespace

extern "C" TfwLoggerPluginApi* get_plugin_api(void)
{
	plugin_populate_api();
	return &plugin_api;
}
