/**
 *	Tempesta Incident Log clickhouse
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The entire architecture is defined in the BPF map file: incident_log_maps.h.
 */
#include <netinet/in.h>
#include <spdlog/spdlog.h>

#include <clickhouse/exceptions.h>

#include "../../fw/libtus/error.hh"
#include "../../fw/logger/plugin_interface.hh"

#include "incident_log_clickhouse.hh"

namespace {
constexpr std::string_view TableCreationQueryTemplate =
	"CREATE TABLE IF NOT EXISTS {} "
	"(timestamp DateTime64(3, 'UTC'),"
	" addr IPv6,"
	" reason UInt64,"
	" packets UInt64,"
	" bytes UInt64,"
	" dropped_events UInt64"
	") ENGINE = MergeTree() ORDER BY timestamp";

constexpr ClickHouseDecorator::TfwField TfwFields[] = {
	{"timestamp", ch::Type::DateTime64},
	{"addr", ch::Type::IPv6},
	{"reason", ch::Type::UInt64},
	{"packets", ch::Type::UInt64},
	{"bytes", ch::Type::UInt64},
	{"dropped_events", ch::Type::UInt64}
};

template <ch::Type::Code Code>
struct TfwFieldType;

template <>
struct TfwFieldType<ch::Type::DateTime64> {
	using type = clickhouse::ColumnDateTime64;
};

template <>
struct TfwFieldType<ch::Type::IPv6> {
	using type = clickhouse::ColumnIPv6;
};

template <>
struct TfwFieldType<ch::Type::UInt64> {
	using type = clickhouse::ColumnUInt64;
};

} // anonymous namespace

IncidentLogClickhouse::IncidentLogClickhouse(
	std::unique_ptr<IClickhouse> client, std::string_view table_name,
	size_t max_events)
		: ClickHouseDecorator(std::move(client), TableCreationQueryTemplate,
				      table_name, TfwFields, max_events)
{
}

void
IncidentLogClickhouse::append_event(
	const in6_addr &key, const IncidentLogStat &value, uint64_t drop_cnt)
try {
	// timestamp
	auto cur_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch()).count();
	block_[0]->As<TfwFieldType<TfwFields[0].code>::type>()->Append(cur_time_ms);

	block_[1]->As<TfwFieldType<TfwFields[1].code>::type>()->Append(key);

	block_[2]->As<TfwFieldType<TfwFields[2].code>::type>()->Append(value.reason);
	block_[3]->As<TfwFieldType<TfwFields[3].code>::type>()->Append(value.packets);
	block_[4]->As<TfwFieldType<TfwFields[4].code>::type>()->Append(value.bytes);
	block_[5]->As<TfwFieldType<TfwFields[5].code>::type>()->Append(drop_cnt);
}
catch (const clickhouse::Error &e) {
	spdlog::error("Failed to append event to CH block: {}", e.what());
}
catch (const std::exception& e) {
	spdlog::error("Failed to append event to CH block: {}", e.what());
}
catch (...) {
	spdlog::error("Failed to append event to CH block: unknown error");
}
