/**
 *	API for section with name "ip_proto"
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "tcl_private.hh"
#include "section.hh"

struct IpProtoSection final: public Section
{
public:
	IpProtoSection(XfwConf &conf);
	virtual ~IpProtoSection() override = default;

private:
	virtual void commit() override;

	virtual std::string get_path() const override;

	virtual std::pair<bool, std::shared_ptr<LineConsumer>>
	process_body() override;

private:
	XfwConf 			&conf_;
	std::optional<IpProtoRule>	ip_proto_;
};
