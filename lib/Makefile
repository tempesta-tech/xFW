#	Tempesta Management LIB
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

SUBDIRS := proto cli t

build: $(SUBDIRS)

.PHONY: $(SUBDIRS)

proto:
	@$(MAKE) -C proto build

cli: proto
	@$(MAKE) -C cli build

t: cli
	@$(MAKE) -C t build

clean: FORCE
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
		$(MAKE) -C $$dir clean; \
	done

install:
	@for dir in $(SUBDIRS); do \
		echo "Installing $$dir..."; \
		$(MAKE) -C $$dir install; \
	done

test:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir test; \
	done

FORCE:
