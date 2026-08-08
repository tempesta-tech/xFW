#	Tempesta xFW tests
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

SUBDIRS := bpf

build: $(SUBDIRS)

.PHONY: $(SUBDIRS)

bpf:
	@$(MAKE) -C bpf build

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
