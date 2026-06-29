#	Tempesta Escudo logger
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
CXX := g++

LOGGER_DIR := ../fw/logger
LOGGER_TARGET := tfw_logger

LIBTUS_DIR := ../fw/libtus
LIBTUS_LIB := libtus.so

PLUGIN_DIR := incident_log_plugin

SUBDIRS := $(LIBTUS_DIR) $(LOGGER_DIR) $(PLUGIN_DIR)

.PHONY: $(SUBDIRS)

build: $(SUBDIRS)

$(LIBTUS_DIR):
	@$(MAKE) -C $(LIBTUS_DIR) all
	@cp $(LIBTUS_DIR)/*.so $(BUILD_LIBDIR)

$(LOGGER_DIR): $(LIBTUS_DIR)
	@$(MAKE) -C $(LOGGER_DIR) $(LOGGER_TARGET)
	@cp $(LOGGER_DIR)/$(LOGGER_TARGET) $(BUILD_SBINDIR)

$(PLUGIN_DIR): $(LIBTUS_DIR)
	@$(MAKE) -C $(PLUGIN_DIR) build

clean: FORCE
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
		$(MAKE) -C $$dir clean; \
	done

FORCE:

install:
	$(MAKE) -C $(PLUGIN_DIR) install
	@echo "Installing shared library to $(LIBDIR)"
	install -d $(LIBDIR)
	install -m 755 $(BUILD_LIBDIR)/$(LIBTUS_LIB) $(LIBDIR)
	@echo "Installing executable to $(SBINDIR)"
	install -d $(SBINDIR)
	install -m 755 $(BUILD_SBINDIR)/$(LOGGER_TARGET) $(SBINDIR)

test:
