#	Tempesta xFW global build
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

Q := $(if $(V),,@)
BUILD_DIR := $(CURDIR)/BUILD
BUILD_BINDIR := $(BUILD_DIR)/bin
BUILD_SBINDIR := $(BUILD_DIR)/sbin
BUILD_LIBDIR := $(BUILD_DIR)/lib
BUILD_INCLUDE := $(BUILD_DIR)/include

# Instalation paths
# PREFIX: installation root inside the package or system.
# DESTDIR: temporary root for packaging (used with make install).
PREFIX ?= /opt/tempesta
BINDIR ?= $(DESTDIR)${PREFIX}/bin
SBINDIR ?= $(DESTDIR)${PREFIX}/sbin
LIBDIR ?= $(DESTDIR)${PREFIX}/lib
INCLUDEDIR ?= $(DESTDIR)${PREFIX}/include

CC	:= clang-19
CXX	:= clang++-19
CFLAGS	:= -Wall
LDFLAGS	:= -lfmt -lboost_program_options

DEBUG ?= 0
# -fdebug-prefix-map=$(PWD)=. flag replaces absolute file paths in debug
# information with relative paths, making the debug symbols portable and easier
# to share between different environments.
ifeq ($(DEBUG), 0)
	CFLAGS += -O3 -DNDEBUG
else ifeq ($(DEBUG), 1)
	# This option is useful for multi-thread tests debugging.
	CFLAGS += -DDEBUG=1 -DXFW_DEBUG=1 -O0 -ggdb3 -fdebug-prefix-map=$(PWD)=.
else
	# Tempesta DB debugging is printed on the level >=2
	CFLAGS += -DDEBUG=3 -DXFW_DEBUG=1 -O0 -ggdb3 -fdebug-prefix-map=$(PWD)=.
endif

CXXFLAGS := $(CFLAGS) -std=c++23

JOBS ?= $(shell grep -c ^processor /proc/cpuinfo)
MAKEFLAGS += --jobs=$(JOBS)

export CXX CC CXXFLAGS CFLAGS LDFLAGS INCLUDES MAKEFLAGS BUILD_DIR Q
export BINDIR SBINDIR LIBDIR INCLUDEDIR BUILD_LIBDIR BUILD_BINDIR BUILD_SBINDIR BUILD_INCLUDE

.PHONY: all help build install clean test clang-format print-all

.SUFFIXES:

all: clang-format build

help:
	@echo "Usage: make <target>. Available targets:"
	@echo
	@echo " * 'all'		- Build all Tempesta xFW modules (default)"
	@echo " * 'build'	- build all Tempesta xFW modules"
	@echo " * 'install'	- Install binaries and documents to system locations"
	@echo " * 'test'	- Execute unit tests"
	@echo " * 'clean'	- Clean artifacts"
	@echo " * 'help'	- Show this help message"
	@echo " * 'print-all'	- Print out all makefile variables computed in runtime"

SUBDIRS := lib cli manager bpf logger

.PHONY: $(SUBDIRS) prepare_dirs

build: $(SUBDIRS)

prepare_dirs:
	@mkdir -p $(BUILD_BINDIR) $(BUILD_SBINDIR) $(BUILD_LIBDIR) $(BUILD_INCLUDE)

lib: | prepare_dirs
	@$(MAKE) -C $@ build

cli: lib | prepare_dirs
	@$(MAKE) -C $@ build

manager: lib | prepare_dirs
	@$(MAKE) -C $@ build

$(BUILD_DIR)/vmlinux.h: | prepare_dirs
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf: $(BUILD_DIR)/vmlinux.h | prepare_dirs
	@$(MAKE) -C bpf build

# NOTE: The logger and all its dependencies are built with g++
logger: | prepare_dirs
	@$(MAKE) -C $@ build

clang-format:
 	#find . -name '*.cc' -o -name '*.c' -o -name '*.h' -o -name '*.hh' | xargs clang-format -i

clean: FORCE
	@rm -rf $(BUILD_DIR)
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
		$(MAKE) -C $$dir clean; \
	done

install:
	@echo "Installing executables to $(BINDIR)"
	@install -d -m 755 ${BINDIR} ${SBINDIR} ${LIBDIR} ${INCLUDEDIR}
	install -m 755 xfwctl $(BINDIR)
	@for dir in $(SUBDIRS); do \
		echo "Installing $$dir..."; \
		$(MAKE) -C $$dir install; \
	done

test:
	@$(foreach dir,$(SUBDIRS),$(MAKE) -C $(dir) test || exit 1)

FORCE:

print-all:
	@$(foreach V,$(sort $(.VARIABLES)),\
		$(if $(filter-out environment% default automatic,$(origin $V)),\
			$(info $V=$($V))))
