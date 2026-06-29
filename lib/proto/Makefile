#	Tempesta Management gRPC implementation
#
# SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

OUTPUT_DIR := BUILD
OBJECTS := $(patsubst %.cc, $(OUTPUT_DIR)/%.o, $(wildcard *.cc))
DEPS := $(OBJECTS:.o=.d)
DEPS += $(OUTPUT_DIR)/proto.grpc.fb.d
CXXFLAGS += -fPIC
LDFLAGS += -lgrpc -lgrpc++ -lflatbuffers
INCLUDES += -I$(BUILD_INCLUDE)

.PHONY: build install clean test

build: $(OUTPUT_DIR)/libproto.so

FLATBUFFERS_SRC := proto.fbs
FLATBUFFERS_CC := $(OUTPUT_DIR)/proto.grpc.fb.cc
FLATBUFFERS_O  := $(OUTPUT_DIR)/proto.grpc.fb.o
FLATBUFFERS_HEADERS := $(BUILD_INCLUDE)/generated/proto.grpc.fb.h $(BUILD_INCLUDE)/generated/proto_generated.hh

.SECONDARY: $(FLATBUFFERS_HEADERS)

$(OUTPUT_DIR)/libproto.so: $(OBJECTS) $(FLATBUFFERS_O)
	$(CXX) $(CXXFLAGS) -shared -o $@ $(OBJECTS) $(OUTPUT_DIR)/proto.grpc.fb.o $(LDFLAGS)
	@mkdir -p $(BUILD_LIBDIR)
	@cp $@ $(BUILD_LIBDIR)

$(OUTPUT_DIR)/%.o: %.cc $(FLATBUFFERS_HEADERS)
	@mkdir -p $(OUTPUT_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP $(INCLUDES) -c $< -o $@

$(FLATBUFFERS_CC) $(addprefix $(OUTPUT_DIR)/, $(notdir $(FLATBUFFERS_HEADERS))) &: $(FLATBUFFERS_SRC)
	@echo "Generating FlatBuffers files..."
	@mkdir -p $(OUTPUT_DIR)
	flatc --cpp --grpc --filename-ext hh -o $(OUTPUT_DIR) $(FLATBUFFERS_SRC)
	@echo "FlatBuffers generation complete."

$(BUILD_INCLUDE)/generated/%: $(OUTPUT_DIR)/%
	@mkdir -p $(BUILD_INCLUDE)/generated
	@cp $< $@

clean: FORCE
	@rm -rf $(OUTPUT_DIR)

install:
	@echo "Installing shared library to $(LIBDIR)"
	install -d $(LIBDIR)
	install -m 755 $(BUILD_LIBDIR)/libproto.so $(LIBDIR)

-include $(DEPS)

test:

FORCE:
