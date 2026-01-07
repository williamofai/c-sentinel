#
# C-Sentinel - Semantic Observability for UNIX Systems
# Cross-Platform Makefile (Linux, macOS, BSD)
#
# Usage:
#   make              - Build release version
#   make DEBUG=1      - Build with debug symbols
#   make test         - Run tests
#   make clean        - Remove build artifacts
#   make install      - Install to /usr/local/bin
#

# ============================================================
# Platform Detection
# ============================================================

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
    PLATFORM_CFLAGS := -DPLATFORM_MACOS
    PLATFORM_LDFLAGS := 
    # macOS doesn't need -lrt
else ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    PLATFORM_CFLAGS := -DPLATFORM_LINUX
    PLATFORM_LDFLAGS := -lrt
else ifeq ($(UNAME_S),FreeBSD)
    PLATFORM := bsd
    PLATFORM_CFLAGS := -DPLATFORM_BSD
    PLATFORM_LDFLAGS := -lkvm
else ifeq ($(UNAME_S),NetBSD)
    PLATFORM := bsd
    PLATFORM_CFLAGS := -DPLATFORM_BSD
    PLATFORM_LDFLAGS := -lkvm
else ifeq ($(UNAME_S),OpenBSD)
    PLATFORM := bsd
    PLATFORM_CFLAGS := -DPLATFORM_BSD
    PLATFORM_LDFLAGS := -lkvm
else
    $(error Unsupported platform: $(UNAME_S))
endif

# ============================================================
# Compiler Configuration
# ============================================================

CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic -std=c99 $(PLATFORM_CFLAGS)
CFLAGS += -I./include

# macOS may need Clang instead
ifeq ($(PLATFORM),macos)
    CC := clang
    # Suppress some overly pedantic warnings on macOS
    CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
endif

# Debug vs Release
ifdef DEBUG
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

LDFLAGS := $(PLATFORM_LDFLAGS)

# ============================================================
# Project Structure
# ============================================================

SRCDIR := src
INCDIR := include
OBJDIR := obj
BINDIR := bin

# Source files - exclude diff.c (separate utility)
SRCS := $(filter-out $(SRCDIR)/diff.c, $(wildcard $(SRCDIR)/*.c))
OBJS := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Target binaries
TARGET := $(BINDIR)/sentinel
DIFF_TARGET := $(BINDIR)/sentinel-diff

# ============================================================
# Build Rules
# ============================================================

.PHONY: all clean test install uninstall help info

all: info $(TARGET) $(DIFF_TARGET)

info:
	@echo "Building C-Sentinel for $(PLATFORM) ($(UNAME_S))"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo ""

$(TARGET): $(OBJS) | $(BINDIR)
	@echo "Linking $(TARGET)..."
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"
	@ls -lh $(TARGET)

$(DIFF_TARGET): $(OBJDIR)/diff.o $(OBJDIR)/json_serialize.o $(OBJDIR)/sha256.o | $(BINDIR)
	@echo "Linking $(DIFF_TARGET)..."
	$(CC) $(OBJDIR)/diff.o $(OBJDIR)/json_serialize.o $(OBJDIR)/sha256.o -o $@ $(LDFLAGS)
	@echo "Build complete: $(DIFF_TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# ============================================================
# Installation
# ============================================================

PREFIX ?= /usr/local

install: $(TARGET) $(DIFF_TARGET)
	@echo "Installing to $(PREFIX)/bin..."
	install -d $(PREFIX)/bin
	install -m 755 $(TARGET) $(PREFIX)/bin/sentinel
	install -m 755 $(DIFF_TARGET) $(PREFIX)/bin/sentinel-diff
	@echo "Installed: $(PREFIX)/bin/sentinel"
	@echo "Installed: $(PREFIX)/bin/sentinel-diff"

uninstall:
	@echo "Removing $(PREFIX)/bin/sentinel..."
	rm -f $(PREFIX)/bin/sentinel
	rm -f $(PREFIX)/bin/sentinel-diff

# ============================================================
# Testing
# ============================================================

test: $(TARGET)
	@echo "Running basic tests..."
	@echo ""
	@echo "=== Version Check ==="
	$(TARGET) --version
	@echo ""
	@echo "=== Help Check ==="
	$(TARGET) --help | head -20
	@echo ""
	@echo "=== Quick Probe ==="
	$(TARGET) --quick 2>/dev/null || echo "(Quick probe requires baseline)"
	@echo ""
	@echo "=== JSON Output Sample ==="
	$(TARGET) --json 2>/dev/null | head -50 || echo "(JSON output sample)"
	@echo ""
	@echo "Tests completed."

# ============================================================
# Cleanup
# ============================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "Clean complete."

# ============================================================
# Help
# ============================================================

help:
	@echo "C-Sentinel Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the sentinel binary (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Run basic tests"
	@echo "  install   - Install to $(PREFIX)/bin"
	@echo "  uninstall - Remove installed binary"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1   - Build with debug symbols"
	@echo "  PREFIX=   - Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Detected platform: $(PLATFORM) ($(UNAME_S))"
