# C-Sentinel Makefile
# Semantic Observability for UNIX Systems
#
# Build targets:
#   make          - Build all binaries
#   make static   - Build statically linked (maximum portability)
#   make test     - Run test suite
#   make install  - Install to /usr/local/bin

# ============================================================
# Platform Detection
# ============================================================

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
    PLATFORM_CFLAGS := -DPLATFORM_MACOS
    PLATFORM_LDFLAGS :=
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

CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99 -O2
CFLAGS += -I./include
CFLAGS += $(PLATFORM_CFLAGS)
LDFLAGS = $(PLATFORM_LDFLAGS)
LDLIBS = -lm

# macOS uses clang
ifeq ($(PLATFORM),macos)
    CC = clang
    CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
endif

# FreeBSD and OpenBSD use clang by default
ifeq ($(UNAME_S),FreeBSD)
    CC = clang
endif
ifeq ($(UNAME_S),OpenBSD)
    CC = clang
endif

# Debug build
ifdef DEBUG
    CFLAGS += -g -DDEBUG -O0
    CFLAGS := $(filter-out -O2,$(CFLAGS))
endif

# Static linking for maximum portability
ifdef STATIC
    LDFLAGS += -static
endif

# ============================================================
# Directories
# ============================================================

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# ============================================================
# Source Files
# ============================================================

# Core sources (all platforms)
CORE_SRCS = $(SRC_DIR)/main.c \
            $(SRC_DIR)/prober.c \
            $(SRC_DIR)/net_probe.c \
            $(SRC_DIR)/json_serialize.c \
            $(SRC_DIR)/policy.c \
            $(SRC_DIR)/sanitize.c \
            $(SRC_DIR)/baseline.c \
            $(SRC_DIR)/config.c \
            $(SRC_DIR)/alert.c \
            $(SRC_DIR)/sha256.c \
            $(SRC_DIR)/audit_json.c \
            $(SRC_DIR)/process_chain.c

# Audit sources - platform-specific
AUDIT_COMMON_SRCS = $(SRC_DIR)/audit_common.c

ifeq ($(PLATFORM),linux)
    AUDIT_PLATFORM_SRCS = $(SRC_DIR)/audit_linux.c
else
    # macOS and BSD both use OpenBSM
    AUDIT_PLATFORM_SRCS = $(SRC_DIR)/audit_bsm.c
endif

# Combined sentinel sources
SENTINEL_SRCS = $(CORE_SRCS) $(AUDIT_COMMON_SRCS) $(AUDIT_PLATFORM_SRCS)
SENTINEL_OBJS = $(SENTINEL_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Diff tool sources
DIFF_SRCS = $(SRC_DIR)/diff.c
DIFF_OBJS = $(DIFF_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Header dependencies
HEADERS = $(wildcard $(INC_DIR)/*.h)

# Target binaries
SENTINEL = $(BIN_DIR)/sentinel
SENTINEL_DIFF = $(BIN_DIR)/sentinel-diff

# ============================================================
# Build Rules
# ============================================================

.PHONY: all clean install uninstall test dirs static info lint format size help \
        unit-test integration-test coverage test-clean

# Default target
all: info dirs $(SENTINEL) $(SENTINEL_DIFF)
	@echo ""
	@echo "Build complete. Binaries:"
	@ls -la $(BIN_DIR)/

# Build info
info:
	@echo "Building C-Sentinel for $(PLATFORM) ($(UNAME_S))"
	@echo "Compiler: $(CC)"
	@echo "Audit backend: $(if $(filter linux,$(PLATFORM)),auditd,openbsm)"
	@echo ""

# Static build for deployment
static: LDFLAGS += -static
static: clean all
	@echo ""
	@echo "Static build complete. Checking dependencies:"
	@file $(BIN_DIR)/* || true
	@ldd $(BIN_DIR)/sentinel 2>&1 | head -5 || echo "(statically linked)"

# Create directories
dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

# Link sentinel
$(SENTINEL): $(SENTINEL_OBJS)
	$(CC) $(SENTINEL_OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

# Link sentinel-diff
$(SENTINEL_DIFF): $(DIFF_OBJS)
	$(CC) $(DIFF_OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

# Compile rule
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# ============================================================
# Installation
# ============================================================

# Install
PREFIX ?= /usr/local
install: all
	install -d $(PREFIX)/bin
	install -m 755 $(SENTINEL) $(PREFIX)/bin/
	install -m 755 $(SENTINEL_DIFF) $(PREFIX)/bin/
	install -d $(PREFIX)/share/man/man1
	install -m 644 man/sentinel.1 $(PREFIX)/share/man/man1/
	@echo "Installed to $(PREFIX)/bin/"

# Uninstall
uninstall:
	rm -f $(PREFIX)/bin/sentinel
	rm -f $(PREFIX)/bin/sentinel-diff
	rm -f $(PREFIX)/share/man/man1/sentinel.1

# Test suite - runs both unit tests and integration tests
test: unit-test integration-test

# Integration tests (existing smoke tests)
integration-test: all
	@echo "=== C-Sentinel Test Suite ==="
	@echo ""
	@echo "1. Quick mode test..."
	@(./$(SENTINEL) --quick > /dev/null && echo "   PASS: Quick mode" || echo "   FAIL: Quick mode") || true
	@echo ""
	@echo "2. JSON output test..."
	@(./$(SENTINEL) /etc/hosts > /tmp/sentinel_test.json 2>/dev/null && echo "   PASS: JSON output" || echo "   FAIL: JSON output") || true
	@echo ""
	@echo "3. Diff tool test..."
	@./$(SENTINEL) > /tmp/fp1.json 2>/dev/null || true
	@./$(SENTINEL) > /tmp/fp2.json 2>/dev/null || true
	@(./$(SENTINEL_DIFF) /tmp/fp1.json /tmp/fp2.json > /dev/null 2>&1 && echo "   PASS: Diff tool" || echo "   PASS: Diff tool (differences found)") || true
	@echo ""
	@echo "4. JSON validity test..."
	@(python3 -c "import json; json.load(open('/tmp/sentinel_test.json'))" 2>/dev/null && echo "   PASS: Valid JSON" || echo "   FAIL: Invalid JSON") || true
	@echo ""
	@echo "5. Audit probe test ($(if $(filter linux,$(PLATFORM)),auditd,openbsm))..."
	@(./$(SENTINEL) --audit --quick 2>/dev/null && echo "   PASS: Audit probe" || echo "   WARN: Audit probe (audit may not be enabled)") || true
	@echo ""
	@echo "6. Colour output test..."
	@(./$(SENTINEL) --quick --color 2>/dev/null | head -1 | grep -q "C-Sentinel" && echo "   PASS: Colour output" || echo "   FAIL: Colour output") || true
	@echo ""
	@echo "=== All tests complete ==="
	@rm -f /tmp/sentinel_test.json /tmp/fp1.json /tmp/fp2.json
# ============================================================
# Cleanup
# ============================================================

clean: test-clean
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# ============================================================
# Development Helpers
# ============================================================

# Static analysis
lint:
	@which cppcheck > /dev/null 2>&1 && \
		cppcheck --enable=all --suppress=missingIncludeSystem \
		         --suppress=unusedFunction $(SRC_DIR)/ $(INC_DIR)/ || \
		echo "Install cppcheck for static analysis"

# Format code
format:
	@which clang-format > /dev/null 2>&1 && \
		clang-format -i $(SRC_DIR)/*.c $(INC_DIR)/*.h || \
		echo "Install clang-format for code formatting"

# Show binary sizes
size: all
	@echo "Binary sizes:"
	@size $(BIN_DIR)/* || ls -lh $(BIN_DIR)/*

# ============================================================
# Unit Testing (requires cmocka)
# ============================================================
#
# Unit tests use cmocka framework for mocking and assertions.
# Install cmocka via your package manager:
#   macOS:   brew install cmocka
#   Debian:  apt install libcmocka-dev
#   Fedora:  dnf install libcmocka-devel
#   FreeBSD: pkg install cmocka
#   OpenBSD: pkg_add cmocka

# Test directories
TEST_SRC_DIR = tests/src
TEST_INC_DIR = tests/include
TEST_BUILD_DIR = build/tests
TEST_BIN_DIR = bin/tests

# Detect cmocka using pkg-config (standard Unix practice)
CMOCKA_EXISTS := $(shell pkg-config --exists cmocka 2>/dev/null && echo yes)

ifeq ($(CMOCKA_EXISTS),yes)
    CMOCKA_CFLAGS := $(shell pkg-config --cflags cmocka)
    CMOCKA_LDFLAGS := $(shell pkg-config --libs cmocka)
else
    # Fallback: try common paths (Homebrew, system)
    CMOCKA_CFLAGS := -I/usr/local/include -I/opt/homebrew/include
    CMOCKA_LDFLAGS := -L/usr/local/lib -L/opt/homebrew/lib -lcmocka
endif

# Test compiler flags
# - Include both project headers and test headers
# - Add debug symbols for better test output
# - Disable some warnings that cmocka triggers
TEST_CFLAGS = $(CFLAGS) -g -I$(TEST_INC_DIR) $(CMOCKA_CFLAGS)
TEST_CFLAGS += -Wno-unused-parameter
# POSIX feature test macros for test helpers (mkdtemp, strdup, lstat, setenv, unsetenv)
ifeq ($(PLATFORM),linux)
    TEST_CFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
endif
ifeq ($(PLATFORM),macos)
    TEST_CFLAGS += -D_DARWIN_C_SOURCE
endif
ifeq ($(findstring bsd,$(PLATFORM)),bsd)
    TEST_CFLAGS += -D_BSD_SOURCE
endif
TEST_LDFLAGS = $(LDFLAGS) $(CMOCKA_LDFLAGS)

# Coverage flags (optional, enabled with make coverage)
ifdef COVERAGE
    TEST_CFLAGS += --coverage -fprofile-arcs -ftest-coverage
    TEST_LDFLAGS += --coverage
endif

# Find all test source files
TEST_SRCS := $(wildcard $(TEST_SRC_DIR)/test_*.c)
TEST_BINS := $(TEST_SRCS:$(TEST_SRC_DIR)/test_%.c=$(TEST_BIN_DIR)/test_%)

# Object files needed for tests (reuse main project objects)
# Exclude main.o since tests have their own main()
TEST_SUPPORT_OBJS := $(filter-out $(BUILD_DIR)/main.o, $(SENTINEL_OBJS))

# Create test directories
test-dirs:
	@mkdir -p $(TEST_BUILD_DIR) $(TEST_BIN_DIR)

# Check if cmocka is available
check-cmocka:
	@if ! pkg-config --exists cmocka 2>/dev/null; then \
		if ! $(CC) -x c -o /dev/null /dev/null $(CMOCKA_LDFLAGS) 2>/dev/null; then \
			echo ""; \
			echo "ERROR: cmocka not found."; \
			echo ""; \
			echo "Install cmocka using your package manager:"; \
			echo "  macOS:   brew install cmocka"; \
			echo "  Debian:  apt install libcmocka-dev"; \
			echo "  Fedora:  dnf install libcmocka-devel"; \
			echo "  FreeBSD: pkg install cmocka"; \
			echo "  OpenBSD: pkg_add cmocka"; \
			echo ""; \
			exit 1; \
		fi \
	fi

# Compile a test file
# Each test links against the support objects it needs
$(TEST_BIN_DIR)/test_%: $(TEST_SRC_DIR)/test_%.c $(TEST_SUPPORT_OBJS) | test-dirs
	$(CC) $(TEST_CFLAGS) $< $(TEST_SUPPORT_OBJS) -o $@ $(TEST_LDFLAGS) $(LDLIBS)

# Run unit tests
unit-test: check-cmocka dirs $(TEST_SUPPORT_OBJS) $(TEST_BINS)
	@echo ""
	@echo "=== C-Sentinel Unit Tests ==="
	@echo ""
	@failed=0; \
	for test in $(TEST_BINS); do \
		echo "Running $$(basename $$test)..."; \
		if $$test; then \
			echo "  PASSED"; \
		else \
			echo "  FAILED"; \
			failed=$$((failed + 1)); \
		fi; \
		echo ""; \
	done; \
	if [ $$failed -gt 0 ]; then \
		echo "=== $$failed test(s) FAILED ==="; \
		exit 1; \
	else \
		echo "=== All unit tests PASSED ==="; \
	fi

# Run tests with coverage (generates .gcov files)
coverage: COVERAGE=1
coverage: clean unit-test
	@echo ""
	@echo "=== Generating Coverage Report ==="
	@gcov -o $(BUILD_DIR) $(SRC_DIR)/*.c 2>/dev/null || true
	@echo ""
	@echo "Coverage files generated. For HTML report, install lcov and run:"
	@echo "  lcov --capture --directory $(BUILD_DIR) --output-file coverage.info"
	@echo "  genhtml coverage.info --output-directory coverage-report"

# Clean test artifacts
test-clean:
	rm -rf $(TEST_BUILD_DIR) $(TEST_BIN_DIR)
	rm -f *.gcov *.gcda *.gcno coverage.info
	rm -rf coverage-report

# ============================================================
# Help
# ============================================================

help:
	@echo "C-Sentinel Build System"
	@echo ""
	@echo "Detected: $(PLATFORM) ($(UNAME_S))"
	@echo "Audit backend: $(if $(filter linux,$(PLATFORM)),auditd (Linux),openbsm (macOS/BSD))"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build all binaries (default)"
	@echo "  static           - Build with static linking"
	@echo "  test             - Run all tests (unit + integration)"
	@echo "  unit-test        - Run unit tests only (requires cmocka)"
	@echo "  integration-test - Run integration tests only"
	@echo "  coverage         - Run tests with coverage report"
	@echo "  install          - Install to PREFIX (default: /usr/local)"
	@echo "  clean            - Remove build artifacts"
	@echo "  test-clean       - Remove test artifacts and coverage data"
	@echo "  lint             - Run static analysis"
	@echo "  format           - Format source code"
	@echo "  size             - Show binary sizes"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1   - Debug build with symbols"
	@echo "  STATIC=1  - Static linking"
	@echo "  PREFIX=   - Installation prefix"
	@echo ""
	@echo "Examples:"
	@echo "  make"
	@echo "  make DEBUG=1"
	@echo "  make STATIC=1"
	@echo "  make install PREFIX=/opt/sentinel"
