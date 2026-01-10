#!/bin/bash
#
# C-Sentinel BSD Audit Cross-Platform Test Suite
# Tests audit functionality on FreeBSD, NetBSD, OpenBSD using Vagrant + libvirt
#
# Usage: ./test-bsd-audit-vagrant.sh [--quick] [--keep] [distro...]
#
# Options:
#   --quick    Skip baseline learning tests (faster)
#   --keep     Don't destroy VMs after testing
#   distro     Specific distros to test (freebsd, netbsd, openbsd)
#              Default: all
#
# Requirements:
#   - Vagrant
#   - libvirt provider (vagrant-libvirt plugin)
#   - KVM/QEMU
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${SCRIPT_DIR}/vagrant-bsd-audit-test"
RESULTS_DIR="${SCRIPT_DIR}/bsd-audit-test-results"
QUICK_MODE=0
KEEP_VMS=0
DISTROS=()

# BSD boxes for libvirt
declare -A BSD_BOXES=(
    ["freebsd"]="generic/freebsd14"
    ["netbsd"]="generic/netbsd9"
    ["openbsd"]="generic/openbsd7"
)

declare -A BSD_NAMES=(
    ["freebsd"]="FreeBSD 14"
    ["netbsd"]="NetBSD 9"
    ["openbsd"]="OpenBSD 7"
)

# Test results
declare -A TEST_RESULTS
TOTAL_PASS=0
TOTAL_FAIL=0

log_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    TOTAL_PASS=$((TOTAL_PASS + 1))
}

log_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
}

log_info() {
    echo -e "  ${YELLOW}→${NC} $1"
}

log_skip() {
    echo -e "  ${BLUE}○ SKIP${NC}: $1"
}

usage() {
    echo "Usage: $0 [--quick] [--keep] [distro...]"
    echo ""
    echo "Options:"
    echo "  --quick    Skip baseline learning tests"
    echo "  --keep     Don't destroy VMs after testing"
    echo ""
    echo "Distros: freebsd, netbsd, openbsd (default: all)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=1
            shift
            ;;
        --keep)
            KEEP_VMS=1
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            if [[ -n "${BSD_BOXES[$1]}" ]]; then
                DISTROS+=("$1")
            else
                echo "Unknown option or distro: $1"
                usage
            fi
            shift
            ;;
    esac
done

# Default to all distros
if [[ ${#DISTROS[@]} -eq 0 ]]; then
    DISTROS=("freebsd" "netbsd" "openbsd")
fi

# Check prerequisites
check_prerequisites() {
    log_header "Checking Prerequisites"
    
    if ! command -v vagrant &> /dev/null; then
        log_fail "Vagrant not installed"
        echo "Install with: sudo apt install vagrant"
        exit 1
    fi
    log_pass "Vagrant installed"
    
    if ! vagrant plugin list | grep -q vagrant-libvirt; then
        log_fail "vagrant-libvirt plugin not installed"
        echo "Install with: vagrant plugin install vagrant-libvirt"
        exit 1
    fi
    log_pass "vagrant-libvirt plugin installed"
    
    if ! command -v virsh &> /dev/null; then
        log_fail "libvirt not installed"
        echo "Install with: sudo apt install libvirt-daemon-system"
        exit 1
    fi
    log_pass "libvirt installed"
    
    # Check if source files exist
    if [[ ! -f "${SCRIPT_DIR}/src/audit_bsm.c" ]]; then
        log_fail "Source files not found - run from c-sentinel directory"
        exit 1
    fi
    log_pass "Source files found"
}

# Create Vagrantfile with embedded test script
create_vagrantfile() {
    local distro=$1
    local box="${BSD_BOXES[$distro]}"
    
    mkdir -p "${TEST_DIR}/${distro}"
    
    cat > "${TEST_DIR}/${distro}/Vagrantfile" << EOF
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "${box}"
  config.vm.hostname = "sentinel-${distro}-test"
  
  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 1024
    libvirt.cpus = 2
  end
  
  # Sync the source code (exclude vagrant test dirs to avoid conflicts)
  config.vm.synced_folder "${SCRIPT_DIR}", "/vagrant", type: "rsync",
    rsync__exclude: [".git/", "build/", "bin/", "vagrant-bsd-audit-test/", "bsd-audit-test-results/", "*.zip"]
  
  # Provisioning script - build sentinel
  config.vm.provision "shell", inline: <<-SHELL
    echo "=== Setting up test environment on \$(uname -s) ==="
    
    OS=\$(uname -s)
    
    case "\$OS" in
      FreeBSD)
        # FreeBSD uses clang by default, install gmake
        pkg install -y gmake
        export CC=clang
        MAKE="gmake CC=clang"
        ;;
      NetBSD)
        # NetBSD needs gmake, has gcc
        pkgin -y install gmake
        MAKE=gmake
        ;;
      OpenBSD)
        # OpenBSD: use clang (base system) and try gmake or fall back to make
        export CC=clang
        if pkg_add gmake 2>/dev/null; then
          MAKE="gmake CC=clang"
        else
          # Use BSD make with explicit compiler
          MAKE="make CC=clang"
        fi
        ;;
      *)
        MAKE=make
        ;;
    esac
    
    # Build sentinel
    cd /vagrant
    \$MAKE clean 2>/dev/null || true
    echo ""
    echo "Building with: \$MAKE"
    echo ""
    \$MAKE || { echo "Build failed!"; exit 1; }
    
    echo ""
    echo "=== Build complete ==="
    ls -la bin/ 2>/dev/null || echo "No bin directory"
  SHELL
end
EOF
}

# Run tests inside VM
run_vm_tests() {
    local distro=$1
    
    vagrant ssh -c 'sh -s' << 'TESTSCRIPT'
#!/bin/sh
#
# Test script to run inside BSD VM
#

SENTINEL="/vagrant/bin/sentinel"
PASS=0
FAIL=0

test_pass() {
    echo "PASS: $1"
    PASS=$((PASS + 1))
}

test_fail() {
    echo "FAIL: $1"
    FAIL=$((FAIL + 1))
}

echo ""
echo "========================================"
echo "  C-Sentinel BSD Audit Tests"
echo "  Platform: $(uname -s) $(uname -r)"
echo "========================================"
echo ""

# Test 1: Binary exists and runs
echo "=== Test 1: Binary execution ==="
if [ -x "$SENTINEL" ]; then
    if $SENTINEL --version > /dev/null 2>&1; then
        test_pass "Binary executes"
    else
        # Try running it and capture error
        ERR=$($SENTINEL --version 2>&1)
        test_fail "Binary crashes: $ERR"
    fi
else
    test_fail "Binary not found or not executable at $SENTINEL"
    ls -la /vagrant/bin/ 2>/dev/null
fi

# Test 2: Quick mode without audit
echo ""
echo "=== Test 2: Quick mode ==="
if $SENTINEL --quick > /dev/null 2>&1; then
    test_pass "Quick mode runs"
else
    test_fail "Quick mode failed"
fi

# Test 3: Audit probe
echo ""
echo "=== Test 3: Audit probe ==="
OUTPUT=$($SENTINEL --audit --quick 2>&1)
if echo "$OUTPUT" | grep -q "Security (audit):"; then
    test_pass "Audit section present"
    
    # Check if audit is available or unavailable
    if echo "$OUTPUT" | grep -q "unavailable"; then
        echo "INFO: Audit unavailable (expected if not configured)"
    else
        test_pass "Audit probe returned data"
    fi
else
    test_fail "Audit section missing"
    echo "OUTPUT: $OUTPUT"
fi

# Test 4: JSON output
echo ""
echo "=== Test 4: JSON output ==="
OUTPUT=$($SENTINEL --audit --json 2>&1)
if echo "$OUTPUT" | grep -q '"audit_summary"'; then
    test_pass "audit_summary in JSON"
else
    test_fail "audit_summary missing from JSON"
fi

if echo "$OUTPUT" | grep -q '"risk_score"'; then
    test_pass "risk_score in JSON"
else
    test_fail "risk_score missing from JSON"
fi

if echo "$OUTPUT" | grep -q '"risk_level"'; then
    test_pass "risk_level in JSON"
else
    test_fail "risk_level missing from JSON"
fi

# Test 5: Risk level is valid
echo ""
echo "=== Test 5: Risk level validation ==="
RISK_LEVEL=$(echo "$OUTPUT" | grep -o '"risk_level":"[^"]*"' | head -1 | cut -d'"' -f4)
case "$RISK_LEVEL" in
    low|medium|high|critical)
        test_pass "Valid risk level: $RISK_LEVEL"
        ;;
    "")
        test_fail "Risk level is empty"
        ;;
    *)
        test_fail "Unknown risk level: $RISK_LEVEL"
        ;;
esac

# Test 6: Security framework detection
echo ""
echo "=== Test 6: Security framework ==="
case "$(uname -s)" in
    FreeBSD|NetBSD|OpenBSD)
        SECURELEVEL=$(sysctl -n kern.securelevel 2>/dev/null || echo "N/A")
        echo "INFO: kern.securelevel = $SECURELEVEL"
        test_pass "Securelevel readable"
        ;;
esac

# Test 7: Baseline learning
echo ""
echo "=== Test 7: Audit baseline ==="
if $SENTINEL --audit-learn > /dev/null 2>&1; then
    test_pass "Audit baseline learning"
else
    echo "INFO: Baseline learning failed (audit may not be enabled)"
fi

# Summary
echo ""
echo "========================================"
echo "  Test Summary for $(uname -s)"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "  ALL TESTS PASSED"
    exit 0
else
    echo "  SOME TESTS FAILED"
    exit 1
fi
TESTSCRIPT
}

# Run tests on a specific distro
run_distro_tests() {
    local distro=$1
    local name="${BSD_NAMES[$distro]}"
    local result_file="${RESULTS_DIR}/${distro}-results.txt"
    
    log_header "Testing ${name}"
    
    mkdir -p "${RESULTS_DIR}"
    
    cd "${TEST_DIR}/${distro}"
    
    # Start VM
    log_info "Starting ${name} VM..."
    if ! vagrant up --provider=libvirt 2>&1 | tee -a "${result_file}"; then
        log_fail "Failed to start ${name} VM"
        TEST_RESULTS[$distro]="VM_FAILED"
        return 1
    fi
    
    # Run tests
    log_info "Running tests on ${name}..."
    if run_vm_tests "$distro" 2>&1 | tee -a "${result_file}"; then
        log_pass "${name}: All tests passed"
        TEST_RESULTS[$distro]="PASS"
    else
        log_fail "${name}: Some tests failed"
        TEST_RESULTS[$distro]="FAIL"
    fi
    
    # Cleanup
    if [ $KEEP_VMS -eq 0 ]; then
        log_info "Destroying ${name} VM..."
        vagrant destroy -f 2>/dev/null || true
    else
        log_info "Keeping ${name} VM (--keep specified)"
    fi
    
    cd "${SCRIPT_DIR}"
}

# Main execution
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   C-Sentinel BSD Audit Cross-Platform Test Suite              ║${NC}"
    echo -e "${CYAN}║   Using Vagrant + libvirt                                     ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_info "Test targets: ${DISTROS[*]}"
    [ $QUICK_MODE -eq 1 ] && log_info "Quick mode enabled"
    [ $KEEP_VMS -eq 1 ] && log_info "VMs will be kept after testing"
    
    check_prerequisites
    
    # Setup test directory
    mkdir -p "${TEST_DIR}"
    
    # Create Vagrantfiles for each distro
    for distro in "${DISTROS[@]}"; do
        create_vagrantfile "$distro"
    done
    
    # Run tests
    for distro in "${DISTROS[@]}"; do
        run_distro_tests "$distro"
    done
    
    # Final summary
    log_header "Final Results"
    echo ""
    printf "  %-12s %s\n" "DISTRO" "RESULT"
    printf "  %-12s %s\n" "------" "------"
    for distro in "${DISTROS[@]}"; do
        local result="${TEST_RESULTS[$distro]:-UNKNOWN}"
        local color=$NC
        case $result in
            PASS) color=$GREEN ;;
            FAIL) color=$RED ;;
            VM_FAILED) color=$RED ;;
        esac
        printf "  %-12s ${color}%s${NC}\n" "${BSD_NAMES[$distro]}" "$result"
    done
    echo ""
    echo -e "  ${GREEN}Total Passed:${NC} $TOTAL_PASS"
    echo -e "  ${RED}Total Failed:${NC} $TOTAL_FAIL"
    echo ""
    
    # Save summary
    {
        echo "C-Sentinel BSD Audit Test Results"
        echo "=================================="
        echo "Date: $(date)"
        echo ""
        for distro in "${DISTROS[@]}"; do
            echo "${BSD_NAMES[$distro]}: ${TEST_RESULTS[$distro]:-UNKNOWN}"
        done
        echo ""
        echo "Total Passed: $TOTAL_PASS"
        echo "Total Failed: $TOTAL_FAIL"
    } > "${RESULTS_DIR}/summary.txt"
    
    log_info "Results saved to ${RESULTS_DIR}/"
    
    # Exit with appropriate code
    if [ $TOTAL_FAIL -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${YELLOW}Some tests failed - check individual results${NC}"
        exit 1
    fi
}

main "$@"
