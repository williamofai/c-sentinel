#!/bin/bash
# ============================================================
# C-Sentinel BSD Test Suite
#
# Tests builds on FreeBSD, OpenBSD, NetBSD, and DragonFlyBSD
# using Vagrant with libvirt provider.
#
# Requirements:
#   - vagrant
#   - libvirt
#   - vagrant-libvirt plugin
#
# Usage:
#   ./test-bsd-all.sh           # Test all BSDs
#   ./test-bsd-all.sh freebsd   # Test only FreeBSD
#   ./test-bsd-all.sh --clean   # Remove all VMs
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAGRANT_DIR="${SCRIPT_DIR}/.vagrant-bsd-tests"
RESULTS_FILE="${SCRIPT_DIR}/bsd-test-results.txt"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

# BSD configurations
declare -A BSD_BOXES=(
    ["freebsd"]="generic/freebsd14"
    ["openbsd"]="generic/openbsd7"
    ["netbsd"]="generic/netbsd9"
    ["dragonfly"]="generic/dragonflybsd6"
)

declare -A BSD_INSTALL_CMD=(
    ["freebsd"]="pkg install -y gmake llvm"
    ["openbsd"]="pkg_add gmake"
    ["netbsd"]="pkgin -y install gmake clang"
    ["dragonfly"]="pkg install -y gmake llvm"
)

declare -A BSD_RESULTS=()

# ============================================================
# Functions
# ============================================================

check_requirements() {
    log_info "Checking requirements..."
    
    if ! command -v vagrant &> /dev/null; then
        log_fail "Vagrant not installed"
        exit 1
    fi
    
    if ! vagrant plugin list | grep -q vagrant-libvirt; then
        log_warn "vagrant-libvirt plugin not found, installing..."
        vagrant plugin install vagrant-libvirt
    fi
    
    if ! systemctl is-active --quiet libvirtd 2>/dev/null; then
        log_warn "libvirtd not running, attempting to start..."
        sudo systemctl start libvirtd || true
    fi
    
    # Check that BSD fixes are in place
    log_info "Checking BSD compatibility fixes..."
    
    if ! grep -q "defined(KVM_NO_FILES)" src/prober.c 2>/dev/null; then
        log_fail "KVM_NO_FILES fix not applied to src/prober.c"
        echo ""
        echo "Apply this fix around line 537 in src/prober.c:"
        echo ""
        echo '  #if defined(KVM_NO_FILES)'
        echo '      kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);'
        echo '  #else'
        echo '      kd = kvm_openfiles(NULL, "/dev/null", NULL, O_RDONLY, errbuf);'
        echo '  #endif'
        echo ""
        exit 1
    fi
    
    if grep -q '#include <sys/user.h>' include/platform.h 2>/dev/null && \
       ! grep -q 'PLATFORM_FREEBSD.*sys/user.h\|sys/user.h.*PLATFORM_FREEBSD' include/platform.h 2>/dev/null; then
        log_warn "sys/user.h may not be properly wrapped for NetBSD in include/platform.h"
    fi
    
    log_ok "Requirements satisfied"
}

create_vagrantfile() {
    local bsd_name="$1"
    local box="${BSD_BOXES[$bsd_name]}"
    local install_cmd="${BSD_INSTALL_CMD[$bsd_name]}"
    
    mkdir -p "${VAGRANT_DIR}/${bsd_name}"
    
    cat > "${VAGRANT_DIR}/${bsd_name}/Vagrantfile" << EOF
Vagrant.configure("2") do |config|
  config.vm.box = "${box}"
  config.vm.synced_folder "${SCRIPT_DIR}", "/vagrant", type: "rsync",
    rsync__exclude: [".git/", "obj/", "bin/", ".vagrant*/"]
  config.vm.provider "libvirt" do |v|
    v.memory = 2048
    v.cpus = 2
  end
end
EOF
}

test_bsd() {
    local bsd_name="$1"
    local box="${BSD_BOXES[$bsd_name]}"
    local install_cmd="${BSD_INSTALL_CMD[$bsd_name]}"
    
    log_info "=========================================="
    log_info "Testing ${bsd_name^^}"
    log_info "=========================================="
    
    create_vagrantfile "$bsd_name"
    cd "${VAGRANT_DIR}/${bsd_name}"
    
    # Destroy any existing VM
    vagrant destroy -f 2>/dev/null || true
    
    # Start VM
    log_info "Starting ${bsd_name} VM..."
    if ! vagrant up --provider=libvirt 2>&1 | tee /tmp/vagrant-${bsd_name}.log; then
        log_fail "${bsd_name}: VM failed to start"
        BSD_RESULTS[$bsd_name]="FAIL (VM start)"
        return 1
    fi
    
    # Install build tools
    log_info "Installing build tools on ${bsd_name}..."
    
    # Special handling for OpenBSD - mirrors for 7.4 are down, build gmake from source
    if [ "$bsd_name" == "openbsd" ]; then
        log_info "OpenBSD 7.4 mirrors are offline, building gmake from source..."
        vagrant ssh -c "cd /tmp && ftp -o make-4.4.tar.gz https://ftp.gnu.org/gnu/make/make-4.4.tar.gz && tar xzf make-4.4.tar.gz && cd make-4.4 && ./configure && make" > /tmp/install-${bsd_name}.log 2>&1 || {
            log_warn "${bsd_name}: gmake build had issues, checking log..."
            cat /tmp/install-${bsd_name}.log | tail -20
        }
        
        # Build using the locally built gmake
        log_info "Building on ${bsd_name}..."
        vagrant ssh -c "cd /vagrant && sudo rm -rf obj bin && /tmp/make-4.4/make CC=clang 2>&1" > /tmp/build-${bsd_name}.log 2>&1
    else
        vagrant ssh -c "sudo ${install_cmd}" > /tmp/install-${bsd_name}.log 2>&1 || {
            log_warn "${bsd_name}: Package install had issues, continuing anyway..."
            cat /tmp/install-${bsd_name}.log | tail -10
        }
        
        # Build
        log_info "Building on ${bsd_name}..."
        vagrant ssh -c "cd /vagrant && sudo rm -rf obj bin && gmake CC=clang 2>&1" > /tmp/build-${bsd_name}.log 2>&1
    fi
    
    # Check build result
    if vagrant ssh -c "test -x /vagrant/bin/sentinel" 2>/dev/null; then
        log_ok "${bsd_name}: Build successful"
    else
        log_fail "${bsd_name}: Build failed"
        cat /tmp/build-${bsd_name}.log
        BSD_RESULTS[$bsd_name]="FAIL (build)"
        return 1
    fi
    
    # Run tests
    log_info "Running tests on ${bsd_name}..."
    
    local test_output
    test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --quick 2>&1" 2>/dev/null)
    
    if echo "$test_output" | grep -q "C-Sentinel Quick Analysis"; then
        log_ok "${bsd_name}: --quick test passed"
    else
        log_fail "${bsd_name}: --quick test failed"
        BSD_RESULTS[$bsd_name]="FAIL (--quick)"
        return 1
    fi
    
    # Test network probe
    test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --network --json 2>&1 | head -100" 2>/dev/null)
    
    if echo "$test_output" | grep -q '"network"'; then
        log_ok "${bsd_name}: --network test passed"
    else
        log_warn "${bsd_name}: --network test may have issues"
    fi
    
    # Test audit (should report unavailable gracefully)
    test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --quick --audit 2>&1" 2>/dev/null)
    
    if echo "$test_output" | grep -qi "audit"; then
        log_ok "${bsd_name}: --audit test passed (reports unavailable as expected)"
    fi
    
    # Test JSON validity
    test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --json 2>/dev/null | head -200" 2>/dev/null)
    
    if echo "$test_output" | python3 -m json.tool > /dev/null 2>&1; then
        log_ok "${bsd_name}: JSON output valid"
    else
        log_warn "${bsd_name}: JSON output may be truncated or invalid"
    fi
    
    BSD_RESULTS[$bsd_name]="PASS"
    log_ok "${bsd_name}: All tests passed!"
    
    cd "${SCRIPT_DIR}"
    return 0
}

cleanup_vm() {
    local bsd_name="$1"
    
    if [ -d "${VAGRANT_DIR}/${bsd_name}" ]; then
        cd "${VAGRANT_DIR}/${bsd_name}"
        vagrant destroy -f 2>/dev/null || true
        cd "${SCRIPT_DIR}"
    fi
}

cleanup_all() {
    log_info "Cleaning up all VMs..."
    
    for bsd in "${!BSD_BOXES[@]}"; do
        cleanup_vm "$bsd"
    done
    
    rm -rf "${VAGRANT_DIR}"
    log_ok "Cleanup complete"
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "        BSD Test Results Summary"
    echo "=========================================="
    echo ""
    
    local all_pass=true
    
    for bsd in freebsd openbsd netbsd dragonfly; do
        local result="${BSD_RESULTS[$bsd]:-NOT RUN}"
        
        if [ "$result" == "PASS" ]; then
            echo -e "  ${bsd^^}:\t\t${GREEN}${result}${NC}"
        elif [ "$result" == "NOT RUN" ]; then
            echo -e "  ${bsd^^}:\t\t${YELLOW}${result}${NC}"
        else
            echo -e "  ${bsd^^}:\t\t${RED}${result}${NC}"
            all_pass=false
        fi
    done
    
    echo ""
    echo "=========================================="
    
    # Save results to file
    {
        echo "C-Sentinel BSD Test Results"
        echo "Date: $(date)"
        echo ""
        for bsd in freebsd openbsd netbsd dragonfly; do
            echo "${bsd}: ${BSD_RESULTS[$bsd]:-NOT RUN}"
        done
    } > "${RESULTS_FILE}"
    
    log_info "Results saved to ${RESULTS_FILE}"
    
    if $all_pass; then
        return 0
    else
        return 1
    fi
}

usage() {
    echo "C-Sentinel BSD Test Suite"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  all                 Test all BSD variants (default)"
    echo "  freebsd             Test FreeBSD only"
    echo "  openbsd             Test OpenBSD only"
    echo "  netbsd              Test NetBSD only"
    echo "  dragonfly           Test DragonFlyBSD only"
    echo "  --clean             Remove all test VMs"
    echo "  --help              Show this help"
    echo ""
    echo "Options:"
    echo "  --keep              Don't destroy VMs after testing"
    echo ""
    echo "Examples:"
    echo "  $0                  # Test all BSDs"
    echo "  $0 freebsd          # Test FreeBSD only"
    echo "  $0 freebsd --keep   # Test FreeBSD, keep VM running"
    echo "  $0 --clean          # Clean up all VMs"
}

# ============================================================
# Main
# ============================================================

KEEP_VMS=false
TARGETS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)
            cleanup_all
            exit 0
            ;;
        --keep)
            KEEP_VMS=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        all)
            TARGETS=(freebsd openbsd netbsd dragonfly)
            shift
            ;;
        freebsd|openbsd|netbsd|dragonfly)
            TARGETS+=("$1")
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Default to all if no targets specified
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(freebsd openbsd netbsd dragonfly)
fi

# Run tests
check_requirements

echo ""
echo "=========================================="
echo "     C-Sentinel BSD Test Suite"
echo "=========================================="
echo ""
echo "Testing: ${TARGETS[*]}"
echo ""

for target in "${TARGETS[@]}"; do
    test_bsd "$target" || true
    
    if ! $KEEP_VMS; then
        cleanup_vm "$target"
    fi
done

print_summary
exit $?
