#!/bin/bash
# ============================================================
# C-Sentinel BSD Test Suite
#
# Comprehensive test suite for FreeBSD, OpenBSD, NetBSD, and DragonFlyBSD
# using Vagrant with libvirt provider.
#
# This script tests:
#   - Build compatibility
#   - Basic functionality (--quick, --network)
#   - Audit functionality (OpenBSM)
#   - JSON output validation
#
# Requirements:
#   - vagrant
#   - libvirt
#   - vagrant-libvirt plugin
#
# Usage:
#   ./test-bsd.sh                 # Test all BSDs (build + audit tests)
#   ./test-bsd.sh freebsd         # Test only FreeBSD
#   ./test-bsd.sh --build-only    # Only build tests (faster)
#   ./test-bsd.sh --audit-only    # Only audit tests
#   ./test-bsd.sh --keep          # Keep VMs running after tests
#   ./test-bsd.sh --clean         # Remove all VMs
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
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_header() {
	echo ""
	echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
	echo -e "${CYAN}  $1${NC}"
	echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# BSD configurations
declare -A BSD_BOXES=(
	["freebsd"]="generic/freebsd14"
	["openbsd"]="generic/openbsd7"
	["netbsd"]="generic/netbsd9"
	["dragonfly"]="generic/dragonflybsd6"
)

declare -A BSD_NAMES=(
	["freebsd"]="FreeBSD 14"
	["openbsd"]="OpenBSD 7"
	["netbsd"]="NetBSD 9"
	["dragonfly"]="DragonFlyBSD 6"
)

declare -A BSD_INSTALL_CMD=(
	["freebsd"]="pkg install -y gmake llvm"
	["openbsd"]="pkg_add gmake"
	["netbsd"]="pkgin -y install gmake clang"
	["dragonfly"]="pkg install -y gmake llvm"
)

declare -A BSD_RESULTS=()
declare -A TEST_COUNTS=()

# Test mode flags
BUILD_TESTS=1
AUDIT_TESTS=1
KEEP_VMS=false
TARGETS=()

# ============================================================
# Functions
# ============================================================

cleanup_stale_vms() {
	log_info "Checking for stale VMs from previous runs..."

	# Get list of VMs from this test directory that are still running
	local stale_found=false
	local cleanup_failed=false

	for bsd in "${TARGETS[@]}"; do
		# Check if there's a VM with this name in libvirt
		if virsh list --all 2>/dev/null | grep -q "${bsd}_default"; then
			log_warn "Found existing VM: ${bsd}_default"
			stale_found=true

			# Try to destroy it from its directory if it exists
			if [ -d "${VAGRANT_DIR}/${bsd}" ]; then
				log_info "Cleaning up ${bsd}_default from ${VAGRANT_DIR}/${bsd}..."
				(cd "${VAGRANT_DIR}/${bsd}" && vagrant destroy -f 2>/dev/null) || true

				# Verify it was actually destroyed
				if virsh list --all 2>/dev/null | grep -q "${bsd}_default"; then
					log_warn "VM still exists - it may be from another project"
					cleanup_failed=true
				fi
			else
				log_warn "VM exists but no local vagrant directory found"
				cleanup_failed=true
			fi
		fi
	done

	if $cleanup_failed; then
		echo ""
		log_fail "Failed to cleanup existing VMs with conflicting names"
		log_info "You have VMs named *_default that conflict with this test:"
		virsh list --all 2>/dev/null | grep "_default" || true
		echo ""
		log_info "Options to resolve this:"
		echo "  1. Stop VMs from other projects: vagrant halt (in their directories)"
		echo "  2. Use virsh to manually destroy them: virsh destroy <vm-name> && virsh undefine <vm-name>"
		echo "  3. Or check 'vagrant global-status' and clean up old VMs"
		echo ""
		exit 1
	elif $stale_found; then
		log_ok "Stale VM cleanup complete"
	else
		log_info "No stale VMs found"
	fi
}

check_requirements() {
	log_info "Checking requirements..."

	if ! command -v vagrant &>/dev/null; then
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

	if ! grep -q '#include <stdint.h>' include/platform.h 2>/dev/null; then
		log_warn "stdint.h may not be included in include/platform.h (needed for BSD types)"
	fi

	log_ok "Requirements satisfied"
}

create_vagrantfile() {
	local bsd_name="$1"
	local box="${BSD_BOXES[$bsd_name]}"
	local install_cmd="${BSD_INSTALL_CMD[$bsd_name]}"

	mkdir -p "${VAGRANT_DIR}/${bsd_name}"

	cat >"${VAGRANT_DIR}/${bsd_name}/Vagrantfile" <<EOF
Vagrant.configure("2") do |config|
  config.vm.box = "${box}"
  config.vm.hostname = "sentinel-${bsd_name}-test"
  config.vm.synced_folder "${SCRIPT_DIR}", "/vagrant", type: "rsync",
    rsync__exclude: [".git/", "obj/", "bin/", ".vagrant*/"]
  config.vm.provider "libvirt" do |v|
    v.memory = 2048
    v.cpus = 2
  end
end
EOF
}

run_build_tests() {
	local bsd_name="$1"
	local install_cmd="${BSD_INSTALL_CMD[$bsd_name]}"

	log_header "Build Tests: ${BSD_NAMES[$bsd_name]}"

	# Install build tools
	log_info "Installing build tools..."

	# Special handling for OpenBSD - mirrors for 7.4 are down, build gmake from source
	if [ "$bsd_name" == "openbsd" ]; then
		log_info "OpenBSD 7.4 mirrors are offline, building gmake from source..."
		vagrant ssh -c "cd /tmp && ftp -o make-4.4.tar.gz https://ftp.gnu.org/gnu/make/make-4.4.tar.gz && tar xzf make-4.4.tar.gz && cd make-4.4 && ./configure && make" >/tmp/install-${bsd_name}.log 2>&1 || {
			log_warn "gmake build had issues, checking log..."
			cat /tmp/install-${bsd_name}.log | tail -20
		}

		# Build using the locally built gmake
		log_info "Building..."
		vagrant ssh -c "cd /vagrant && sudo rm -rf obj bin && /tmp/make-4.4/make CC=clang 2>&1" >/tmp/build-${bsd_name}.log 2>&1
	else
		vagrant ssh -c "sudo ${install_cmd}" >/tmp/install-${bsd_name}.log 2>&1 || {
			log_warn "Package install had issues, continuing anyway..."
			cat /tmp/install-${bsd_name}.log | tail -10
		}

		# Build
		log_info "Building..."
		vagrant ssh -c "cd /vagrant && sudo rm -rf obj bin && gmake CC=clang 2>&1" >/tmp/build-${bsd_name}.log 2>&1
	fi

	# Check build result
	if vagrant ssh -c "test -x /vagrant/bin/sentinel" 2>/dev/null; then
		log_ok "Build successful"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
	else
		log_fail "Build failed"
		cat /tmp/build-${bsd_name}.log
		BSD_RESULTS[$bsd_name]="FAIL (build)"
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
		return 1
	fi

	# Test binary execution
	log_info "Testing binary execution..."
	if vagrant ssh -c "/vagrant/bin/sentinel --version 2>&1" 2>/dev/null | grep -q "C-Sentinel"; then
		log_ok "Binary executes"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
	else
		log_fail "Binary crashes"
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
		return 1
	fi

	# Run --quick test
	log_info "Testing --quick mode..."
	local test_output
	test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --quick 2>&1" 2>/dev/null)

	if echo "$test_output" | grep -q "C-Sentinel Quick Analysis"; then
		log_ok "--quick test passed"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
	else
		log_fail "--quick test failed"
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
	fi

	# Test network probe
	log_info "Testing --network..."
	test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --network --json 2>&1 | head -100" 2>/dev/null)

	if echo "$test_output" | grep -q '"network"'; then
		log_ok "--network test passed"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
	else
		log_warn "--network test may have issues"
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
	fi

	# Test JSON validity
	log_info "Testing JSON output..."
	test_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --json 2>/dev/null | head -200" 2>/dev/null)

	if echo "$test_output" | python3 -m json.tool >/dev/null 2>&1; then
		log_ok "JSON output valid"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
	else
		log_warn "JSON output may be truncated or invalid"
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
	fi

	return 0
}

enable_audit_system() {
	local bsd_name="$1"

	log_info "Enabling audit system..."

	case "$bsd_name" in
	freebsd)
		vagrant ssh -c "
                # Enable audit in rc.conf
                sudo sysrc auditd_enable=YES 2>/dev/null || echo 'auditd_enable=\"YES\"' | sudo tee -a /etc/rc.conf
                
                # Create audit directory if it doesn't exist
                sudo mkdir -p /var/audit
                sudo chmod 700 /var/audit
                
                # Create basic audit configuration
                if [ ! -f /etc/security/audit_control ]; then
                    sudo tee /etc/security/audit_control > /dev/null << 'EOF'
dir:/var/audit
flags:lo,aa
minfree:5
naflags:lo,aa
policy:cnt,argv
filesz:2M
expire-after:10M
EOF
                fi
                
                # Start auditd
                sudo service auditd start 2>/dev/null || sudo /usr/sbin/auditd 2>/dev/null || true
                
                # Generate some audit events for testing
                sudo ls /etc/passwd >/dev/null 2>&1
                sudo -k 2>/dev/null || true
                
                sleep 2
                echo 'Audit system configured'
            " 2>&1 | grep -v "command not found" || true
		;;

	openbsd)
		vagrant ssh -c "
                # OpenBSD doesn't have auditd by default, but has accounting
                # Try to enable it if available
                if [ -f /usr/sbin/auditd ]; then
                    sudo mkdir -p /var/audit
                    sudo chmod 700 /var/audit
                    sudo /usr/sbin/auditd 2>/dev/null || true
                fi
                echo 'OpenBSD audit check complete'
            " 2>&1 || true
		;;

	netbsd)
		vagrant ssh -c "
                # NetBSD may have audit support
                if [ -f /usr/sbin/auditd ]; then
                    sudo mkdir -p /var/audit
                    sudo chmod 700 /var/audit
                    sudo /usr/sbin/auditd 2>/dev/null || true
                fi
                echo 'NetBSD audit check complete'
            " 2>&1 || true
		;;

	dragonfly)
		vagrant ssh -c "
                # DragonFlyBSD may have audit support similar to FreeBSD
                if [ -f /usr/sbin/auditd ]; then
                    sudo mkdir -p /var/audit
                    sudo chmod 700 /var/audit
                    sudo /usr/sbin/auditd 2>/dev/null || true
                fi
                echo 'DragonFlyBSD audit check complete'
            " 2>&1 || true
		;;
	esac

	# Verify audit is running
	if vagrant ssh -c "test -d /var/audit && ls /var/audit 2>/dev/null | grep -q ." 2>/dev/null; then
		log_ok "Audit system enabled and running"
		return 0
	else
		log_info "Audit system not available or not running (this is OK)"
		return 1
	fi
}

run_audit_tests() {
	local bsd_name="$1"

	log_header "Audit Tests: ${BSD_NAMES[$bsd_name]}"

	# Try to enable audit system
	enable_audit_system "$bsd_name" || true

	# Test audit probe
	log_info "Testing audit probe..."
	local audit_output
	audit_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --audit --quick 2>&1" 2>/dev/null)

	# Accept either "Security (audit):" (enabled) or "Audit: unavailable" (disabled)
	if echo "$audit_output" | grep -qE "(Security \(audit\):|Audit:.*unavailable)"; then
		log_ok "Audit section present"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))

		# Check if audit is available or unavailable
		if echo "$audit_output" | grep -q "unavailable"; then
			log_info "Audit unavailable (expected if not configured)"
		else
			log_ok "Audit probe returned data"
			TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
		fi
	else
		log_fail "Audit section missing"
		echo "DEBUG: Actual output:"
		echo "$audit_output" | head -20
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
	fi

	# Test audit JSON output
	log_info "Testing audit JSON fields..."
	local json_output
	json_output=$(vagrant ssh -c "cd /vagrant && ./bin/sentinel --audit --json 2>&1" 2>/dev/null)

	# Check if audit_summary exists (it should always exist, even when disabled)
	if echo "$json_output" | grep -q '"audit_summary"'; then
		log_ok "audit_summary field present in JSON"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))

		# If audit is enabled, check for risk fields
		if echo "$json_output" | grep -q '"enabled":true'; then
			local json_tests=0
			local json_pass=0

			for field in "risk_score" "risk_level"; do
				json_tests=$((json_tests + 1))
				if echo "$json_output" | grep -q "\"$field\""; then
					json_pass=$((json_pass + 1))
				fi
			done

			if [ $json_pass -eq $json_tests ]; then
				log_ok "All risk fields present ($json_pass/$json_tests)"
				TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
			else
				log_warn "Some risk fields missing ($json_pass/$json_tests)"
			fi
		else
			log_info "Audit disabled, skipping risk field checks"
		fi
	else
		log_fail "audit_summary field missing from JSON"
		TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
	fi

	# Test risk level validation (only if audit is enabled)
	if echo "$json_output" | grep -q '"enabled":true'; then
		log_info "Testing risk level validation..."
		local risk_level
		risk_level=$(echo "$json_output" | grep -o '"risk_level":"[^"]*"' | head -1 | cut -d'"' -f4)

		case "$risk_level" in
		low | medium | high | critical)
			log_ok "Valid risk level: $risk_level"
			TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
			;;
		"")
			log_warn "Risk level is empty (audit may be disabled)"
			;;
		*)
			log_fail "Unknown risk level: $risk_level"
			TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
			;;
		esac
	else
		log_info "Audit disabled, skipping risk level validation"
	fi

	# Test security framework detection
	log_info "Testing security framework detection..."
	case "$bsd_name" in
	freebsd | netbsd | openbsd)
		if vagrant ssh -c "sysctl kern.securelevel 2>/dev/null" >/dev/null; then
			log_ok "kern.securelevel readable"
			TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
		else
			log_warn "kern.securelevel not readable"
			TEST_COUNTS["${bsd_name}_fail"]=$((${TEST_COUNTS["${bsd_name}_fail"]:-0} + 1))
		fi
		;;
	esac

	# Test audit baseline learning
	log_info "Testing audit baseline learning..."
	if vagrant ssh -c "cd /vagrant && ./bin/sentinel --audit-learn > /dev/null 2>&1" 2>/dev/null; then
		log_ok "Audit baseline learning works"
		TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
	else
		log_info "Baseline learning failed (audit may not be enabled)"
	fi

	# Additional test: verify audit trails exist if audit is enabled
	if vagrant ssh -c "test -d /var/audit && ls /var/audit/*.not_terminated 2>/dev/null || ls /var/audit/current 2>/dev/null" 2>/dev/null; then
		log_info "Audit trail files detected:"
		vagrant ssh -c "ls -lh /var/audit/ | head -5" 2>/dev/null || true

		# Test that praudit can read the trails
		if vagrant ssh -c "command -v praudit >/dev/null 2>&1" 2>/dev/null; then
			log_info "Testing praudit..."
			if vagrant ssh -c "sudo praudit /var/audit/*.not_terminated 2>/dev/null | head -5" 2>/dev/null | grep -q "header"; then
				log_ok "Audit trails are readable with praudit"
				TEST_COUNTS["${bsd_name}_pass"]=$((${TEST_COUNTS["${bsd_name}_pass"]:-0} + 1))
			fi
		fi
	fi

	return 0
}

verify_vm_health() {
	local bsd_name="$1"

	log_info "Verifying VM is accessible..."

	# Try to SSH into the VM with a simple command
	if vagrant ssh -c "echo 'VM_HEALTH_CHECK_OK'" 2>/dev/null | grep -q "VM_HEALTH_CHECK_OK"; then
		return 0
	else
		return 1
	fi
}

test_bsd() {
	local bsd_name="$1"

	log_header "Testing ${BSD_NAMES[$bsd_name]}"

	create_vagrantfile "$bsd_name"
	cd "${VAGRANT_DIR}/${bsd_name}"

	# Destroy any existing VM
	vagrant destroy -f 2>/dev/null || true

	# Start VM
	log_info "Starting VM..."
	vagrant up --provider=libvirt 2>&1 | tee /tmp/vagrant-${bsd_name}.log
	local vagrant_exit_code=${PIPESTATUS[0]}

	# Check if vagrant up succeeded
	if [ $vagrant_exit_code -ne 0 ]; then
		log_fail "VM failed to start (exit code: $vagrant_exit_code)"
		log_info "Check /tmp/vagrant-${bsd_name}.log for details"
		BSD_RESULTS[$bsd_name]="FAIL (VM start)"
		cd "${SCRIPT_DIR}"
		return 1
	fi

	# Verify VM is actually accessible
	if ! verify_vm_health "$bsd_name"; then
		log_fail "VM started but is not accessible via SSH"
		log_info "This may indicate a name collision or networking issue"
		cat /tmp/vagrant-${bsd_name}.log | tail -20
		BSD_RESULTS[$bsd_name]="FAIL (VM inaccessible)"
		cd "${SCRIPT_DIR}"
		return 1
	fi

	log_ok "VM started successfully and is accessible"

	# Initialize test counters
	TEST_COUNTS["${bsd_name}_pass"]=0
	TEST_COUNTS["${bsd_name}_fail"]=0

	# Run build tests
	if [ $BUILD_TESTS -eq 1 ]; then
		run_build_tests "$bsd_name" || {
			cd "${SCRIPT_DIR}"
			return 1
		}
	fi

	# Run audit tests (only if build succeeded)
	if [ $AUDIT_TESTS -eq 1 ] && [ "${BSD_RESULTS[$bsd_name]:-OK}" != "FAIL (build)" ]; then
		run_audit_tests "$bsd_name" || true
	fi

	# Determine overall result
	local passed="${TEST_COUNTS["${bsd_name}_pass"]}"
	local failed="${TEST_COUNTS["${bsd_name}_fail"]}"

	if [ $failed -eq 0 ] && [ $passed -gt 0 ]; then
		BSD_RESULTS[$bsd_name]="PASS ($passed tests)"
		log_ok "All tests passed! ($passed passed, $failed failed)"
	else
		BSD_RESULTS[$bsd_name]="PARTIAL ($passed passed, $failed failed)"
		log_warn "Some tests failed ($passed passed, $failed failed)"
	fi

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
	log_header "Test Results Summary"
	echo ""

	local all_pass=true
	local total_pass=0
	local total_fail=0

	printf "  %-15s %-30s %s\n" "PLATFORM" "RESULT" "DETAILS"
	printf "  %-15s %-30s %s\n" "--------" "------" "-------"

	for bsd in freebsd openbsd netbsd dragonfly; do
		local result="${BSD_RESULTS[$bsd]:-NOT RUN}"
		local passed="${TEST_COUNTS["${bsd}_pass"]:-0}"
		local failed="${TEST_COUNTS["${bsd}_fail"]:-0}"

		total_pass=$((total_pass + passed))
		total_fail=$((total_fail + failed))

		if [[ "$result" == PASS* ]]; then
			printf "  %-15s ${GREEN}%-30s${NC} %d passed, %d failed\n" "${BSD_NAMES[$bsd]}" "$result" "$passed" "$failed"
		elif [[ "$result" == "NOT RUN" ]]; then
			printf "  %-15s ${YELLOW}%-30s${NC} -\n" "${BSD_NAMES[$bsd]}" "$result"
		else
			printf "  %-15s ${RED}%-30s${NC} %d passed, %d failed\n" "${BSD_NAMES[$bsd]}" "$result" "$passed" "$failed"
			all_pass=false
		fi
	done

	echo ""
	echo -e "  ${GREEN}Total Passed:${NC} $total_pass"
	echo -e "  ${RED}Total Failed:${NC} $total_fail"
	echo ""

	# Save results to file
	{
		echo "C-Sentinel BSD Test Results"
		echo "Date: $(date)"
		echo ""
		echo "Test Configuration:"
		echo "  Build Tests: $([ $BUILD_TESTS -eq 1 ] && echo 'enabled' || echo 'disabled')"
		echo "  Audit Tests: $([ $AUDIT_TESTS -eq 1 ] && echo 'enabled' || echo 'disabled')"
		echo ""
		for bsd in freebsd openbsd netbsd dragonfly; do
			echo "${BSD_NAMES[$bsd]}: ${BSD_RESULTS[$bsd]:-NOT RUN}"
		done
		echo ""
		echo "Total Passed: $total_pass"
		echo "Total Failed: $total_fail"
	} >"${RESULTS_FILE}"

	log_info "Results saved to ${RESULTS_FILE}"

	if $all_pass && [ $total_fail -eq 0 ]; then
		echo -e "${GREEN}✓ All tests passed!${NC}"
		return 0
	else
		echo -e "${YELLOW}⚠ Some tests failed or were skipped${NC}"
		return 1
	fi
}

usage() {
	cat <<EOF
C-Sentinel BSD Test Suite

Comprehensive test suite for FreeBSD, OpenBSD, NetBSD, and DragonFlyBSD.

Usage: $0 [options] [bsd...]

Options:
  --build-only        Run only build tests (faster)
  --audit-only        Run only audit tests (requires previous build)
  --keep              Keep VMs running after tests
  --clean             Remove all test VMs and exit
  --help, -h          Show this help

BSD Targets:
  all                 Test all BSD variants (default)
  freebsd             Test FreeBSD 14 only
  openbsd             Test OpenBSD 7 only
  netbsd              Test NetBSD 9 only
  dragonfly           Test DragonFlyBSD 6 only

Examples:
  $0                          # Test all BSDs (build + audit)
  $0 freebsd                  # Test FreeBSD only
  $0 --build-only             # Quick build test on all BSDs
  $0 freebsd openbsd --keep   # Test FreeBSD and OpenBSD, keep VMs
  $0 --clean                  # Clean up all VMs

EOF
}

# ============================================================
# Main
# ============================================================

# Parse arguments
while [[ $# -gt 0 ]]; do
	case "$1" in
	--clean)
		cleanup_all
		exit 0
		;;
	--build-only)
		BUILD_TESTS=1
		AUDIT_TESTS=0
		shift
		;;
	--audit-only)
		BUILD_TESTS=0
		AUDIT_TESTS=1
		shift
		;;
	--keep)
		KEEP_VMS=true
		shift
		;;
	--help | -h)
		usage
		exit 0
		;;
	all)
		TARGETS=(freebsd openbsd netbsd dragonfly)
		shift
		;;
	freebsd | openbsd | netbsd | dragonfly)
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

# Banner
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        C-Sentinel BSD Comprehensive Test Suite                ║${NC}"
echo -e "${CYAN}║        Testing: ${TARGETS[*]}$(printf '%*s' $((45 - ${#TARGETS[@]} * 10)) '')║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"

# Run tests
check_requirements
cleanup_stale_vms

for target in "${TARGETS[@]}"; do
	test_bsd "$target" || true

	if ! $KEEP_VMS; then
		cleanup_vm "$target"
	fi
done

print_summary
exit $?
