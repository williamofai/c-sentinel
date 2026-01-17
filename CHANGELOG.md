# Changelog

All notable changes to C-Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **DragonFlyBSD support** - Full platform support in Makefile
- **Improved BSD test infrastructure** - Comprehensive test suite with robust error handling
  - VM health verification after startup
  - Stale VM cleanup to prevent name collisions
  - Enhanced error detection and reporting
  - Consolidated test scripts (removed test-bsd-all.sh and test-bsd-audit-vagrant.sh)

### Fixed
- **OpenBSD header inclusion order** - Fixed compilation issues with sys/types.h ordering
- **Audit backend detection** - Enhanced detection for dormant OpenBSM installations
- **Audit JSON output** - Include audit section even when disabled for consistent schema
- **Portability** - Fixed isdigit() cast for BSD compatibility

### Changed
- Test infrastructure now uses single comprehensive test-bsd.sh script

## [0.5.8] - 2026-01-03

### Added
- **Dashboard authentication** - Password-protected access with session management
- **Event History tab** - Filterable audit event log with timestamps and acknowledge functionality
- **Risk factors explanation** - "Why This Score?" section showing weighted risk contributors
- **Confidence indicator** - Learning/Calibrating badge showing baseline sample count
- **Email alerts** - SMTP integration for high-risk events and brute force detection
- **Security posture summary** - Natural language assessment of system health
- **Risk trend sparkline** - 24-hour mini chart showing risk score history
- **Cumulative totals** - Persistent counters that survive probe windows
- **Reset functionality** - Clear acknowledged events and cumulative counters

### Fixed
- Time window handling now locale-aware for international deployments
- Session cookie persistence across restarts
- Audit data no longer resets to zero between probe windows

## [0.4.0] - 2026-01-02

### Added
- **Auditd integration** - Security event summarisation with semantic analysis
- **Brute force detection** - Automatic detection of authentication failure spikes
- **Privacy-preserving usernames** - SHA256 hashing protects identity while preserving patterns
- **Process attribution** - Track which process accessed sensitive files
- **Process chains** - Ancestry tracking (best-effort for long-running processes)
- **Risk scoring** - Deviation-aware scoring with baseline comparison
- **Dashboard Security tab** - Visual security summary with risk badges
- Database schema upgrade for audit metrics

### Changed
- Binary size increased to 99KB (from 76KB) to accommodate audit features
- Systemd service now includes `--audit` flag by default

## [0.3.0] - 2026-01-01

### Added
- **Web Dashboard** - Flask-based multi-host monitoring interface
- **SHA256 checksums** - Cryptographic config file integrity tracking
- **Systemd service** - Production deployment with auto-restart
- **Baseline learning** - Learn normal patterns with `--learn` flag
- **Network probe** - Listener and connection monitoring
- **Watch mode** - Continuous monitoring with configurable intervals
- **Webhook support** - POST fingerprints to external endpoints

## [0.2.0] - 2025-12-28

### Added
- Network probing (`--network` flag)
- Connection state tracking (ESTABLISHED, LISTEN, etc.)
- Unusual port detection
- Process-to-port correlation

## [0.1.0] - 2025-12-25

### Added
- Initial release
- Core system prober (CPU, memory, load, uptime)
- Process analysis (zombies, high FD, long-running)
- Config file monitoring with metadata
- JSON output for LLM analysis
- Quick mode (`--quick`) for human-readable summary
- Exit codes for CI/CD integration (0=ok, 1=warning, 2=critical, 3=error)

---

## Upgrade Notes

### Upgrading to 0.5.8

1. Update dashboard files and restart:
   ```bash
   sudo systemctl restart sentinel-dashboard
   ```

2. Run database migration for cumulative totals:
   ```sql
   ALTER TABLE hosts ADD COLUMN IF NOT EXISTS audit_totals_since TIMESTAMP DEFAULT NOW();
   ALTER TABLE hosts ADD COLUMN IF NOT EXISTS audit_auth_failures_total INTEGER DEFAULT 0;
   ALTER TABLE hosts ADD COLUMN IF NOT EXISTS audit_sudo_count_total INTEGER DEFAULT 0;
   ALTER TABLE hosts ADD COLUMN IF NOT EXISTS audit_file_access_total INTEGER DEFAULT 0;
   ALTER TABLE hosts ADD COLUMN IF NOT EXISTS audit_brute_force_total INTEGER DEFAULT 0;
   ```

3. Configure email alerts in `.env`:
   ```
   SMTP_HOST=smtp.example.com
   SMTP_PORT=587
   SMTP_USER=alerts@example.com
   SMTP_PASS=your-app-password
   ALERT_EMAIL=admin@example.com
   ALERT_THRESHOLD=20
   ```

### Upgrading to 0.4.0

1. Rebuild the binary:
   ```bash
   make clean && make
   sudo cp bin/sentinel /usr/local/bin/
   ```

2. Add audit rules for full functionality:
   ```bash
   sudo auditctl -w /etc/passwd -p wa -k identity
   sudo auditctl -w /etc/shadow -p wa -k identity
   sudo auditctl -w /etc/sudoers -p wa -k priv_esc
   ```

3. Update systemd service to include `--audit` flag
