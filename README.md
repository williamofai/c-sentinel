# C-Sentinel

**Semantic Observability for UNIX Systems**

A lightweight, portable system prober written in C that captures "system fingerprints" for AI-assisted analysis of non-obvious risks. Now with auditd integration and a live web dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Version](https://img.shields.io/badge/version-0.4.0-blue)

**Live Demo**: [sentinel.speytech.com](https://sentinel.speytech.com)

![Dashboard Screenshot](docs/main-dashboard.png)

## What's New in v0.4.0

- 🔐 **Auditd Integration** - Security event summarisation with semantic analysis
- 🚨 **Brute Force Detection** - Automatic detection of auth failure spikes
- 👤 **Privacy-Preserving** - Username hashing protects identity while preserving patterns
- 🔗 **Process Attribution** - Know *which process* accessed sensitive files
- 📊 **Risk Scoring** - Deviation-aware scoring with baseline comparison
- 🎯 **Process Chains** - Track process ancestry for context (best-effort)

### Previous Releases

**v0.3.0**: Web Dashboard, SHA256 checksums, systemd service, baseline learning, network probe, watch mode, webhooks

## The Problem

Modern observability tools like Dynatrace, Datadog, and Prometheus are excellent at metric collection and threshold alerting. But they answer a narrow question: *"Is this metric outside its expected range?"*

They struggle with:
- **Causal reasoning**: *Why* did something fail?
- **Context synthesis**: Connecting a config change last week to today's latency spike
- **Non-obvious degradation**: Things that aren't "broken" but are drifting toward failure
- **Security context**: Understanding *who* accessed *what* and *why it matters*

C-Sentinel takes a different approach: capture a comprehensive system fingerprint—including security events—and use LLM reasoning to identify the "ghosts in the machine."

## Quick Start

```bash
# Clone and build
git clone https://github.com/williamofai/c-sentinel.git
cd c-sentinel
make

# Quick analysis
./bin/sentinel --quick --network

# Quick analysis with security events (requires root for audit logs)
sudo ./bin/sentinel --quick --network --audit

# Learn baselines
./bin/sentinel --learn --network
sudo ./bin/sentinel --audit-learn

# Continuous monitoring with full context
sudo ./bin/sentinel --watch --interval 300 --network --audit
```

## Auditd Integration

C-Sentinel can summarise auditd logs for semantic security analysis.

### Example Output

```
C-Sentinel Quick Analysis
========================
Hostname: axioma-validator
Uptime: 14.5 days
Load: 0.02 0.04 0.00
Memory: 49.2% used
Processes: 120 total

Potential Issues:
  Zombie processes: 0
  High FD processes: 1
  Long-running (>7d): 95
  Config permission issues: 0

Network:
  Listening ports: 26
  Established connections: 14
  Unusual ports: 12 ⚠

Security (audit):
  Auth failures: 6
  ⚠ BRUTE FORCE PATTERN DETECTED
  Sudo commands: 81
  Sensitive file access: 2
    - /etc/passwd by touch
    - /etc/shadow by touch ⚠

  Risk: high (score: 25)
```

### JSON Output

```json
{
  "audit_summary": {
    "enabled": true,
    "period_seconds": 300,
    "authentication": {
      "failures": 6,
      "failure_users_hashed": ["user_c4c5", "user_b91b"],
      "brute_force_detected": true
    },
    "privilege_escalation": {
      "sudo_count": 81,
      "su_count": 5
    },
    "file_integrity": {
      "sensitive_file_access": [
        {
          "path": "/etc/shadow",
          "access": "write",
          "count": 2,
          "process": "touch",
          "process_chain": ["touch"],
          "suspicious": true
        }
      ]
    },
    "risk_score": 25,
    "risk_level": "high"
  }
}
```

### Setup Audit Rules

For best results, add audit rules for sensitive files:

```bash
# Add audit rules
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -w /etc/shadow -p wa -k identity
sudo auditctl -w /etc/sudoers -p wa -k priv_esc
sudo auditctl -w /var/log/lastlog -p wa -k auth

# Make permanent (add to /etc/audit/rules.d/sentinel.rules)
```

### Privacy Features

- **Username hashing**: Failed login usernames are hashed (e.g., `user_c4c5`) preserving pattern detection without exposing identities
- **No passwords**: Command arguments and sensitive data never captured
- **Process names only**: Full paths sanitised for privacy

## Web Dashboard

C-Sentinel includes a web dashboard for monitoring multiple hosts in real-time.

### Features

- **Real-time host monitoring** - See all hosts at a glance
- **Historical charts** - Memory and load over 24 hours  
- **Network view** - All listening ports and connections
- **Config tracking** - SHA256 checksums of monitored files
- **Multi-host support** - Monitor your entire fleet

### Quick Setup

```bash
# Install dashboard
cd dashboard
sudo ./install-dashboard.sh

# Configure agent to report (with audit)
*/5 * * * * sudo /usr/local/bin/sentinel --json --network --audit | curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d @- https://your-dashboard.com/api/ingest
```

See [dashboard/README.md](dashboard/README.md) for full setup instructions.

## Systemd Service

For production deployment:

```bash
# Install
sudo ./install.sh

# Enable and start
sudo systemctl enable sentinel
sudo systemctl start sentinel

# Check status
sudo journalctl -u sentinel -f
```

## All Features

| Feature | Command | Description |
|---------|---------|-------------|
| Quick analysis | `--quick` | Human-readable summary |
| Network probe | `--network` | Listening ports & connections |
| **Audit probe** | `--audit` | Security events (requires root) |
| Watch mode | `--watch --interval 60` | Continuous monitoring |
| Baseline learn | `--learn` | Save current state as "normal" |
| **Audit baseline** | `--audit-learn` | Learn normal security patterns |
| Baseline compare | `--baseline` | Detect deviations |
| JSON output | `--json` | Full fingerprint for LLM/dashboard |
| Config | `--config` | Show current settings |

### Exit Codes (for CI/CD)

| Code | Meaning |
|------|---------|
| 0 | No issues detected |
| 1 | Warnings (minor issues) |
| 2 | Critical (zombies, permission issues, unusual ports, **high-risk security events**) |
| 3 | Error (probe failed) |

## What It Captures

| Category | Data | Purpose |
|----------|------|---------|
| System | Hostname, kernel, uptime, load, memory | Basic health context |
| Processes | Notable processes with metadata | Zombie, leak, stuck detection |
| Configs | File metadata + SHA256 checksums | Cryptographic drift detection |
| Network | Listeners, connections, ports | Service monitoring |
| **Security** | Auth failures, sudo usage, file access | Threat detection |

## What It Flags

### System Issues
- 🧟 **Zombie processes**: Always a problem
- 📂 **High FD counts**: Potential descriptor leaks (>100 open)
- ⏰ **Long-running processes**: >7 days without restart
- 🔓 **Permission issues**: World-writable configs

### Network Issues
- 🌐 **Unusual ports**: Services not in common ports list
- 📡 **New listeners**: Ports that weren't in baseline
- ❌ **Missing services**: Expected ports that stopped listening

### Security Issues (with --audit)
- 🔐 **Brute force**: Auth failure spikes (>5 in window)
- 📊 **Baseline deviation**: Activity significantly above normal
- 📁 **Sensitive file access**: /etc/shadow, /etc/sudoers modifications
- ⚠️ **Suspicious processes**: Unusual process accessing sensitive files

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Dashboard                          │
│  • Multi-host view          • Historical charts             │
│  • Network listeners        • Security summary              │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ JSON via HTTP POST
                              │
┌─────────────────────────────────────────────────────────────┐
│                     C Foundation (99KB)                     │
│  • /proc parsing            • SHA256 checksums              │
│  • Process analysis         • Drift detection               │
│  • Network probing          • Baseline learning             │
│  • Auditd parsing           • Risk scoring                  │
└─────────────────────────────────────────────────────────────┘
```

### Why C?

| Concern | Python | C |
|---------|--------|---|
| **Dependencies** | Requires Python runtime (~100MB) | Static binary (~99KB) |
| **Startup time** | ~500ms interpreter startup | ~1ms |
| **Memory** | ~30MB baseline | <2MB |
| **Portability** | Needs matching Python version | Runs on any POSIX system |

## Building

```bash
make              # Release build
make DEBUG=1      # Debug build with symbols
make test         # Run basic tests
make install      # Install to /usr/local/bin
```

### Requirements
- GCC or Clang with C99 support
- GNU Make
- Linux (uses `/proc` filesystem)
- auditd (optional, for `--audit` flag)

## Project Structure

```
c-sentinel/
├── include/
│   ├── sentinel.h        # Core data structures
│   └── audit.h           # Audit integration types
├── src/
│   ├── main.c            # CLI entry point
│   ├── prober.c          # System probing (/proc)
│   ├── net_probe.c       # Network probing
│   ├── audit.c           # Auditd log parsing
│   ├── audit_json.c      # Audit JSON serialisation
│   ├── process_chain.c   # Process ancestry walking
│   ├── baseline.c        # Baseline learning
│   ├── sha256.c          # Pure C SHA256
│   └── ...
├── dashboard/            # Flask web dashboard
├── deploy/               # Systemd service files
└── docs/
    └── AUDIT_SPEC.md     # Audit integration design
```

## Roadmap

### Completed ✅
- [x] Core system prober
- [x] JSON serialization  
- [x] Network probing
- [x] Watch mode & baseline learning
- [x] SHA256 checksums
- [x] Systemd service
- [x] Web dashboard
- [x] **Auditd integration**
- [x] **Risk scoring with deviation analysis**
- [x] **Process attribution**

### Planned 📋
- [x] **Dashboard Security tab**
- [ ] Dashboard authentication
- [ ] Email alerts
- [ ] FreeBSD/macOS support

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**William Murray** - 30 years UNIX systems engineering

- GitHub: [@williamofai](https://github.com/williamofai)
- LinkedIn: [William Murray](https://www.linkedin.com/in/william-murray-5180aa32b/)
- Website: [speytech.com](https://speytech.com)

---

*"The goal isn't to replace monitoring tools—it's to add wisdom to their data."*
