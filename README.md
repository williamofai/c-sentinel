# C-Sentinel

**Semantic Observability for UNIX Systems**

A lightweight, portable system prober written in C that captures "system fingerprints" for AI-assisted analysis of non-obvious risks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Version](https://img.shields.io/badge/version-0.3.0-blue)

## What's New in v0.3.0

- 🧠 **Baseline Learning** - Teach Sentinel what "normal" looks like, detect deviations
- 🌐 **Network Probe** - Monitor listening ports, established connections, unusual services
- 👁️ **Watch Mode** - Continuous monitoring with configurable intervals
- ⚙️ **Config File** - `~/.sentinel/config` for API keys, thresholds, webhooks
- 🔔 **Webhook Alerts** - Slack/Discord notifications on critical findings
- 📊 **Exit Codes** - CI/CD integration (0=OK, 1=WARN, 2=CRITICAL)

## The Problem

Modern observability tools like Dynatrace, Datadog, and Prometheus are excellent at metric collection and threshold alerting. But they answer a narrow question: *"Is this metric outside its expected range?"*

They struggle with:
- **Causal reasoning**: *Why* did something fail?
- **Context synthesis**: Connecting a config change last week to today's latency spike
- **Non-obvious degradation**: Things that aren't "broken" but are drifting toward failure
- **The "silent drift"**: Two servers that should be identical but have subtly diverged

C-Sentinel takes a different approach: capture a comprehensive system fingerprint and use LLM reasoning to identify the "ghosts in the machine."

## Quick Start

```bash
# Clone and build
git clone https://github.com/williamofai/c-sentinel.git
cd c-sentinel
make

# Quick analysis
./bin/sentinel --quick --network

# Learn what's "normal" for this system
./bin/sentinel --learn --network

# Later, detect deviations from normal
./bin/sentinel --baseline --network

# Continuous monitoring (every 5 minutes)
./bin/sentinel --watch --interval 300 --network

# Full AI-powered analysis
export ANTHROPIC_API_KEY="your-key"
./bin/sentinel --json --network | python3 sentinel_analyze.py
```

## Example Output

### Quick Analysis with Network
```
C-Sentinel Quick Analysis
========================
Hostname: axioma-validator
Uptime: 13.6 days
Load: 0.12 0.11 0.07
Memory: 44.3% used
Processes: 114 total

Potential Issues:
  Zombie processes: 0
  High FD processes: 0
  Long-running (>7d): 97
  Config permission issues: 0

Network:
  Listening ports: 25
  Established connections: 13
  Unusual ports: 11 ⚠

  Listeners:
    127.0.0.54:53 (tcp) - systemd-resolved
    0.0.0.0:80 (tcp) - nginx
    0.0.0.0:22 (tcp) - sshd
    0.0.0.0:443 (tcp) - nginx
    127.0.0.1:5432 (tcp) - postgres
    127.0.0.1:11434 (tcp) - ollama
    ... and 19 more
```

### Baseline Comparison
```
C-Sentinel Quick Analysis
========================
Hostname: axioma-validator
Uptime: 13.6 days
Load: 0.18 0.09 0.07
Processes: 114 total

Baseline Comparison
══════════════════════════════════════════════════
Baseline created: Thu Jan  1 23:36:16 2026
Samples learned: 2
Expected ports: 13
Tracked configs: 5

✓ System matches baseline - no deviations detected
```

### Deviation Detection
```
Baseline Comparison
══════════════════════════════════════════════════
Baseline created: Thu Jan  1 23:36:16 2026
Samples learned: 5
Expected ports: 13
Tracked configs: 5

⚠ DEVIATIONS DETECTED: 2
──────────────────────────────────────────────────
• NEW LISTENERS (1): 4444
• CONFIG CHANGES (1):
    - /etc/ssh/sshd_config
```

## Features

| Feature | Command | Description |
|---------|---------|-------------|
| Quick analysis | `--quick` | Human-readable summary |
| Network probe | `--network` | Listening ports & connections |
| Watch mode | `--watch --interval 60` | Continuous monitoring |
| Baseline learn | `--learn` | Save current state as "normal" |
| Baseline compare | `--baseline` | Detect deviations |
| JSON output | `--json` | Full fingerprint for LLM |
| Config | `--config` | Show current settings |

### Exit Codes (for CI/CD)

| Code | Meaning |
|------|---------|
| 0 | No issues detected |
| 1 | Warnings (minor issues) |
| 2 | Critical (zombies, permission issues, unusual ports) |
| 3 | Error (probe failed) |

## Configuration

Create a config file with `./bin/sentinel --init-config`, then edit `~/.sentinel/config`:

```ini
# API Keys
anthropic_api_key = sk-ant-...
ollama_host = http://localhost:11434

# Default AI model: claude, openai, or ollama
default_model = claude
ollama_model = llama3.2:3b

# Thresholds
zombie_threshold = 0
high_fd_threshold = 100
unusual_port_threshold = 3
memory_warn_percent = 80.0
memory_crit_percent = 95.0

# Webhook (Slack-compatible)
webhook_url = https://hooks.slack.com/services/...
webhook_on_critical = true
webhook_on_warning = false

# Watch mode defaults
default_interval = 60
network_by_default = false
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Python Orchestration                      │
│  • API communication        • Response parsing              │
│  • Policy validation        • User interface                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     C Foundation                             │
│  • /proc parsing            • JSON serialization            │
│  • Process analysis         • Sanitization                  │
│  • Config checksumming      • Drift detection               │
│  • Network probing          • Baseline learning             │
└─────────────────────────────────────────────────────────────┘
```

### Why C?

| Concern | Python | C |
|---------|--------|---|
| **Dependencies** | Requires Python runtime (~100MB) | Static binary (~76KB) |
| **Startup time** | ~500ms interpreter startup | ~1ms |
| **Memory** | ~30MB baseline | <2MB |
| **Portability** | Needs matching Python version | Runs on any POSIX system |

When you're probing a struggling production server, the last thing you want is your diagnostic tool consuming resources.

## What It Captures

| Category | Data | Purpose |
|----------|------|---------|
| System | Hostname, kernel, uptime, load, memory | Basic health context |
| Processes | Notable processes with metadata | Zombie, leak, stuck detection |
| Configs | File metadata and checksums | Drift detection |
| Network | Listeners, connections, ports | Service monitoring |

## What It Flags

- 🧟 **Zombie processes**: Always a problem
- 📂 **High FD counts**: Potential descriptor leaks (>100 open)
- ⏰ **Long-running processes**: >7 days without restart
- 🔓 **Permission issues**: World-writable configs
- 💾 **Memory hogs**: Processes >1GB RSS
- 🌐 **Unusual ports**: Services not in common ports list
- 📡 **New listeners**: Ports that weren't in baseline
- ❌ **Missing services**: Expected ports that stopped listening

## AI Integration

```bash
# With Anthropic Claude (cloud)
export ANTHROPIC_API_KEY="your-key"
./bin/sentinel --json --network | python3 sentinel_analyze.py

# With Ollama (local, free, private)
ollama pull llama3.2:3b
./bin/sentinel --json --network | python3 sentinel_analyze.py --local
```

The Python wrapper includes:
- **Policy Engine**: Validates AI suggestions before display
- **Sanitizer**: Strips IPs, secrets, and PII before API transmission
- **Safe command detection**: Blocks dangerous commands regardless of AI reasoning

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

## Project Structure

```
c-sentinel/
├── include/
│   ├── sentinel.h      # Core data structures & baseline types
│   ├── policy.h        # Safety gate API
│   └── sanitize.h      # Data sanitization API
├── src/
│   ├── main.c          # CLI entry point
│   ├── prober.c        # System probing (/proc)
│   ├── net_probe.c     # Network probing (/proc/net)
│   ├── baseline.c      # Baseline learning & comparison
│   ├── config.c        # Config file parsing
│   ├── alert.c         # Webhook alerting
│   ├── json_serialize.c # JSON output generation
│   ├── policy.c        # Command validation engine
│   ├── sanitize.c      # PII/secret stripping
│   └── diff.c          # Fingerprint comparison
├── sentinel_analyze.py # Python wrapper for LLM integration
├── Makefile
├── README.md
├── DESIGN_DECISIONS.md
└── LICENSE
```

## Roadmap

- [x] Core system prober
- [x] JSON serialization  
- [x] Policy engine (command validation)
- [x] Sanitizer (PII stripping)
- [x] Drift detection (sentinel-diff)
- [x] Python wrapper with Claude integration
- [x] Network probing
- [x] Watch mode
- [x] Baseline learning
- [x] Config file support
- [x] Webhook alerts
- [ ] SHA256 checksums (replace simple hash)
- [ ] Systemd service unit
- [ ] Web dashboard
- [ ] Multi-host aggregation
- [ ] Plugin system for application-specific probes
- [ ] FreeBSD/macOS support

## Contributing

Contributions welcome! Areas of particular interest:

- **Platform support**: BSD, macOS, Solaris
- **Application probers**: nginx, postgres, redis, etc.
- **Sanitization patterns**: Help identify sensitive data patterns
- **Test coverage**: Edge cases and failure modes

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**William Murray** - 30 years UNIX systems engineering

- GitHub: [@williamofai](https://github.com/williamofai)
- LinkedIn: [William Murray](https://www.linkedin.com/in/william-murray-5180aa32b/)

---

*"The goal isn't to replace monitoring tools—it's to add wisdom to their data."*
