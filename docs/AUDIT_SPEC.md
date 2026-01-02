# C-Sentinel Auditd Integration Specification

## Overview

Add `--audit` flag to ingest and summarise auditd logs, providing security-relevant context for semantic analysis.

## Design Principles

### 1. Security First
- **Omit successful logins** - Only surface failures and anomalies
- **No sensitive data in output** - No passwords, tokens, or full command arguments
- **Hash usernames** - Use salted hash (e.g., `user_8f3d`) for privacy while preserving pattern detection
- **No IP addresses in public dashboard** - Keep in JSON, redact in UI

### 2. Summarise, Don't Dump
- Aggregate counts, not raw logs
- Pattern detection, not log forwarding
- Time-windowed (last N minutes or since last run)

### 3. Context is Everything
- **Process ancestry** - Not just "what" but "who spawned it"
- **Baseline deviation** - Not just "3 failures" but "400% above normal"
- Enables LLM to reason about *stories*, not just events

### 4. Complementary
- Adds context to existing fingerprint
- Doesn't replace auditd/SIEM
- Enables LLM reasoning about security posture

---

## Proposed JSON Structure

```json
{
  "audit_summary": {
    "enabled": true,
    "period_seconds": 300,
    "log_source": "/var/log/audit/audit.log",
    
    "authentication": {
      "failures": 3,
      "failure_users_hashed": ["user_8f3d", "user_a1b2"],
      "failure_sources": 2,
      "baseline_avg": 0.6,
      "deviation_pct": 400.0,
      "brute_force_detected": true
    },
    
    "privilege_escalation": {
      "sudo_count": 12,
      "sudo_baseline_avg": 10.0,
      "sudo_deviation_pct": 20.0,
      "su_count": 0,
      "setuid_executions": 0,
      "capability_changes": 0
    },
    
    "file_integrity": {
      "permission_changes": 2,
      "ownership_changes": 0,
      "sensitive_file_access": [
        {
          "path": "/etc/shadow",
          "access": "read",
          "count": 1,
          "process": "python3",
          "process_chain": ["sshd", "bash", "python3"],
          "suspicious": true
        },
        {
          "path": "/etc/passwd",
          "access": "read",
          "count": 3,
          "process": "cat",
          "process_chain": ["sshd", "bash", "cat"],
          "suspicious": false
        }
      ]
    },
    
    "process_activity": {
      "unusual_executions": [
        {
          "path": "/tmp/.hidden/shell",
          "parent_process": "apache2",
          "process_chain": ["systemd", "apache2", "shell"],
          "suspicious": true
        }
      ],
      "tmp_executions": 1,
      "devshm_executions": 0,
      "shell_spawns": 4,
      "cron_executions": 7
    },
    
    "network_audit": {
      "new_listeners": 0,
      "outbound_connections": 15,
      "firewall_changes": 0
    },
    
    "security_framework": {
      "selinux_enforcing": true,
      "selinux_avc_denials": 2,
      "apparmor_denials": 0
    },
    
    "anomalies": [
      {
        "severity": "high",
        "type": "auth_failure_spike",
        "description": "3 failed logins in 5 minutes",
        "current": 3,
        "baseline_avg": 0.6,
        "deviation_pct": 400.0,
        "timestamp": "2026-01-02T17:42:00Z"
      },
      {
        "severity": "critical",
        "type": "suspicious_process_chain",
        "description": "Web server spawned shell in /tmp",
        "process_chain": ["apache2", "/tmp/.hidden/shell"],
        "timestamp": "2026-01-02T17:43:00Z"
      }
    ],
    
    "risk_score": 18,
    "risk_level": "high"
  }
}
```

---

## Process Ancestry (The "Ballache" Worth Doing)

### Why It Matters

| Without Ancestry | With Ancestry |
|------------------|---------------|
| `/etc/shadow` accessed by `python3` | `/etc/shadow` accessed by `python3` spawned by `apache2` |
| "Might be legitimate" | "Web server reading shadow file = incident" |

### Implementation

```c
// Walk /proc/<pid>/stat to build process chain
char** get_process_chain(pid_t pid, int *depth) {
    char **chain = malloc(sizeof(char*) * MAX_CHAIN_DEPTH);
    int i = 0;
    
    while (pid > 1 && i < MAX_CHAIN_DEPTH) {
        chain[i++] = get_process_name(pid);
        pid = get_parent_pid(pid);  // Read ppid from /proc/<pid>/stat
    }
    
    *depth = i;
    return chain;
}
```

### What We Capture

- **Max depth:** 5 levels (usually enough: systemd → sshd → bash → python → child)
- **Store:** Process name only (not full path for privacy)
- **Flag suspicious patterns:**
  - Web server → shell
  - Cron → network tool
  - Database → file write outside data dir

---

## Rolling Baseline with Deviation Detection

### Why Static Thresholds Fail

| Static | Contextual |
|--------|------------|
| "3 auth failures = warning" | "3 auth failures = normal for Monday morning" |
| "3 auth failures = warning" | "3 auth failures = 400% above baseline for 2am Saturday" |

### Implementation (Extend existing baseline.c)

```c
#define BASELINE_FILE "/var/lib/sentinel/audit_baseline.dat"
#define EMA_ALPHA 0.2  // Smoothing factor - recent data weighted 20%

typedef struct {
    float avg_auth_failures;
    float avg_sudo_count;
    float avg_sensitive_access;
    float avg_tmp_executions;
    uint32_t sample_count;
    time_t last_updated;
} audit_baseline_t;

// Exponential Moving Average update
void update_audit_baseline(audit_baseline_t *base, const audit_summary_t *current) {
    if (base->sample_count == 0) {
        // First sample - use as initial baseline
        base->avg_auth_failures = current->auth_failures;
        base->avg_sudo_count = current->sudo_count;
    } else {
        // EMA: new_avg = (current * alpha) + (old_avg * (1 - alpha))
        base->avg_auth_failures = 
            (current->auth_failures * EMA_ALPHA) + 
            (base->avg_auth_failures * (1 - EMA_ALPHA));
        base->avg_sudo_count = 
            (current->sudo_count * EMA_ALPHA) + 
            (base->avg_sudo_count * (1 - EMA_ALPHA));
    }
    base->sample_count++;
    base->last_updated = time(NULL);
}

// Calculate deviation percentage
float calculate_deviation(float current, float baseline_avg) {
    if (baseline_avg < 0.1) {
        // Baseline near zero - any activity is significant
        return current > 0 ? 100.0 : 0.0;
    }
    return ((current - baseline_avg) / baseline_avg) * 100.0;
}

// Determine significance
const char* deviation_significance(float deviation_pct) {
    if (deviation_pct > 500.0) return "CRITICAL";
    if (deviation_pct > 200.0) return "HIGH";
    if (deviation_pct > 100.0) return "MEDIUM";
    if (deviation_pct > 50.0) return "LOW";
    return "NORMAL";
}
```

### Baseline Storage

- **Location:** `/var/lib/sentinel/audit_baseline.dat`
- **Format:** Binary struct (fast read/write)
- **Update:** Every probe run
- **Decay:** EMA naturally decays old data (alpha = 0.2 means ~90% forgotten after 10 samples)

---

## Username Hashing (Privacy-Preserving Pattern Detection)

### Why Hash?

The LLM needs to know "same user failing repeatedly" without knowing the actual username.

### Implementation

```c
#include <openssl/sha.h>  // Or use our existing sha256.c!

// We already have SHA256 - reuse it!
void hash_username(const char *username, const char *salt, char *output) {
    char salted[256];
    snprintf(salted, sizeof(salted), "%s:%s", salt, username);
    
    char hash[65];
    sha256_string(salted, hash);
    
    // Take first 8 chars for readability
    snprintf(output, 12, "user_%c%c%c%c", hash[0], hash[1], hash[2], hash[3]);
}

// Example:
// "root" + salt "sentinel" → "user_8f3d"
// "admin" + salt "sentinel" → "user_a1b2"
```

### Salt Management

- **System-unique salt:** Generated on first run, stored in `/var/lib/sentinel/salt`
- **Consistent:** Same username always hashes to same value on that system
- **Not reversible:** Can't recover username from hash

---

## Suspicious Pattern Detection

### High-Value Patterns to Flag

| Pattern | Why Suspicious | Detection |
|---------|----------------|-----------|
| Web server → shell | Classic web exploit | Parent is nginx/apache/httpd, child is sh/bash/python |
| `/tmp` execution | Malware staging area | execve path starts with `/tmp/` |
| `/dev/shm` execution | Memory-only malware | execve path starts with `/dev/shm/` |
| Database → file write | Data exfiltration | Parent is postgres/mysql, child writes outside data dir |
| Cron → network tool | C2 callback | Parent is cron, child is curl/wget/nc |
| SUID binary creation | Privilege escalation | chmod +s on any file |

### Implementation

```c
typedef struct {
    const char *parent_pattern;
    const char *child_pattern;
    const char *description;
    int severity;  // 1-10
} suspicious_pattern_t;

static const suspicious_pattern_t SUSPICIOUS_PATTERNS[] = {
    {"apache", "sh",     "Web server spawned shell", 9},
    {"apache", "bash",   "Web server spawned shell", 9},
    {"nginx",  "sh",     "Web server spawned shell", 9},
    {"httpd",  "python", "Web server spawned script", 7},
    {"cron",   "curl",   "Cron job making HTTP request", 5},
    {"cron",   "wget",   "Cron job downloading file", 5},
    {"cron",   "nc",     "Cron job using netcat", 8},
    {NULL, NULL, NULL, 0}
};

bool is_suspicious_chain(const char **chain, int depth, const char **description) {
    for (int i = 0; i < depth - 1; i++) {
        for (const suspicious_pattern_t *p = SUSPICIOUS_PATTERNS; p->parent_pattern; p++) {
            if (strstr(chain[i], p->parent_pattern) && 
                strstr(chain[i+1], p->child_pattern)) {
                *description = p->description;
                return true;
            }
        }
    }
    return false;
}
```

---

## What We Capture vs Omit

### ✅ Capture (Summarised)

| Category | What | Why |
|----------|------|-----|
| Auth failures | Count + hashed users + deviation% | Indicates brute force, preserves privacy |
| Sudo usage | Count + baseline deviation | Baseline for privilege escalation |
| Sensitive file access | Path + process chain | Full context for LLM reasoning |
| Permission changes | Count + paths | chmod/chown on sensitive files |
| Unusual processes | Binary + parent chain | Process ancestry tells the story |
| `/tmp` and `/dev/shm` executions | Path + parent | Classic malware indicators |
| New listeners | Port only | Network changes |
| SELinux/AppArmor denials | Count | "System shield is firing" |

### ❌ Omit (Privacy/Security)

| Category | Why Omitted |
|----------|-------------|
| Successful logins | Not anomalous, noisy |
| Raw usernames | Use hashed version instead |
| Full command arguments | Could contain secrets |
| IP addresses (in dashboard) | Privacy, keep in JSON only |
| File contents | Never captured |
| Password hashes | Never captured |
| Session tokens | Never captured |
| Full paths for user files | Privacy |

---

## Dashboard Considerations

### Public Dashboard (sentinel.speytech.com)

The dashboard is currently **unauthenticated**. For auditd data:

#### Option A: Redacted View (Recommended)
```
Authentication: 3 failures (details hidden)
Privilege: 12 sudo commands
Risk Level: LOW
```

#### Option B: Authenticated Section
- Add simple auth (API key in cookie)
- Full audit data behind login
- Public view shows only risk score

#### Option C: Separate Endpoint
- `/api/hosts/<name>/audit` requires auth
- Main dashboard shows summary only

### Recommendation

**Phase 1:** Implement Option A (redacted public view)
- Show counts and risk level only
- Full JSON available via authenticated API
- Add `?redact=true` parameter for public endpoints

**Phase 2:** Add dashboard authentication
- Simple login (single admin password)
- Full audit details for authenticated users

---

## CLI Usage

```bash
# Include audit summary
sentinel --audit

# Audit with network (full security picture)
sentinel --audit --network

# Audit with custom time window (last 10 minutes)
sentinel --audit --audit-window 600

# Audit with specific log path
sentinel --audit --audit-log /var/log/audit/audit.log

# JSON output with audit
sentinel --json --audit --network
```

---

## Implementation Plan

### Phase 1: Core Parsing (src/audit.c)

```c
// New source file: src/audit.c (~400 lines)

typedef struct {
    int auth_failures;
    int sudo_count;
    int permission_changes;
    int sensitive_access_count;
    int risk_score;
    char risk_level[16];
    // ... more fields
} audit_summary_t;

// Parse audit.log or use ausearch
audit_summary_t* probe_audit(int window_seconds);

// Output as JSON
void audit_to_json(audit_summary_t *summary, FILE *out);
```

### Phase 2: Anomaly Detection

```c
// Compare against baseline
typedef struct {
    float avg_auth_failures;
    float avg_sudo_count;
    // ... rolling averages
} audit_baseline_t;

// Flag anomalies
void detect_audit_anomalies(audit_summary_t *current, audit_baseline_t *baseline);
```

### Phase 3: Dashboard Integration

```python
# app.py additions
@app.route('/api/hosts/<hostname>/audit')
@require_api_key  # Authenticated only
def get_audit_details(hostname):
    ...

# Redacted version for public
def redact_audit_summary(audit_data):
    return {
        'risk_level': audit_data.get('risk_level'),
        'risk_score': audit_data.get('risk_score'),
        'auth_failures': audit_data.get('authentication', {}).get('failures', 0),
        'anomaly_count': len(audit_data.get('anomalies', []))
    }
```

---

## Auditd Rules (Recommended)

For C-Sentinel to be useful, the host needs appropriate audit rules:

```bash
# /etc/audit/rules.d/c-sentinel.rules

# Authentication
-w /var/log/faillog -p wa -k auth
-w /var/log/lastlog -p wa -k auth

# Privilege escalation
-w /etc/sudoers -p wa -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc

# Sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd

# Network
-a always,exit -F arch=b64 -S bind -k network

# Cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron -p wa -k cron
```

---

## Risk Scoring (Deviation-Aware)

### Base Points (Static)

| Event | Points |
|-------|--------|
| Auth failure | +1 |
| Auth failure (root/admin) | +3 |
| Sensitive file access | +2 |
| Permission change on /etc | +3 |
| New SUID binary | +5 |
| `/tmp` execution | +4 |
| `/dev/shm` execution | +6 |
| SELinux/AppArmor denial | +1 |

### Deviation Multiplier (Dynamic)

| Deviation from Baseline | Multiplier |
|-------------------------|------------|
| < 50% above | 1.0x |
| 50-100% above | 1.5x |
| 100-200% above | 2.0x |
| 200-500% above | 3.0x |
| > 500% above | 5.0x |

### Process Chain Bonus

| Pattern | Bonus Points |
|---------|--------------|
| Web server → shell | +10 |
| Cron → network tool | +5 |
| Database → unexpected child | +7 |
| Any → `/tmp` execution | +4 |

### Example Calculation

```
3 auth failures:           3 × 1 = 3 points
  → 400% above baseline:   3 × 3.0 multiplier = 9 points
  
/etc/shadow access:        2 points
  → via python from sshd:  normal (no bonus)
  
/tmp execution:            4 points
  → from apache2:          +10 bonus = 14 points
  
Total: 9 + 2 + 14 = 25 points → HIGH risk
```

**Risk Levels:**
- 0-5: `low`
- 6-15: `medium`  
- 16-30: `high`
- 31+: `critical`

---

## Example LLM Analysis Prompt

With full audit context, the LLM prompt becomes much richer:

```
System fingerprint for axioma-validator:
- 122 processes, 46% memory, 14.3d uptime
- 26 listeners (12 unusual)
- Config checksums: no changes

Audit summary (last 5 minutes):
- 3 authentication failures (users: user_8f3d, user_a1b2)
  → 400% above baseline (normally 0.6/period)
  → Significance: HIGH
- 12 sudo commands (20% above baseline - normal variance)
- /etc/shadow accessed by python3
  → Process chain: sshd → bash → python3
  → Flagged: script accessing sensitive file
- 2 SELinux AVC denials (policy blocking something)
- Risk level: HIGH (score: 18)

Anomalies detected:
1. auth_failure_spike: 400% above baseline
2. suspicious_process_chain: python3 reading /etc/shadow via sshd session

What's your assessment?
```

**Without context:** "3 failed logins, shadow file accessed"
**With context:** "Brute force attempt (400% above normal), followed by successful login, then script accessing shadow file from that session"

That's a *story*. That's what an LLM can reason about.

---

## What We Deferred (Not Over-Engineering)

These are valid features but premature for Phase 1:

| Feature | Why Deferred |
|---------|--------------|
| Hash chain / cryptographic signing | Enterprise audit compliance - add when someone needs it |
| Automated remediation | Observability ≠ Response. Tool informs, human/LLM decides |
| Time-of-day baselines | "Monday afternoon normal" adds complexity - simple EMA first |
| Full syscall tracing | That's what auditd itself does - we summarise, not replicate |

---

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `src/audit.c` | Create | Audit log parsing and summarisation |
| `src/audit.h` | Create | Header for audit types and functions |
| `src/process_chain.c` | Create | Process ancestry walking (/proc/pid/stat) |
| `src/audit_baseline.c` | Create | Rolling EMA baseline for audit metrics |
| `src/main.c` | Modify | Add --audit flag handling |
| `src/output.c` | Modify | Add audit JSON output |
| `include/sentinel.h` | Modify | Add audit structures |
| `dashboard/app.py` | Modify | Add audit endpoints with redaction |
| `dashboard/templates/host.html` | Modify | Add audit tab (redacted) |
| `Makefile` | Modify | Add new source files to build |

---

## Timeline Estimate

| Phase | Effort | Description |
|-------|--------|-------------|
| Phase 1 | 2-3 hours | Core audit.c parsing + JSON output |
| Phase 2 | 2-3 hours | Process chain walking (the "ballache") |
| Phase 3 | 1-2 hours | Rolling baseline with deviation % |
| Phase 4 | 1 hour | Username hashing + privacy controls |
| Phase 5 | 1-2 hours | Dashboard integration (redacted view) |
| Phase 6 | 1 hour | Documentation |

**Total: ~8-12 hours**

---

## Security Checklist

Before release:

- [ ] No sensitive data in default JSON output
- [ ] IP addresses redacted in public dashboard  
- [ ] Successful logins never logged
- [ ] Usernames hashed with system-unique salt
- [ ] Command arguments truncated/sanitised
- [ ] File contents never captured
- [ ] Audit endpoint requires authentication
- [ ] Process chains limited to 5 depth (no infinite loops)
- [ ] Salt file permissions 0600
- [ ] Baseline file permissions 0600
- [ ] Risk score algorithm documented
- [ ] Privacy section in README
- [ ] "Learning mode" clearly indicated in output

---

## Open Questions

1. **ausearch vs raw parsing?**
   - `ausearch` is easier but requires auditd tools installed
   - Raw parsing is more portable but complex
   - **Recommendation:** Try ausearch first, fall back to raw if not available

2. **Process chain depth?**
   - Deeper = more context but more overhead
   - **Recommendation:** Max 5 levels (covers 99% of cases)

3. **SELinux/AppArmor events?**
   - **Resolved:** Yes, include denial counts. Low effort, high signal.

4. **Baseline cold start?**
   - First run has no baseline - how to score?
   - **Recommendation:** First 10 samples = "learning mode", use static scores only

5. **Hash salt rotation?**
   - Should salt change periodically?
   - **Recommendation:** No - consistency more valuable than rotation for pattern detection

---

## Resolved Design Decisions

| Question | Decision | Rationale |
|----------|----------|-----------|
| Include successful logins? | No | Noise, not signal |
| Show raw usernames? | No, hash them | Privacy + pattern detection |
| Cryptographic signing? | Deferred | Premature optimisation |
| Automated remediation? | No | Inform, don't act |
| Time-of-day baselines? | Deferred | Simple EMA first |

---

## References

- [auditd documentation](https://linux.die.net/man/8/auditd)
- [ausearch man page](https://linux.die.net/man/8/ausearch)
- [RHEL Security Guide - Audit](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [CIS Benchmarks - Logging](https://www.cisecurity.org/benchmark/distribution_independent_linux)
