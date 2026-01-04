# Contributing to C-Sentinel

First off, thank you for considering contributing to C-Sentinel! It's people like you that make open source work.

## Ways to Contribute

### 🐛 Reporting Bugs

Found a bug? Please open an issue with:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected vs actual behaviour
- Your environment (OS, kernel version, compiler, locale)
- Any relevant output or error messages

### 💡 Suggesting Features

Have an idea? Open an issue and tell us:

- What problem it solves
- How you envision it working
- Whether you'd be interested in implementing it

### 🔧 Submitting Code

1. **Fork the repository** and create your branch from `main`
2. **Write clear, readable code** that follows the existing style
3. **Test your changes** - make sure `make` succeeds with no warnings
4. **Update documentation** if you're changing behaviour
5. **Submit a pull request** with a clear description of changes

## Code Style

C-Sentinel follows strict C99 with these conventions:

```c
/* Comments use C-style block comments */
/* NOT // C++ style */

/* Functions are snake_case */
int capture_fingerprint(fingerprint_t *fp);

/* Types end with _t */
typedef struct { ... } fingerprint_t;

/* Constants are UPPER_SNAKE_CASE */
#define MAX_PROCESSES 1024

/* Braces on same line for control structures */
if (condition) {
    do_something();
}
```

### File Headers

All source files should include the standard header block:

```c
/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * filename.c - Brief description of this file's purpose
 */
```

### Compiler Flags

All code must compile cleanly with:
```bash
gcc -Wall -Wextra -Werror -pedantic -std=c99
```

No warnings allowed. This is non-negotiable.

### Memory Safety

- Always use `snprintf()`, never `sprintf()`
- Check all return values
- Define `MAX_*` limits for all arrays
- No dynamic allocation where static will do

### Locale Awareness

When working with dates/times for external tools (like `ausearch`), use locale-aware formatting:
```c
/* Good - respects system locale */
strftime(datebuf, sizeof(datebuf), "%x", tm);

/* Bad - assumes US date format */
snprintf(buf, size, "%02d/%02d/%04d", month, day, year);
```

## Project Structure

```
c-sentinel/
├── include/
│   ├── sentinel.h        # Core data structures
│   ├── audit.h           # Audit integration types
│   ├── policy.h          # Policy engine
│   └── sanitize.h        # PII sanitization
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
│   ├── app.py            # Main Flask application
│   ├── migrate.sql       # Database schema (run once)
│   ├── templates/        # HTML templates
│   │   ├── base.html     # Base template with toast system
│   │   ├── index.html    # Main dashboard
│   │   ├── host.html     # Host detail view
│   │   ├── login.html    # Login page (with TOTP support)
│   │   ├── profile.html  # User profile
│   │   ├── 2fa.html      # 2FA setup page
│   │   ├── api_keys.html # API key management
│   │   └── admin/        # Admin-only pages
│   │       ├── users.html
│   │       ├── sessions.html
│   │       └── audit.html
└── docs/
    ├── AUDIT_SPEC.md     # Audit integration design
    └── DESIGN_DECISIONS.md
```

## Good First Issues

Looking for something to start with? These are beginner-friendly:

| Issue | Description | Skills |
|-------|-------------|--------|
| **CMake build** | Add CMake as alternative to Make | CMake |
| **macOS support** | Port /proc parsing to sysctl | C, macOS |
| **Colour output** | Add `--color` flag for terminal | C |
| **Dashboard dark/light toggle** | Theme switcher | HTML/JS |
| **Config file support** | Load settings from `/etc/sentinel.conf` | C |
| **Man page** | Write `sentinel(1)` manual page | Documentation |

Look for issues labelled [`good first issue`](https://github.com/williamofai/c-sentinel/labels/good%20first%20issue) on GitHub.

## Areas Where Help is Wanted

We'd particularly welcome contributions in:

| Area | Description |
|------|-------------|
| **Platform support** | BSD, macOS, Solaris ports |
| **Application probes** | nginx, postgres, redis, docker |
| **Sanitization patterns** | New PII/secret detection patterns |
| **Documentation** | Examples, tutorials, translations |
| **Testing** | Edge cases, failure modes, fuzzing |
| **Dashboard** | UI improvements, new visualisations |
| **Alerting** | Slack/Teams webhooks, PagerDuty integration |
| **Security** | Penetration testing, security review |

## Development Setup

### C Prober

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/c-sentinel.git
cd c-sentinel

# Build
make

# Run tests
make test

# Run with debug symbols
make DEBUG=1
./bin/sentinel --quick

# Test with audit (requires root)
sudo ./bin/sentinel --quick --network --audit
```

### Dashboard

```bash
cd dashboard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask psycopg2-binary gunicorn pyotp qrcode pillow

# Run database migration
sudo -u postgres psql -d sentinel -f migrate.sql

# Run development server
FLASK_DEBUG=1 python app.py
```

### Dashboard Authentication Modes

The dashboard supports two authentication modes:

1. **Single-password mode**: Set `SENTINEL_ADMIN_PASSWORD_HASH` environment variable
2. **Multi-user mode**: Create users in the database (activates automatically)

```bash
# Create first admin user (multi-user mode)
cd dashboard
source venv/bin/activate
python -c "
import hashlib
password = input('Password: ')
print(hashlib.sha256(password.encode()).hexdigest())
"
# Then INSERT into users table
```

## Commit Messages

Write clear, concise commit messages:

```
feat: Add PostgreSQL probe support

- Parse pg_stat_activity for connection info
- Detect long-running queries (>30s)
- Add to network probe output
```

Format: `type: Short description`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## Pull Request Process

1. Update the README.md if you've added features
2. Update DESIGN_DECISIONS.md if you've made architectural choices
3. Add standard header block to any new source files
4. Ensure all tests pass and code compiles cleanly
5. Your PR will be reviewed by a maintainer

## Testing Checklist

Before submitting:

- [ ] `make clean && make` completes with no warnings
- [ ] `make test` passes
- [ ] JSON output is valid (`sentinel --json | python3 -m json.tool`)
- [ ] Audit features tested with root (`sudo ./bin/sentinel --audit`)
- [ ] Dashboard changes tested in browser
- [ ] Multi-user features tested (login, roles, 2FA)
- [ ] Documentation updated if behaviour changed

## Questions?

Not sure about something? Open an issue and ask! There are no stupid questions.

---

Thank you for helping make C-Sentinel better! 🛡️
