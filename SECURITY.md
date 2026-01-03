# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | ✅ Yes             |
| 0.4.x   | ✅ Yes             |
| 0.3.x   | ⚠️ Security fixes only |
| < 0.3   | ❌ No              |

## Reporting a Vulnerability

If you discover a security vulnerability in C-Sentinel, please report it responsibly.

### How to Report

**Email**: william@fstopify.com

**Please include**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Resolution timeline**: Depends on severity, typically within 30 days

### What We Ask

- **Don't** disclose publicly until we've had a chance to fix it
- **Don't** exploit the vulnerability beyond what's needed to demonstrate it
- **Do** provide enough detail for us to reproduce and fix the issue

### Scope

Security issues we're interested in:

**C Prober:**
- Buffer overflows or memory corruption
- Command injection vulnerabilities
- Path traversal issues
- Information disclosure in sanitization
- Policy engine bypasses

**Dashboard:**
- Authentication bypasses
- Session hijacking
- SQL injection
- Cross-site scripting (XSS)
- API key exposure
- Unauthorised data access

### Out of Scope

- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service (C-Sentinel is a diagnostic tool, not a service)
- Self-XSS or issues requiring user to attack themselves
- Missing security headers that don't lead to exploitable vulnerabilities

## Security Design

C-Sentinel is designed with security in mind:

### C Prober
- **Read-only by design**: Never modifies system state
- **No network listeners**: Doesn't open any ports
- **Sanitization layer**: Strips sensitive data before external transmission
- **Policy engine**: Validates AI suggestions before display
- **Minimal privileges**: Runs without root for basic operation (root only needed for audit logs)
- **No dynamic allocation**: Static buffers with defined limits prevent heap exploits

### Dashboard
- **Password authentication**: SHA256 hashed passwords, never stored in plaintext
- **Session security**: Flask secure sessions with configurable secret key
- **API key authentication**: Separate API keys for agent ingestion
- **No default credentials**: Installation requires explicit password configuration
- **SQL parameterisation**: All queries use parameterised statements
- **Environment-based secrets**: Credentials stored in environment variables, not code

### Audit Integration
- **Privacy-preserving**: Usernames are hashed, not stored in plaintext
- **No command arguments**: Sensitive data in command arguments never captured
- **Process names only**: Full paths sanitised for privacy

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (unless you prefer to remain anonymous).

---

Thank you for helping keep C-Sentinel secure! 🛡️
