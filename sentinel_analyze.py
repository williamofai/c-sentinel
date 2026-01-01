#!/usr/bin/env python3
"""
C-Sentinel - Semantic Observability for UNIX Systems
Copyright (c) 2025 William Murray

Licensed under the MIT License.
See LICENSE file for details.

https://github.com/williamofai/c-sentinel

Python wrapper for LLM-powered analysis.
Supports both cloud (Anthropic) and local (Ollama) LLMs.

Usage:
    ./sentinel_analyze.py                    # Analyze local system with AI
    ./sentinel_analyze.py --local            # Use local Ollama instead of cloud
    ./sentinel_analyze.py --quick            # Quick local analysis (no AI)
    ./sentinel_analyze.py --diff node_a.json node_b.json  # Compare systems
"""

import subprocess
import json
import sys
import argparse
import os
import re
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

# Try to import API clients
try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Configuration
SENTINEL_BIN = "./bin/sentinel"
SENTINEL_DIFF_BIN = "./bin/sentinel-diff"
OLLAMA_BASE_URL = "http://localhost:11434/v1"
DEFAULT_LOCAL_MODEL = "llama3.2:3b"

# The system prompt that turns the LLM into a Principal UNIX Engineer
SYSTEM_PROMPT = """You are a Principal UNIX Systems Engineer with 40 years of experience.
You have seen every type of system failure, performance issue, and configuration mistake.

Your role is to analyze system fingerprints from C-Sentinel and identify:

1. **Non-obvious risks** that traditional monitoring tools would miss
2. **Silent drift** - things that aren't broken yet but are heading that way
3. **Process anomalies** - zombies, descriptor leaks, stuck processes
4. **Configuration issues** - permission problems, missing files, suspicious changes

Be SPECIFIC. Reference actual process names, PIDs, values, and file paths from the data.
Don't give generic advice - give actionable insights based on THIS system's state.

If you identify a potential fix, suggest commands. Note that C-Sentinel's policy 
engine will validate them before presenting to the user - dangerous commands like
'rm -rf' or 'chmod 777' will be blocked automatically.

Format your response as:

## Summary
One paragraph overview of system health.

## Concerns (if any)
Specific issues found, ordered by severity.

## Recommendations
Concrete next steps, with specific commands where appropriate.

Keep responses concise - engineers don't want to read essays."""


class PolicyValidator:
    """
    Python-side policy validation.
    
    This mirrors the C policy engine for commands suggested by the LLM.
    It's defense-in-depth - the C engine is authoritative, but we also
    validate in Python to provide user feedback.
    """
    
    BLOCKED_PATTERNS = [
        (r'\brm\s+(-[rf]+\s+)*/', "Recursive deletion of root"),
        (r'\brm\s+-rf\s+\.', "Recursive deletion of current directory"),
        (r'\bmkfs\b', "Filesystem formatting"),
        (r'\bdd\s+if=', "Direct disk write"),
        (r'>\s*/dev/sd', "Direct device write"),
        (r'\bchmod\s+777\s+/', "World-writable root"),
        (r'\bchmod\s+-R\s+777', "Recursive world-writable"),
        (r':\(\)\{.*:\|:.*\};:', "Fork bomb"),
        (r'\|\s*sh\b', "Pipe to shell"),
        (r'\|\s*bash\b', "Pipe to bash"),
        (r'\bcurl\b.*\|\s*(sh|bash)', "Remote code execution"),
        (r'\bwget\b.*\|\s*(sh|bash)', "Remote code execution"),
        (r'>\s*/etc/passwd', "Overwrite passwd"),
        (r'>\s*/etc/shadow', "Overwrite shadow"),
        (r'--no-preserve-root', "Dangerous rm flag"),
    ]
    
    WARN_PATTERNS = [
        (r'\bsudo\b', "Elevated privileges"),
        (r'\bsu\s+-', "User switching"),
        (r'\bsystemctl\s+(restart|stop)', "Service control"),
        (r'\bkill\b', "Process termination"),
        (r'\bchmod\b', "Permission change"),
        (r'\bchown\b', "Ownership change"),
    ]
    
    @classmethod
    def validate_command(cls, command: str) -> Tuple[str, Optional[str]]:
        """
        Validate a command against policy rules.
        
        Returns: (status, reason)
            status: 'ALLOW', 'WARN', or 'BLOCK'
            reason: Explanation if not ALLOW
        """
        for pattern, reason in cls.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return ('BLOCK', f"RISK_CRITICAL: {reason}")
        
        for pattern, reason in cls.WARN_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return ('WARN', f"RISK_MEDIUM: {reason}")
        
        return ('ALLOW', None)
    
    @classmethod
    def extract_and_validate_commands(cls, text: str) -> List[Dict[str, Any]]:
        """
        Extract commands from LLM response and validate each one.
        
        Looks for:
        - Code blocks with shell commands
        - Lines starting with $ or #
        - Common command patterns
        """
        results = []
        
        # Find code blocks
        code_blocks = re.findall(r'```(?:bash|sh|shell)?\n(.*?)```', text, re.DOTALL)
        
        # Find inline commands (lines starting with $ or common commands)
        inline_commands = re.findall(
            r'(?:^|\n)\s*(?:\$|#)?\s*((?:sudo\s+)?(?:rm|chmod|chown|kill|systemctl|service|reboot|shutdown|dd|mkfs)\s+[^\n]+)',
            text
        )
        
        all_commands = []
        for block in code_blocks:
            # Split block into lines and filter
            for line in block.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    all_commands.append(line)
        
        all_commands.extend(inline_commands)
        
        for cmd in all_commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            
            status, reason = cls.validate_command(cmd)
            results.append({
                'command': cmd,
                'status': status,
                'reason': reason
            })
        
        return results


class SentinelAnalyzer:
    """Orchestrates C-Sentinel probing with LLM analysis."""
    
    def __init__(self, api_key: Optional[str] = None, use_local: bool = False,
                 local_model: str = DEFAULT_LOCAL_MODEL):
        self.sentinel_path = Path(SENTINEL_BIN)
        self.diff_path = Path(SENTINEL_DIFF_BIN)
        self.use_local = use_local
        self.local_model = local_model
        self.client = None
        
        if use_local:
            if not HAS_OPENAI:
                print("Warning: openai package not installed. Install with: pip install openai", 
                      file=sys.stderr)
            else:
                self.client = OpenAI(
                    base_url=OLLAMA_BASE_URL,
                    api_key="ollama"  # Required but ignored by Ollama
                )
        elif HAS_ANTHROPIC:
            if api_key:
                self.client = Anthropic(api_key=api_key)
            elif os.environ.get('ANTHROPIC_API_KEY'):
                self.client = Anthropic()  # Uses ANTHROPIC_API_KEY env var
    
    def _run_sentinel(self, config_files: Optional[List[str]] = None, 
                      quick: bool = False) -> Dict[str, Any]:
        """Run the C-Sentinel prober and return parsed JSON."""
        
        if not self.sentinel_path.exists():
            raise FileNotFoundError(
                f"Sentinel binary not found at {self.sentinel_path}. "
                "Run 'make' to build it."
            )
        
        cmd = [str(self.sentinel_path)]
        
        if quick:
            cmd.append("--quick")
            result = subprocess.run(cmd, capture_output=True, text=True)
            return {"quick_output": result.stdout, "is_quick": True}
        
        if config_files:
            cmd.extend(config_files)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"Sentinel failed: {result.stderr}")
        
        return json.loads(result.stdout)
    
    def _sanitize_for_api(self, fingerprint: Dict[str, Any]) -> str:
        """Sanitize fingerprint before sending to external API."""
        json_str = json.dumps(fingerprint, indent=2)
        
        # Defense in depth - Python-side sanitization
        json_str = re.sub(
            r'(api[_-]?key|token|secret|password)\s*[=:]\s*["\']?[\w-]+["\']?',
            r'\1=[REDACTED]',
            json_str,
            flags=re.IGNORECASE
        )
        
        return json_str
    
    def _call_llm(self, user_message: str) -> str:
        """Call either local or cloud LLM."""
        
        if self.use_local:
            response = self.client.chat.completions.create(
                model=self.local_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ]
            )
            return response.choices[0].message.content
        else:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}]
            )
            return response.content[0].text
    
    def _format_policy_report(self, validations: List[Dict[str, Any]]) -> str:
        """Format policy validation results as a report."""
        
        if not validations:
            return ""
        
        lines = [
            "",
            "---",
            "## 🛡️ C-Sentinel Policy Engine Report",
            ""
        ]
        
        blocked = [v for v in validations if v['status'] == 'BLOCK']
        warned = [v for v in validations if v['status'] == 'WARN']
        allowed = [v for v in validations if v['status'] == 'ALLOW']
        
        if blocked:
            lines.append("### ❌ BLOCKED Commands")
            lines.append("The following AI-suggested commands were blocked by the policy engine:")
            lines.append("")
            for v in blocked:
                lines.append(f"- `{v['command']}`")
                lines.append(f"  - **Reason**: {v['reason']}")
            lines.append("")
        
        if warned:
            lines.append("### ⚠️ Commands Requiring Review")
            lines.append("The following commands should be reviewed before execution:")
            lines.append("")
            for v in warned:
                lines.append(f"- `{v['command']}`")
                lines.append(f"  - **Note**: {v['reason']}")
            lines.append("")
        
        if allowed:
            lines.append("### ✅ Safe Commands")
            lines.append(f"{len(allowed)} command(s) passed policy validation.")
            lines.append("")
        
        if blocked:
            lines.append("*The C-Sentinel policy engine protects against dangerous operations.*")
            lines.append("*Blocked commands will not be executed even if suggested by AI.*")
        
        return "\n".join(lines)
    
    def analyze(self, config_files: Optional[List[str]] = None,
                model: str = "claude-sonnet-4-20250514") -> str:
        """Capture system fingerprint and analyze with LLM."""
        
        if not self.client:
            return self._analyze_without_api(config_files)
        
        # Capture fingerprint
        backend = "Ollama (local)" if self.use_local else "Claude (cloud)"
        print(f"Capturing system fingerprint...", file=sys.stderr)
        fingerprint = self._run_sentinel(config_files)
        
        # Sanitize before sending
        sanitized = self._sanitize_for_api(fingerprint)
        
        # Build the prompt
        user_message = f"""Analyze this system fingerprint from C-Sentinel:

```json
{sanitized}
```

Identify any non-obvious risks, anomalies, or concerns. If you suggest commands to fix issues, be specific."""
        
        print(f"Sending to {backend} for analysis...", file=sys.stderr)
        
        # Call LLM
        analysis = self._call_llm(user_message)
        
        # Validate any commands in the response
        validations = PolicyValidator.extract_and_validate_commands(analysis)
        policy_report = self._format_policy_report(validations)
        
        return analysis + policy_report
    
    def _analyze_without_api(self, config_files: Optional[List[str]] = None) -> str:
        """Fallback analysis when API is not available."""
        
        fingerprint = self._run_sentinel(config_files)
        concerns = []
        
        proc_summary = fingerprint.get("process_summary", {})
        
        if proc_summary.get("zombie_count", 0) > 0:
            concerns.append(f"⚠️  {proc_summary['zombie_count']} zombie process(es) detected")
        
        if proc_summary.get("high_fd_count", 0) > 0:
            concerns.append(f"⚠️  {proc_summary['high_fd_count']} process(es) with high FD count")
        
        if proc_summary.get("stuck_count", 0) > 0:
            concerns.append(f"⚠️  {proc_summary['stuck_count']} potentially stuck process(es)")
        
        for config in fingerprint.get("config_files", []):
            if config.get("warning"):
                concerns.append(f"⚠️  Config issue: {config['path']} - {config['warning']}")
        
        output = ["# C-Sentinel Local Analysis", ""]
        output.append("## System Info")
        system = fingerprint.get("system", {})
        output.append(f"- Hostname: {system.get('hostname', 'unknown')}")
        output.append(f"- Kernel: {system.get('kernel', 'unknown')}")
        output.append(f"- Uptime: {system.get('uptime_days', 0):.1f} days")
        output.append(f"- Memory: {system.get('memory_used_percent', 0):.1f}% used")
        output.append("")
        
        if concerns:
            output.append("## Concerns")
            for c in concerns:
                output.append(f"- {c}")
        else:
            output.append("## Status")
            output.append("No obvious concerns detected.")
        
        output.append("")
        output.append("*For AI-powered analysis:*")
        output.append("- Cloud: Set ANTHROPIC_API_KEY and install anthropic package")
        output.append("- Local: Install Ollama and run with --local flag")
        
        return "\n".join(output)
    
    def quick_check(self) -> str:
        """Run quick analysis (no API call)."""
        result = self._run_sentinel(quick=True)
        return result.get("quick_output", "")
    
    def compare(self, file_a: str, file_b: str) -> str:
        """Compare two fingerprint files using sentinel-diff."""
        
        if not self.diff_path.exists():
            raise FileNotFoundError(
                f"Diff binary not found at {self.diff_path}. "
                "Run 'make' to build it."
            )
        
        result = subprocess.run(
            [str(self.diff_path), file_a, file_b],
            capture_output=True,
            text=True
        )
        
        return result.stdout


def main():
    parser = argparse.ArgumentParser(
        description="C-Sentinel: Semantic Observability for UNIX Systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Analyze with Claude (cloud)
  %(prog)s --local                      # Analyze with Ollama (local)
  %(prog)s --quick                      # Quick local analysis (no AI)
  %(prog)s --config /etc/nginx.conf     # Include specific config
  %(prog)s --diff fp1.json fp2.json     # Compare two fingerprints
  %(prog)s --local --model mistral      # Use different local model

Environment:
  ANTHROPIC_API_KEY    API key for Claude (cloud mode)
  OLLAMA_HOST          Ollama server URL (default: localhost:11434)
        """
    )
    
    parser.add_argument(
        "--local", "-l",
        action="store_true",
        help="Use local Ollama instead of cloud API"
    )
    
    parser.add_argument(
        "--model", "-m",
        default=DEFAULT_LOCAL_MODEL,
        help=f"Model to use (default: {DEFAULT_LOCAL_MODEL} for local, claude-sonnet-4-20250514 for cloud)"
    )
    
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick analysis without API call"
    )
    
    parser.add_argument(
        "--config", "-c",
        action="append",
        dest="configs",
        metavar="FILE",
        help="Config file to include (can be repeated)"
    )
    
    parser.add_argument(
        "--diff", "-d",
        nargs=2,
        metavar=("FILE_A", "FILE_B"),
        help="Compare two fingerprint JSON files"
    )
    
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output raw JSON fingerprint (no analysis)"
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = SentinelAnalyzer(use_local=args.local, local_model=args.model)
        
        if args.diff:
            print(analyzer.compare(args.diff[0], args.diff[1]))
        
        elif args.quick:
            print(analyzer.quick_check())
        
        elif args.json:
            fingerprint = analyzer._run_sentinel(args.configs)
            print(json.dumps(fingerprint, indent=2))
        
        else:
            analysis = analyzer.analyze(args.configs)
            print(analysis)
    
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
