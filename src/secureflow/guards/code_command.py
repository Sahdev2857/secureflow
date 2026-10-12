"""Detect commands, code execution, traversal, and link-based data exfiltration."""

from __future__ import annotations

import re

from secureflow.messages import Finding, Message, Severity


class CodeCommandGuard:
    name = "code_command"
    _rules = {
        "dangerous_shell": r"\b(?:rm\s+-rf|curl\s+[^\n|]+\|\s*(?:sh|bash)|wget\s+[^\n|]+\|\s*(?:sh|bash)|nc\s+|chmod\s+777)\b",
        "code_execution": r"\b(?:eval|exec|os\.system|subprocess\.(?:run|call|Popen)|pickle\.loads|__import__)\s*\(",
        "sql_injection": r"(?:\bunion\s+select\b|\bor\s+1\s*=\s*1\b|;\s*drop\s+table\b)",
        "path_traversal": r"(?:^|[\\/])\.\.(?:[\\/]|$)",
        "markdown_exfiltration": r"!?\[[^\]]*\]\(https?://[^)]+\?(?:[^)]*(?:secret|token|key|data)=)[^)]*\)",
        "raw_ip_url": r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)",
    }

    def check(self, message: Message) -> list[Finding]:
        try:
            findings = []
            for category, rule in self._rules.items():
                for match in re.finditer(rule, message.content, flags=re.IGNORECASE):
                    findings.append(Finding(guard_name=self.name, category=category, severity=Severity.HIGH,
                                            description=f"Potential {category.replace('_', ' ')}", evidence=match.group()[:32] + "…", span=match.span()))
            return findings
        except Exception:
            return [Finding(guard_name=self.name, category="guard_failure", severity=Severity.MEDIUM, description="Code/command guard failed closed", evidence="[internal error]")]
