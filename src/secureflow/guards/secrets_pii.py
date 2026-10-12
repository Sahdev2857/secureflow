"""Detect accidental secrets and personally identifiable data with redacted evidence."""

from __future__ import annotations

import re

from secureflow.messages import Finding, Message, Severity


class SecretsPIIGuard:
    name = "secrets_pii"
    _rules = {
        "aws_key": r"\bAKIA[A-Z0-9]{16}\b",
        "github_token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        "api_key": r"\b(?:sk|rk|xai)-[A-Za-z0-9_-]{16,}\b",
        "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "password_url": r"://[^\s/@:]+:[^\s/@]+@",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phone": r"\b(?:\+?\d{1,3}[-. ]?)?(?:\d{3}[-. ]?){2}\d{4}\b",
    }

    def check(self, message: Message) -> list[Finding]:
        try:
            findings: list[Finding] = []
            for category, rule in self._rules.items():
                for match in re.finditer(rule, message.content):
                    raw = match.group()
                    findings.append(Finding(guard_name=self.name, category=category, severity=Severity.HIGH if category not in {"email", "phone"} else Severity.MEDIUM,
                                            description=f"Possible {category.replace('_', ' ')}", evidence=raw[:4] + "…", span=match.span()))
            for match in re.finditer(r"\b(?:\d[ -]?){13,19}\b", message.content):
                digits = re.sub(r"\D", "", match.group())
                if self._luhn(digits):
                    findings.append(Finding(guard_name=self.name, category="credit_card", severity=Severity.HIGH, description="Possible payment card", evidence=digits[:4] + "…", span=match.span()))
            return findings
        except Exception:
            return [Finding(guard_name=self.name, category="guard_failure", severity=Severity.MEDIUM, description="Secrets/PII guard failed closed", evidence="[internal error]")]

    @staticmethod
    def _luhn(number: str) -> bool:
        digits = [int(value) for value in number]
        return sum(value if index % 2 else (value * 2 - 9 if value > 4 else value * 2) for index, value in enumerate(reversed(digits))) % 10 == 0
