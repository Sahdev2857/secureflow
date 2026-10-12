"""Stateful detection for harmful instructions assembled across otherwise harmless messages."""

from __future__ import annotations

import base64
import re

from secureflow.guards.code_command import CodeCommandGuard
from secureflow.guards.injection import InjectionGuard
from secureflow.guards.secrets_pii import SecretsPIIGuard
from secureflow.messages import Finding, GateContext, Message, Severity


class AssemblyGuard:
    name = "assembly"
    _cue = re.compile(r"\b(?:part\s*\d+\s*(?:/|of)\s*\d+|concatenate|combine\s+(?:the\s+)?following|\w+\s*=\s*[\"'])", re.I)
    _base64 = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
    _hex = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

    def __init__(self, injection: InjectionGuard | None = None, secrets: SecretsPIIGuard | None = None,
                 code: CodeCommandGuard | None = None, max_chars: int = 20_000, decode_depth: int = 2) -> None:
        self.guards = [injection or InjectionGuard(), secrets or SecretsPIIGuard(), code or CodeCommandGuard()]
        self.max_chars, self.decode_depth = max_chars, decode_depth

    def _views(self, text: str) -> list[str]:
        text = text[-self.max_chars:]
        # IDs in assembled_text are display delimiters, not content: remove them before analysis.
        plain = re.sub(r"\[[0-9a-f-]{8,}\]\n", "", text, flags=re.I)
        compact = re.sub(r"[\s\W_\u200b-\u200f\u2060\ufeff]+", "", plain)
        views = [plain, compact]
        candidate = compact
        for _ in range(self.decode_depth):
            decoded_parts: list[str] = []
            for match in self._base64.finditer(candidate):
                try:
                    decoded_parts.append(base64.b64decode(match.group(), validate=True).decode("utf-8", "ignore"))
                except (ValueError, UnicodeDecodeError):
                    continue
            for match in self._hex.finditer(candidate):
                try:
                    decoded_parts.append(bytes.fromhex(match.group()).decode("utf-8", "ignore"))
                except ValueError:
                    continue
            if not decoded_parts:
                break
            candidate = " ".join(decoded_parts)[:self.max_chars]
            views.append(candidate)
        # Restore separators for high-value split phrases, without attempting unrestricted reconstruction.
        views.append(re.sub(r"ignorepreviousinstructions", "ignore previous instructions ", compact, flags=re.I))
        return list(dict.fromkeys(views))

    def check(self, message: Message, ctx: GateContext) -> list[Finding]:
        try:
            if len(ctx.recent) < 2:
                return []
            ids = [item.id for item in ctx.recent]
            individual: set[tuple[str, str]] = set()
            for item in ctx.recent:
                for guard in self.guards:
                    individual.update((guard.name, finding.category) for finding in guard.check(item))
            assembled: list[Finding] = []
            for view in self._views(ctx.assembled_text):
                probe = message.model_copy(update={"content": view})
                for guard in self.guards:
                    for finding in guard.check(probe):
                        if (guard.name, finding.category) not in individual:
                            assembled.append(finding)
            results: list[Finding] = []
            seen: set[tuple[str, str]] = set()
            for finding in assembled:
                key = (finding.guard_name, finding.category)
                if key in seen:
                    continue
                seen.add(key)
                results.append(Finding(guard_name=self.name, category="assembly.emergent",
                                       severity=Severity.MEDIUM if finding.severity is Severity.LOW else finding.severity,
                                       description=f"Emergent assembled signal: {finding.category}",
                                       evidence=f"messages {', '.join(ids)}: {finding.evidence[:24]}",
                                       contributing_message_ids=ids))
            if self._cue.search(ctx.assembled_text):
                results.append(Finding(guard_name=self.name, category="assembly.cue", severity=Severity.LOW,
                                       description="Text contains an assembly cue", evidence="[assembly cue]", contributing_message_ids=ids))
            return results
        except Exception:
            return [Finding(guard_name=self.name, category="guard_failure", severity=Severity.MEDIUM,
                            description="Assembly guard failed closed", evidence="[internal error]")]
