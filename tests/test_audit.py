from secureflow.audit import AuditLogger
from secureflow.messages import Decision, Finding, Message, Severity


def test_audit_does_not_write_raw_secret(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    finding = Finding(guard_name="x", category="secret", severity=Severity.HIGH, description="x", evidence="AKIAFAKEFAKEFAKEFAKE")
    AuditLogger(audit_path).record(Message(sender="a", recipient="b", content="ignored"), [finding], Decision.FLAG, "flagged")
    assert "AKIAFAKEFAKEFAKEFAKE" not in audit_path.read_text()
