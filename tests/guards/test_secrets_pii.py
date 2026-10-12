from secureflow.guards.secrets_pii import SecretsPIIGuard
from secureflow.messages import Message


def test_detects_and_redacts_secret() -> None:
    findings = SecretsPIIGuard().check(Message(sender="a", recipient="b", content="AKIAFAKEFAKEFAKEFAKE contact a@example.com"))
    assert {f.category for f in findings} >= {"aws_key", "email"}
    assert all("AKIAFAKEFAKEFAKEFAKE" not in f.evidence for f in findings)


def test_benign_text_is_not_secret() -> None:
    assert not SecretsPIIGuard().check(Message(sender="a", recipient="b", content="The key point is documentation."))
