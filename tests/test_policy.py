from secureflow.messages import Finding, Severity
from secureflow.policy import Policy


def finding(severity: Severity) -> Finding:
    return Finding(guard_name="x", category="x", severity=severity, description="x")


def test_policy_matrix() -> None:
    assert Policy().decide([finding(Severity.LOW)]).value == "allow"
    assert Policy().decide([finding(Severity.MEDIUM)]).value == "flag"
    assert Policy().decide([finding(Severity.CRITICAL)]).value == "flag"
    assert Policy(block_on_critical=True).decide([finding(Severity.CRITICAL)]).value == "block"
