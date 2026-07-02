"""Tests for the cc sandbox clamp (ride CC's own sandbox + launch clamp).

Pure logic over settings objects; runs on any interpreter.
"""
from __future__ import annotations

import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from pub_os_cc_sandbox import (  # noqa: E402
    CcSandboxState,
    assess_cc_sandbox,
    merge_settings,
    recommended_managed_settings,
)


def test_recommended_template_is_self_supervising():
    # The template pub hands the operator must itself pass the clamp.
    verdict = assess_cc_sandbox(recommended_managed_settings())
    assert verdict.state == CcSandboxState.SUPERVISED
    assert verdict.reason_code == "CC_SANDBOX_CONTAINED"
    assert verdict.bash_isolated is True
    # Honesty: must NOT claim in-process write isolation.
    assert verdict.inprocess_write_isolated is False


def test_holds_when_sandbox_not_enabled():
    v = assess_cc_sandbox({"sandbox": {"failIfUnavailable": True, "allowUnsandboxedCommands": False}})
    assert v.state == CcSandboxState.HOLD
    assert v.reason_code == "CC_SANDBOX_NOT_ENABLED"


def test_holds_when_not_fail_closed():
    v = assess_cc_sandbox({"sandbox": {"enabled": True, "allowUnsandboxedCommands": False}})
    assert v.reason_code == "CC_SANDBOX_NOT_FAIL_CLOSED"


def test_holds_when_escape_hatch_open():
    # allowUnsandboxedCommands defaults OPEN when the key is absent.
    v = assess_cc_sandbox({"sandbox": {"enabled": True, "failIfUnavailable": True}})
    assert v.reason_code == "CC_SANDBOX_ESCAPE_HATCH_OPEN"
    v2 = assess_cc_sandbox({"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": True}})
    assert v2.reason_code == "CC_SANDBOX_ESCAPE_HATCH_OPEN"


def test_holds_when_credentials_readable():
    v = assess_cc_sandbox({
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "allowManagedReadPathsOnly": True,
            "allowManagedDomainsOnly": True,
            "filesystem": {"denyRead": ["~/.ssh"]},  # missing ~/.aws etc.
        }
    })
    assert v.reason_code == "CC_SANDBOX_CREDENTIALS_READABLE"
    assert any("~/.aws" in e for e in v.evidence)


def test_holds_when_policy_not_managed_locked():
    v = assess_cc_sandbox({
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {"denyRead": list(__import__("pub_os_cc_sandbox").DEFAULT_REQUIRED_DENY_READ)},
        }
    })
    assert v.reason_code == "CC_SANDBOX_POLICY_NOT_LOCKED"


def test_managed_lockdown_can_be_relaxed_for_non_org_use():
    base = recommended_managed_settings()
    base["sandbox"]["allowManagedReadPathsOnly"] = False
    base["sandbox"]["allowManagedDomainsOnly"] = False
    # With org lockdowns off, default (strict) clamp HOLDs...
    assert assess_cc_sandbox(base).reason_code == "CC_SANDBOX_POLICY_NOT_LOCKED"
    # ...but a single-developer deployment can opt out of that one requirement.
    assert assess_cc_sandbox(base, require_managed_lockdowns=False).state == CcSandboxState.SUPERVISED


def test_merge_managed_wins_scalars_and_unions_arrays():
    user = {"sandbox": {"enabled": False, "filesystem": {"denyRead": ["~/.ssh"]}}}
    managed = {"sandbox": {"enabled": True, "filesystem": {"denyRead": ["~/.aws"]}}}
    merged = merge_settings(user, managed)  # managed last = wins
    assert merged["sandbox"]["enabled"] is True
    assert set(merged["sandbox"]["filesystem"]["denyRead"]) == {"~/.ssh", "~/.aws"}


def test_merged_user_plus_managed_template_supervises():
    user = {"sandbox": {"enabled": False, "allowUnsandboxedCommands": True}}  # a careless user
    merged = merge_settings(user, recommended_managed_settings())  # managed clamps it shut
    assert assess_cc_sandbox(merged).state == CcSandboxState.SUPERVISED


def _run_all():
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
