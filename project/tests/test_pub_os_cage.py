"""PUB-OS cc cage prototype tests.

These assert the cage CONTRACT via the rendered bwrap argv (pure string work),
plus fail-closed behaviour. They do not require bwrap to be installed, so they
run the same under a Windows or a Linux interpreter.
"""
from __future__ import annotations

import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

import pub_os_cage  # noqa: E402
from pub_os_cage import (  # noqa: E402
    CageSpec,
    CageUnavailable,
    build_cage_argv,
    cage_available,
    make_cage_spawn,
    render_cage_command,
)


PROJ = "/workspace/pub/repo"
CLAUDE = ("claude", "--permission-mode", "default")


def _bind_pairs(argv, flag):
    """Yield (src, dst) for each occurrence of a bind flag in a bwrap argv."""
    pairs = []
    i = 0
    while i < len(argv):
        if argv[i] == flag and i + 2 < len(argv):
            pairs.append((argv[i + 1], argv[i + 2]))
            i += 3
        else:
            i += 1
    return pairs


def test_project_root_is_the_only_writable_realestate():
    spec = CageSpec(project_root=PROJ)
    argv = build_cage_argv(CLAUDE, spec)

    rw = _bind_pairs(argv, "--bind")
    assert rw == [(PROJ, PROJ)], f"expected exactly one rw bind of the project, got {rw}"


def test_control_plane_is_rebound_readonly_after_the_project():
    spec = CageSpec(project_root=PROJ)
    argv = build_cage_argv(CLAUDE, spec)

    project_bind_index = argv.index("--bind")
    ro = _bind_pairs(argv, "--ro-bind-try")
    settings = f"{PROJ}/.claude/settings.json"
    gate = f"{PROJ}/.claude/pub_gate_switch.json"

    assert (settings, settings) in ro
    assert (gate, gate) in ro
    # The read-only override must come AFTER the writable project bind to win.
    assert argv.index(settings) > project_bind_index
    assert argv.index(gate) > project_bind_index


def test_audit_dir_is_bound_readonly_not_writable():
    audit = f"{PROJ}/audit_logs"
    spec = CageSpec(project_root=PROJ, audit_dir=audit)
    argv = build_cage_argv(CLAUDE, spec)

    assert (audit, audit) in _bind_pairs(argv, "--ro-bind-try")
    assert (audit, audit) not in _bind_pairs(argv, "--bind")


def test_pub_source_inside_project_is_rejected():
    try:
        CageSpec(project_root=PROJ, pub_source_dir=f"{PROJ}/pub")
    except ValueError as exc:
        assert "writable bind" in str(exc)
    else:
        raise AssertionError("pub source inside the writable project must be rejected")


def test_pub_source_outside_project_is_allowed():
    spec = CageSpec(project_root=PROJ, pub_source_dir="/opt/pub")
    assert spec.pub_source_dir == "/opt/pub"


def test_inner_command_lands_after_the_separator():
    spec = CageSpec(project_root=PROJ)
    argv = build_cage_argv(CLAUDE, spec)
    sep = argv.index("--")
    assert tuple(argv[sep + 1:]) == CLAUDE
    assert argv[:1] == ["bwrap"]


def test_render_is_shell_pasteable():
    spec = CageSpec(project_root=PROJ)
    line = render_cage_command(CLAUDE, spec)
    assert line.startswith("bwrap ")
    assert "--bind" in line
    assert "claude" in line


def test_empty_inner_argv_is_rejected():
    try:
        build_cage_argv((), CageSpec(project_root=PROJ))
    except ValueError as exc:
        assert "inner_argv" in str(exc)
    else:
        raise AssertionError("an empty agent command must be rejected")


def test_spawn_fails_closed_when_cage_unavailable(monkeypatch=None):
    # Force "no cage" regardless of host, then assert spawn refuses to launch.
    original = pub_os_cage.cage_available
    pub_os_cage.cage_available = lambda: (False, "cage_unavailable:forced")
    try:
        spawn = make_cage_spawn(CageSpec(project_root=PROJ))
        try:
            spawn(CLAUDE, cwd=PROJ, env={})
        except CageUnavailable as exc:
            assert "cage_unavailable" in str(exc)
        else:
            raise AssertionError("spawn must fail closed when no cage is available")
    finally:
        pub_os_cage.cage_available = original


def test_cage_available_reports_reason_on_this_host():
    usable, reason = cage_available()
    # We only assert the contract shape: a bool and a non-empty reason string.
    assert isinstance(usable, bool)
    assert reason
    if not usable:
        assert reason.startswith("cage_unavailable:")


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
