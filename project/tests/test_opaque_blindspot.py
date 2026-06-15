"""Tests for the opaque-executor blindspot (closes the python -c seam).

Run (Windows python, per project convention):
    python.exe -m pytest tests/test_opaque_blindspot.py -q
or standalone:
    python.exe tests/test_opaque_blindspot.py
"""

from __future__ import annotations

import json
import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from opaque_executor import is_opaque_executor, opaque_marker  # noqa: E402


# --------------------------------------------------------------------------- #
# 1. recognizer: decidable surface table
# --------------------------------------------------------------------------- #

OPAQUE = [
    "python -c \"open('x','w').write('a')\"",
    "python3 -c 'import os; os.remove(\"y\")'",
    "/usr/bin/python3 -c 'pass'",
    "env python -c 'pass'",
    "timeout 5 python -c 'pass'",
    "python -cprint(1)",            # glued flag
    "sh -c 'rm -rf z'",
    "bash -lc 'echo hi > f'",       # clustered short flag
    "eval \"$PAYLOAD\"",
    "perl -e 'unlink \"q\"'",
    "ruby -e 'puts 1'",
    "node -e 'require(\"fs\")'",
    "node --eval 'x'",
    "php -r 'unlink(\"a\");'",
    "Rscript -e 'q()'",
    "deno eval 'Deno.exit()'",
    "powershell -Command \"rm x\"",
    "pwsh -EncodedCommand ZQ==",
]

NOT_OPAQUE = [
    "ls -la",
    "grep -c foo file.txt",         # -c is grep's flag, grep is not an interpreter
    "cat report.py",
    "python script.py",            # runs a file (a referent), no inline code
    "cp a b",
    "rm -rf build",                 # destructive but MODELLABLE -- not our axis
    "git commit -m 'python -c'",   # the string appears as data, not an invocation
    "echo python -c hello",        # echo is not an interpreter
    "",
    "   ",
]


def test_recognizer_positive():
    for cmd in OPAQUE:
        matched, evidence = is_opaque_executor(cmd)
        assert matched, f"should be opaque: {cmd!r}"
        assert evidence, f"opaque match must carry evidence: {cmd!r}"
        assert opaque_marker(cmd), f"marker expected: {cmd!r}"


def test_recognizer_negative():
    for cmd in NOT_OPAQUE:
        matched, _ = is_opaque_executor(cmd)
        assert not matched, f"should NOT be opaque: {cmd!r}"
        assert opaque_marker(cmd) is None


# --------------------------------------------------------------------------- #
# 2. end-to-end: the seam command is now HELD at admission (was PASS)
# --------------------------------------------------------------------------- #

def _admit(tool_name, tool_input):
    from claude_code_hooks import run_pretool_admission

    event = {
        "session_id": "probe_sess",
        "transcript_path": "probe_tx",
        "cwd": _PROJECT,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": f"probe_{tool_name}_{abs(hash(json.dumps(tool_input, sort_keys=True))) % 10000}",
    }
    return run_pretool_admission(json.dumps(event))


def test_opaque_python_c_is_held():
    pre = _admit("Bash", {"command": "python -c \"open('probe_seam.txt','w').write('x')\""})
    # was EvidenceDisposition.PASS / target_paths=() / review XRAY_CLEAR.
    assert pre.proposal.target_paths == (), "control: lexer still extracts no path"
    assert pre.blocked, "opaque executor must now be blocked at admission"
    decision = pre.output.get("hookSpecificOutput", {}).get("permissionDecision")
    assert decision in {"ask", "deny"}, f"expected hold/deny, got {decision!r} ({pre.reason_code})"


def test_eval_is_held():
    pre = _admit("Bash", {"command": "eval \"$PAYLOAD\""})
    assert pre.blocked, "eval builtin must be held"


# --------------------------------------------------------------------------- #
# 3. no false positives: modellable commands and non-exec tools still pass
# --------------------------------------------------------------------------- #

def test_plain_command_still_passes():
    pre = _admit("Bash", {"command": "ls -la"})
    assert not pre.blocked, f"plain ls must pass, got {pre.reason_code}"


def test_writing_a_script_containing_python_c_is_not_opaque():
    # Writing a file whose CONTENT contains `python -c` is data, not execution.
    pre = _admit(
        "Write",
        {"file_path": "helper_note.txt", "content": "to run: python -c \"print(1)\""},
    )
    assert not pre.blocked, (
        "Write of script content must not trip the executor blindspot "
        f"(got {pre.reason_code})"
    )


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
