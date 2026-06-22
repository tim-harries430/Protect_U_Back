"""④a X-ray de-noise test -- 2026-06-21.

Before: every write/edit/delete made mutation_state=MUTATED + witness>0, which
seal_disguise read as OBJECT SUBSTITUTION -> QUARANTINE (the false-positive flood).
After: a mutation that MATCHES the proposal's declared effect is the job (PASS);
only a mutation that CONTRADICTS the declared effect (declared-READ that mutated)
stays a substitution (QUARANTINE).

Full cycle: PreToolUse (seals enter) -> actually perform the mutation -> PostToolUse
(seals exit, runs the review).

    python pub_xray_denoise_test_2026-06-21.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

for _p in (r"C:\dev\sp", "/mnt/c/dev/sp"):
    if _p not in sys.path and Path(_p).exists():
        sys.path.insert(0, _p)

import claude_code_hooks as h  # noqa: E402

_SEQ = [0]


def _event(proj, tool, tool_input):
    _SEQ[0] += 1
    return {
        "session_id": "xray-denoise",
        "transcript_path": str(proj / "t.jsonl"),
        "cwd": str(proj),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": f"xd{_SEQ[0]}",
    }


def main() -> int:
    base = Path(tempfile.mkdtemp(dir=str(Path.home())))
    proj = base / "repo"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    env = {
        "CLAUDE_PROJECT_DIR": str(proj),
        "PUB_CLAUDE_HOOK_STATE_DIR": str(base / "state"),
        "PUB_CLAUDE_HOOK_LOG_DIR": str(base / "logs"),
        "PUB_CLAUDE_SCENE_STATE_DIR": str(base / "scene"),
        "PUB_CLAUDE_TEMPORAL_STATE_DIR": str(base / "temporal"),
        "PUB_CLAUDE_ACTOR_ID": "claude_code",
    }
    results: list[tuple[bool, str]] = []

    def check(cond, label):
        results.append((bool(cond), label))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    def cycle(tool, tool_input, mutate):
        ev = _event(proj, tool, tool_input)
        h.run_pretool_admission(json.dumps(ev), environ=env)  # seals enter
        mutate()                                              # the tool "runs"
        post = dict(ev)
        post["hook_event_name"] = "PostToolUse"
        post["tool_response"] = {"ok": True}
        autopsy = h.run_posttool_autopsy(json.dumps(post), environ=env)
        s = autopsy.seal
        if s is not None:
            print(f"      seal: mut={s.mutation_state} cont={s.continuity_state} "
                  f"wit={s.witness_count} field={s.field_state} expected={s.expected_mutation} "
                  f"reason={autopsy.review.reason_code if autopsy.review else '-'}")
        return autopsy.review.disposition.value if autopsy.review else "NO_REVIEW"

    # A: Write a NEW file (declared WRITE, file created) -> benign -> PASS
    newf = proj / "src" / "a.py"
    d = cycle("Write", {"file_path": str(newf), "content": "x=1\n"},
              lambda: newf.write_text("x=1\n", encoding="utf-8"))
    check(d == "PASS", f"Write new file -> review={d} (expect PASS, was QUARANTINE)")

    # B: Edit an EXISTING file (declared WRITE, content mutates) -> benign -> PASS
    cfg = proj / "src" / "cfg.py"
    cfg.write_text("V=1\n", encoding="utf-8")
    d = cycle("Edit", {"file_path": str(cfg), "old_string": "1", "new_string": "2"},
              lambda: cfg.write_text("V=2\n", encoding="utf-8"))
    check(d == "PASS", f"Edit existing file -> review={d} (expect PASS)")

    # C: rm a file (declared DELETE) -> benign -> PASS
    victim = proj / "src" / "tmp.py"
    victim.write_text("junk\n", encoding="utf-8")
    d = cycle("Bash", {"command": "rm src/tmp.py"}, lambda: victim.unlink())
    check(d == "PASS", f"rm file -> review={d} (expect PASS)")

    # D: a declared-READ op whose target MUTATES under the window -> substitution -> QUARANTINE
    watched = proj / "src" / "watched.py"
    watched.write_text("ORIGINAL\n", encoding="utf-8")
    d = cycle("Read", {"file_path": str(watched)},
              lambda: watched.write_text("SWAPPED\n", encoding="utf-8"))
    check(d == "QUARANTINE", f"declared-READ that mutated -> review={d} (expect QUARANTINE preserved)")

    # E: a pure read with NO mutation -> clean -> PASS
    stable = proj / "src" / "stable.py"
    stable.write_text("same\n", encoding="utf-8")
    d = cycle("Read", {"file_path": str(stable)}, lambda: None)
    check(d == "PASS", f"clean read (no mutation) -> review={d} (expect PASS)")

    passed = sum(1 for ok, _ in results if ok)
    print(f"\n=== xray de-noise: {passed}/{len(results)} checks passed ===")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
