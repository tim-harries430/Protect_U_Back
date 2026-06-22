"""④b session-level auto-restore arm -- 2026-06-22.

When the sequence judges a session compromised (temporal KILL / scene out-of-band
tamper), restore_session_backfill retakes the ground: it rolls back EVERY in-project
mutation that session journalled. Here we journal two allowed mutations in one
session, then fan the restore over the whole session and verify both are undone.

    python pub_session_restore_test_2026-06-22.py
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

SESSION = "compromised-session"
_SEQ = [0]


def _allow(env, proj, cmd=None, tool="Bash", tool_input=None):
    _SEQ[0] += 1
    ev = {"session_id": SESSION, "transcript_path": str(proj / "t.jsonl"), "cwd": str(proj),
          "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": tool,
          "tool_input": tool_input or {"command": cmd}, "tool_use_id": f"s{_SEQ[0]}"}
    adm = h.run_pretool_admission(json.dumps(ev), environ=env)
    return adm.output is None


def main() -> int:
    base = Path(tempfile.mkdtemp(dir=str(Path.home())))
    proj = base / "repo"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    a = proj / "src" / "a.py"; a.write_text("V=1\n", encoding="utf-8")
    b = proj / "src" / "b.py"; b.write_text("keep\n", encoding="utf-8")
    env = {
        "CLAUDE_PROJECT_DIR": str(proj),
        "PUB_CLAUDE_HOOK_STATE_DIR": str(base / "state"),
        "PUB_CLAUDE_HOOK_LOG_DIR": str(base / "logs"),
        "PUB_CLAUDE_SCENE_STATE_DIR": str(base / "scene"),
        "PUB_CLAUDE_TEMPORAL_STATE_DIR": str(base / "temporal"),
        "PUB_CLAUDE_ACTOR_ID": "claude_code",
    }
    R: list[tuple[bool, str]] = []

    def check(c, label):
        R.append((bool(c), label)); print(f"[{'PASS' if c else 'FAIL'}] {label}")

    # two allowed, journalled mutations in the SAME session
    ok1 = _allow(env, proj, tool="Edit", tool_input={"file_path": str(a), "old_string": "1", "new_string": "2"})
    ok2 = _allow(env, proj, cmd="rm src/b.py")
    check(ok1 and ok2, "two in-project mutations allowed + journalled in one session")

    # simulate the agent executing them
    a.write_text("V=2\n", encoding="utf-8")
    b.unlink()

    # the session is later judged compromised -> retake the whole session's ground
    res = h.restore_session_backfill(SESSION, env)
    check(res["manifests"] == 2, f"session restore found both journals (manifests={res['manifests']})")
    check(a.read_text(encoding="utf-8") == "V=1\n", "edited file reverted to pre-image (V=1)")
    check(b.exists() and b.read_text(encoding="utf-8") == "keep\n", "deleted file restored")

    # an unrelated session's journal is NOT touched
    other = proj / "src" / "c.py"; other.write_text("other\n", encoding="utf-8")
    ev = {"session_id": "innocent", "cwd": str(proj), "hook_event_name": "PreToolUse",
          "tool_name": "Edit", "tool_input": {"file_path": str(other), "old_string": "other", "new_string": "x"},
          "tool_use_id": "iso1", "transcript_path": str(proj / "t.jsonl")}
    h.run_pretool_admission(json.dumps(ev), environ=env)
    other.write_text("x\n", encoding="utf-8")
    res2 = h.restore_session_backfill(SESSION, env)  # restoring the compromised session again
    check(other.read_text(encoding="utf-8") == "x\n", "a different session's work is NOT rolled back")

    passed = sum(1 for ok, _ in R if ok)
    print(f"\n=== session restore ④b: {passed}/{len(R)} checks passed ===")
    return 0 if passed == len(R) else 1


if __name__ == "__main__":
    raise SystemExit(main())
