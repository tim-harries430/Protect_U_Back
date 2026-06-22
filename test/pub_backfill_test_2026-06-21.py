"""Functional test for the reversible-board backfill (補位) -- 2026-06-21.

pub does not execute; admission only journals the PRE-IMAGE. So each case here:
  1. set up an in-project file,
  2. run admission (which snapshots the pre-image into the journal),
  3. SIMULATE the agent actually performing the mutation,
  4. call restore_from_backfill_journal -> assert the ground is retaken.

    python pub_backfill_test_2026-06-21.py
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

PASS = "\033[0m"


_SEQ = [0]


def _run(env, proj, cmd, tool="Bash", tool_input=None):
    _SEQ[0] += 1  # real Claude Code sends a unique tool_use_id per call
    event = {
        "session_id": "backfill-test",
        "transcript_path": str(proj / "t.jsonl"),
        "cwd": str(proj),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input or {"command": cmd},
        "tool_use_id": f"bf{_SEQ[0]}",
    }
    adm = h.run_pretool_admission(json.dumps(event), environ=env)
    cid = h._event_correlation_id(event, action=adm.action)
    return adm, cid


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

    def check(cond: bool, label: str):
        results.append((cond, label))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # --- Case 1: single-file rm of an existing in-project file -> pre-image journalled, restore brings it back
    app = proj / "src" / "app.py"
    app.write_text("ORIGINAL CONTENT\n", encoding="utf-8")
    adm, cid = _run(env, proj, "rm src/app.py")
    check(adm.output is None, "rm src/app.py is ALLOWED (reversible single-file delete)")
    manifest = h._backfill_dir(cid, env) / "manifest.json"
    check(manifest.exists(), "journal manifest written for the delete")
    # simulate the agent executing the delete:
    app.unlink()
    check(not app.exists(), "  (simulated) file deleted by the tool")
    res = h.restore_from_backfill_journal(cid, env)
    check(app.exists() and app.read_text(encoding="utf-8") == "ORIGINAL CONTENT\n",
          f"restore retook the ground: file back with original bytes  ({res['restored']} restored)")

    # --- Case 2: Write tool creating a NEW file -> journal records ABSENT, restore removes it
    new = proj / "src" / "created.py"
    adm2, cid2 = _run(env, proj, "", tool="Write",
                      tool_input={"file_path": str(new), "content": "x=1\n"})
    check(adm2.output is None, "Write new file is ALLOWED")
    # simulate the agent executing the write:
    new.write_text("x=1\n", encoding="utf-8")
    res2 = h.restore_from_backfill_journal(cid2, env)
    check(not new.exists(), f"restore of a created file removes it (no pre-image)  ({res2['restored']} restored)")

    # --- Case 3: Edit overwriting an existing file -> pre-image journalled, restore reverts content
    cfg = proj / "src" / "cfg.py"
    cfg.write_text("VERSION=1\n", encoding="utf-8")
    adm3, cid3 = _run(env, proj, "", tool="Edit",
                      tool_input={"file_path": str(cfg), "old_string": "1", "new_string": "2"})
    check(adm3.output is None, "Edit existing file is ALLOWED")
    cfg.write_text("VERSION=2\n", encoding="utf-8")  # simulate the edit landing
    h.restore_from_backfill_journal(cid3, env)
    check(cfg.read_text(encoding="utf-8") == "VERSION=1\n", "restore reverts edited content to pre-image")

    # --- Case 4: blocked op leaves NO journal (we only journal allowed mutations)
    adm4, cid4 = _run(env, proj, "rm -rf /")
    check(adm4.output is not None, "rm -rf / stays BLOCKED")
    check(not (h._backfill_dir(cid4, env) / "manifest.json").exists(),
          "no journal for a blocked op")

    passed = sum(1 for ok, _ in results if ok)
    print(f"\n=== backfill: {passed}/{len(results)} checks passed ===")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
