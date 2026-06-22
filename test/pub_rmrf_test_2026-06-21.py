"""③ rm -rf workspace-internal recursive delete -- 2026-06-21.

In-project recursive/dir delete is ALLOWED (and the whole tree is journalled so it
can be retaken); escape, root, and protected surfaces stay BLOCKED. glob/dynamic are
NOT relaxed (the gate cannot enumerate/journal them) -> fail-closed.

    python pub_rmrf_test_2026-06-21.py
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

for _p in (r"C:\dev\sp", "/mnt/c/dev/sp"):
    if _p not in sys.path and Path(_p).exists():
        sys.path.insert(0, _p)

import claude_code_hooks as h  # noqa: E402

_SEQ = [0]


def _env(base, proj):
    return {
        "CLAUDE_PROJECT_DIR": str(proj),
        "PUB_CLAUDE_HOOK_STATE_DIR": str(base / "state"),
        "PUB_CLAUDE_HOOK_LOG_DIR": str(base / "logs"),
        "PUB_CLAUDE_SCENE_STATE_DIR": str(base / "scene"),
        "PUB_CLAUDE_TEMPORAL_STATE_DIR": str(base / "temporal"),
        "PUB_CLAUDE_ACTOR_ID": "claude_code",
    }


def _verdict(env, proj, cmd):
    _SEQ[0] += 1
    ev = {"session_id": "rmrf", "transcript_path": str(proj / "t.jsonl"), "cwd": str(proj),
          "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
          "tool_input": {"command": cmd}, "tool_use_id": f"r{_SEQ[0]}"}
    adm = h.run_pretool_admission(json.dumps(ev), environ=env)
    return (adm.output is None), (None if adm.output is None else adm.reason_code), ev, adm


def main() -> int:
    base = Path(tempfile.mkdtemp(dir=str(Path.home())))
    proj = base / "repo"
    for d in ("build/nested", "node_modules/pkg", "src", ".git/hooks", ".phi", ".claude", "secrets"):
        (proj / d).mkdir(parents=True, exist_ok=True)
    (proj / "build" / "out.o").write_text("obj\n", encoding="utf-8")
    (proj / "build" / "nested" / "deep.txt").write_text("deep\n", encoding="utf-8")
    (proj / "src" / "app.py").write_text("x=1\n", encoding="utf-8")
    (proj / ".env").write_text("SECRET=1\n", encoding="utf-8")
    env = _env(base, proj)
    R: list[tuple[bool, str]] = []

    def allow(cmd):
        ok, reason, *_ = _verdict(env, proj, cmd)
        R.append((ok, cmd)); print(f"[{'PASS' if ok else 'FAIL'}] expect ALLOW: {cmd}  -> {'allow' if ok else reason}")

    def block(cmd):
        ok, reason, *_ = _verdict(env, proj, cmd)
        R.append((not ok, cmd)); print(f"[{'PASS' if not ok else 'FAIL'}] expect BLOCK: {cmd}  -> {'allow' if ok else reason}")

    print("--- in-project recursive delete: ALLOW ---")
    for c in ["rm -rf build/nested", "rm -rf node_modules", "rm -rf build"]:
        allow(c)

    print("\n--- must stay BLOCK (root/home/escape/protected/glob/dynamic) ---")
    for c in ["rm -rf /", "rm -rf ~", "rm -rf .", "rm -rf ..",
              "rm -rf .git", "rm -rf .phi", "rm -rf .claude", "rm -rf secrets",
              "rm -rf src/../.git", "rm -rf ../../etc", "rm -rf build/../..",
              "rm -rf $(pwd)/build", "rm -rf *", "rm -rf build/*.o",
              "rm -rf /etc", "rm -rf ../sibling"]:
        block(c)

    print("\n--- journal + restore a recursive delete (retake the tree) ---")
    ok, reason, ev, adm = _verdict(env, proj, "rm -rf build")
    cid = h._event_correlation_id(ev, action=adm.action)
    man = h._backfill_dir(cid, env) / "manifest.json"
    R.append((ok, "rm -rf build allowed")); print(f"[{'PASS' if ok else 'FAIL'}] rm -rf build allowed")
    R.append((man.exists(), "tree journalled")); print(f"[{'PASS' if man.exists() else 'FAIL'}] tree journalled")
    shutil.rmtree(proj / "build")  # simulate the agent executing the delete
    res = h.restore_from_backfill_journal(cid, env)
    back = (proj / "build" / "out.o").read_text(encoding="utf-8") == "obj\n" if (proj / "build" / "out.o").exists() else False
    deep = (proj / "build" / "nested" / "deep.txt").exists()
    R.append((back and deep, "tree restored")); print(f"[{'PASS' if back and deep else 'FAIL'}] tree restored ({res['restored']} files, deep={deep})")

    passed = sum(1 for ok, _ in R if ok)
    print(f"\n=== rmrf ③: {passed}/{len(R)} checks passed ===")
    return 0 if passed == len(R) else 1


if __name__ == "__main__":
    raise SystemExit(main())
