"""④b auto-restore + inferred pass-road test -- 2026-06-21.

Safety first: a benign write is de-noised to PASS, so auto-restore must NOT fire on
it (legitimate work is never undone). Auto-restore fires ONLY when the de-noised
X-ray returns QUARANTINE (a real disguise/tamper) on a journalled op that is NOT a
clean inferred pass-road traversal.

    python pub_autorestore_test_2026-06-21.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

for _p in (r"C:\dev\sp", "/mnt/c/dev/sp"):
    if _p not in sys.path and Path(_p).exists():
        sys.path.insert(0, _p)

import claude_code_hooks as h  # noqa: E402
from llm_channel import infer_pass_road  # noqa: E402

_SEQ = [0]


def _cycle(env, proj, tool, tool_input, mutate):
    _SEQ[0] += 1
    ev = {
        "session_id": "autorestore", "transcript_path": str(proj / "t.jsonl"),
        "cwd": str(proj), "permission_mode": "default", "hook_event_name": "PreToolUse",
        "tool_name": tool, "tool_input": tool_input, "tool_use_id": f"ar{_SEQ[0]}",
    }
    h.run_pretool_admission(json.dumps(ev), environ=env)
    mutate()
    post = dict(ev); post["hook_event_name"] = "PostToolUse"; post["tool_response"] = {"ok": True}
    au = h.run_posttool_autopsy(json.dumps(post), environ=env)
    return au


def main() -> int:
    base = Path(tempfile.mkdtemp(dir=str(Path.home())))
    proj = base / "repo"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "data").mkdir(parents=True, exist_ok=True)
    env = {
        "CLAUDE_PROJECT_DIR": str(proj),
        "PUB_CLAUDE_HOOK_STATE_DIR": str(base / "state"),
        "PUB_CLAUDE_HOOK_LOG_DIR": str(base / "logs"),
        "PUB_CLAUDE_SCENE_STATE_DIR": str(base / "scene"),
        "PUB_CLAUDE_TEMPORAL_STATE_DIR": str(base / "temporal"),
        "PUB_CLAUDE_ACTOR_ID": "claude_code",
    }
    R: list[tuple[bool, str]] = []

    def check(cond, label):
        R.append((bool(cond), label)); print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    pr = str(proj)
    # --- B: infer_pass_road classification (unit) ---
    check(infer_pass_road("cat reports/x.txt", ("reports/x.txt",), pr, has_write=False)
          == "pass-road:daily-read-project:v1", "infer: read in-project -> read recipe")
    check(infer_pass_road("sed -i s/a/b/ data/x.csv", ("data/x.csv",), pr, has_write=True)
          == "pass-road:daily-data-transform:v1", "infer: write into data/ -> data-transform recipe")
    check(infer_pass_road("python foo.py", ("foo.py",), pr, has_write=False) is None,
          "infer: python (opaque/forbidden) -> off road")
    check(infer_pass_road("rm src/app.py", ("src/app.py",), pr, has_write=True) is None,
          "infer: rm (forbidden) -> off road")
    check(infer_pass_road("curl http://x.example -o data/d", ("data/d",), pr, has_write=True) is None,
          "infer: network -> off road")
    check(infer_pass_road("sed -i s/a/b/ src/app.py", ("src/app.py",), pr, has_write=True) is None,
          "infer: write to src/ (out of write lane) -> off road")

    # --- A (SAFETY): benign Edit is PASS -> auto-restore must NOT fire, content kept ---
    cfg = proj / "src" / "cfg.py"; cfg.write_text("V=1\n", encoding="utf-8")
    au = _cycle(env, proj, "Edit", {"file_path": str(cfg), "old_string": "1", "new_string": "2"},
                lambda: cfg.write_text("V=2\n", encoding="utf-8"))
    review = au.review.disposition.value if au.review else "?"
    check(review == "PASS", f"benign Edit -> review={review} (PASS)")
    check(cfg.read_text(encoding="utf-8") == "V=2\n",
          "SAFETY: benign edit NOT auto-reverted (legit work preserved)")

    # --- C: a disguise (hardlink ALIAS) is caught at PreToolUse, not after. This is
    # WHY auto-restore is NOT wired to the X-ray review: anything the single-frame
    # review would quarantine is already blocked pre-exec, so it never coincides with
    # an allowed, journalled op. The wall handles it; no ground is ever lost.
    orig = proj / "src" / "aliased.py"; orig.write_text("ORIGINAL\n", encoding="utf-8")
    link = proj / "src" / "alias_link.py"
    try:
        os.link(orig, link)  # nlink=2 -> ALIAS disguise on the enter frame
        linked = True
    except OSError as exc:
        linked = False
        print(f"[SKIP] hardlink unsupported on this FS ({exc.__class__.__name__}); pre-exec-block test skipped")
    if linked:
        _SEQ[0] += 1
        ev = {
            "session_id": "autorestore", "transcript_path": str(proj / "t.jsonl"),
            "cwd": str(proj), "permission_mode": "default", "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(orig), "old_string": "ORIGINAL", "new_string": "TAMPERED"},
            "tool_use_id": f"ar{_SEQ[0]}",
        }
        adm = h.run_pretool_admission(json.dumps(ev), environ=env)
        check(adm.output is not None and adm.reason_code == "XRAY_REVIEW_ALIAS",
              f"hardlink-aliased write BLOCKED at PreToolUse (reason={None if adm.output is None else adm.reason_code})")
        cid = h._event_correlation_id(ev, action=adm.action)
        check(not (h._backfill_dir(cid, env) / "manifest.json").exists(),
              "blocked op is never journalled (nothing to restore -- the wall already held)")

    passed = sum(1 for ok, _ in R if ok)
    print(f"\n=== auto-restore: {passed}/{len(R)} checks passed ===")
    return 0 if passed == len(R) else 1


if __name__ == "__main__":
    raise SystemExit(main())
