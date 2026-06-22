"""Red-team round 4 -- REAL Windows filesystem TTPs vs pub's REAL transition_xray.

Adapted from a hardcore suite that only exercised a MOCK scanner. Here the same
ATT&CK-style primitives (hardlink alias, timestomp / T1070.006, junction / reparse
redirection, ADS smuggling / T1564.004, atomic rename swap, transient blind-spot file,
delete, compound chain) are driven against pub's ACTUAL enter/exit X-ray
(scan_transition_xray + compare_transition_xray) and the xray_review verdict.

pub anchors on physical content (sha256) + lstat, so it should be IMMUNE to pure
metadata masquerade and CATCH content mutation -- but snapshot-only scanning and the
main-stream hash leave honest gaps (ADS, transient). Report is generated from real runs.

    python pub_hardcore_ttp.py        # Windows only; writes JSON + MD
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from ot_gate import CommandProposal, DeclaredScope, SideEffect
from transition_xray import XrayPhase, compare_transition_xray, scan_transition_xray
from xray_review import review_proposal

RESULTS: list[dict] = []
JSON_OUT = Path(__file__).resolve().parent / "pub_hardcore_ttp_report.json"
MD_OUT = Path(__file__).resolve().parent / "pub_hardcore_ttp_report.md"


def _proposal(cwd: Path, target: Path) -> CommandProposal:
    return CommandProposal(
        command_text=f"read {target.name}",
        actor_id="redteam",
        cwd=str(cwd),
        declared_scope=DeclaredScope.READ_ONLY,
        target_paths=(str(target),),
        expected_side_effects={SideEffect.READ},
        parent_event_id="evt",
        user_request_id="ureq",
        proposal_id="ttp",
    )


def run_ttp(name: str, tta: str, cwd: Path, target: Path, attack) -> None:
    """enter-scan -> run the attack -> exit-scan -> compare. Record what pub saw."""
    prop = _proposal(cwd, target)
    try:
        enter = scan_transition_xray(prop, phase=XrayPhase.ENTER)
        attack()  # the real Windows TTP fires inside the enter/exit window
        exit_frame = scan_transition_xray(prop, phase=XrayPhase.EXIT)
        pair = compare_transition_xray(enter, exit_frame)
        findings = sorted({f.finding_type for f in pair.findings})
        mutated = str(getattr(pair.mutation_state, "value", pair.mutation_state))
        try:
            review = review_proposal(prop)
            disp = review.disposition.value
        except Exception:  # noqa: BLE001
            disp = "n/a"
        detected = mutated.upper() != "STABLE" or bool(findings)
        RESULTS.append({
            "ttp": name, "attck": tta, "detected": detected,
            "mutation_state": mutated, "findings": findings, "review_disposition": disp,
        })
        tag = "CAUGHT" if detected else ">>> MISSED"
        print(f"[{tag:12}] {name:34} mutation={mutated:9} findings={findings} review={disp}")
    except Exception as exc:  # noqa: BLE001
        RESULTS.append({"ttp": name, "attck": tta, "detected": None, "error": f"{type(exc).__name__}: {exc}"})
        print(f"[SKIPPED     ] {name:34} primitive unavailable: {type(exc).__name__}: {str(exc)[:50]}")


def main() -> int:
    if sys.platform != "win32":
        print("Windows-only TTP suite; skipping on", sys.platform)
        return 0
    with tempfile.TemporaryDirectory() as d:
        cwd = Path(d)

        # 1. write-on-READ_ONLY (content mutation)
        t = cwd / "ro.txt"; t.write_bytes(b"V1")
        run_ttp("write_on_readonly", "T1565.001", cwd, t, lambda: t.write_bytes(b"TAMPERED_V2"))

        # 2. delete during blind spot
        t = cwd / "vanish.txt"; t.write_bytes(b"here")
        run_ttp("delete_in_window", "T1070.004", cwd, t, lambda: t.unlink())

        # 3. timestomp: mutate content then RESTORE original mtime (anti-forensics)
        t = cwd / "stomp.txt"; t.write_bytes(b"legit-data-len20!!!!")
        omt = os.stat(t).st_mtime_ns; oat = os.stat(t).st_atime_ns
        def _stomp():
            t.write_bytes(b"evil0-data-len20!!!!")  # same length, diff bytes
            os.utime(t, ns=(oat, omt))              # restore mtime/atime
        run_ttp("timestomp_content_tamper", "T1070.006", cwd, t, _stomp)

        # 4. hardlink cross-dir alias + mutate via the alias (outside the watched path)
        sk = cwd / "skill"; sk.mkdir(); t = sk / "prot.txt"; t.write_bytes(b"PROTECTED")
        az = cwd / "att"; az.mkdir(); alias = az / "back.link"
        def _hl():
            os.link(t, alias)                # NTFS hardlink (no admin)
            alias.write_bytes(b"EXFILTRATED!")
        run_ttp("hardlink_alias_mutation", "T1547/alias", cwd, t, _hl)

        # 5. junction / reparse-point redirection of the parent dir
        sk = cwd / "pkg"; sk.mkdir(); t = sk / "manifest.json"; t.write_bytes(b'{"v":1}')
        shadow = cwd / "shadow"; shadow.mkdir(); (shadow / "manifest.json").write_bytes(b'{"v":999,"pwned":1}')
        def _junction():
            import shutil
            shutil.rmtree(sk)
            subprocess.run(["cmd", "/c", "mklink", "/J", str(sk), str(shadow)], capture_output=True)
        run_ttp("junction_path_redirection", "T1547.009", cwd, t, _junction)

        # 6. ADS smuggling -- payload in an alternate data stream, then RESTORE the
        # host mtime (T1070.006) so the only side-effect pub could notice is erased.
        t = cwd / "clean.txt"; t.write_bytes(b"totally innocent")
        _amt, _aat = os.stat(t).st_mtime_ns, os.stat(t).st_atime_ns
        def _ads():
            with open(str(t) + ":payload.exe", "wb") as fh:
                fh.write(b"MZ\x90\x00malware")
            os.utime(t, ns=(_aat, _amt))
        run_ttp("ads_stream_smuggling", "T1564.004+T1070.006", cwd, t, _ads)

        # 7. atomic rename swap (metadata masquerade)
        a = cwd / "a.txt"; b = cwd / "b.txt"
        a.write_bytes(b"AAAA_orig_data_pad20"); b.write_bytes(b"BBBB_decoy_data_pad2")
        os.utime(b, ns=(os.stat(a).st_atime_ns, os.stat(a).st_mtime_ns))
        def _swap():
            tmp = cwd / ".swap.tmp"
            os.replace(a, tmp); os.replace(b, a); os.replace(tmp, b)
        run_ttp("atomic_rename_swap", "T1036/masquerade", cwd, a, _swap)

        # 8. transient file -- born & died entirely inside the enter/exit window
        t = cwd / "base.txt"; t.write_bytes(b"baseline")
        def _transient():
            flash = cwd / "flash.tmp"; flash.write_bytes(b"only-in-the-gap"); flash.unlink()
        run_ttp("transient_blindspot_file", "snapshot-gap", cwd, t, _transient)

        # 9. compound chain: hardlink + mutate + timestomp + ADS
        sk = cwd / "sk2"; sk.mkdir(); t = sk / "data.bin"; t.write_bytes(b"ORIG" * 32)
        omt2 = os.stat(t).st_mtime_ns; oat2 = os.stat(t).st_atime_ns
        az2 = cwd / "att2"; az2.mkdir(); alias2 = az2 / "al.bin"
        def _chain():
            os.link(t, alias2)
            alias2.write_bytes(b"EVIL" * 32)
            os.utime(t, ns=(oat2, omt2))
            with open(str(t) + ":exfil.log", "wb") as fh:
                fh.write(b"stolen=admin:pw")
        run_ttp("compound_chain", "multi", cwd, t, _chain)

    report = _build_report()
    JSON_OUT.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    _write_md(report)
    s = report["summary"]
    print(f"\n=== {s['caught']}/{s['ran']} CAUGHT, {s['missed']} MISSED, {s['skipped']} skipped ===")
    print(f"wrote {JSON_OUT.name} + {MD_OUT.name}")
    return 0


def _build_report() -> dict:
    ran = [r for r in RESULTS if r["detected"] is not None]
    caught = [r for r in ran if r["detected"]]
    missed = [r for r in ran if not r["detected"]]
    skipped = [r for r in RESULTS if r["detected"] is None]
    return {
        "schema": "pub_hardcore_ttp_v0",
        "title": "Red-team round 4 -- real Windows filesystem TTPs vs pub's real transition_xray",
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "method": "ATT&CK-style primitives fired inside pub's enter/exit X-ray window; "
                  "detection = mutation_state != STABLE or any finding.",
        "summary": {"ran": len(ran), "caught": len(caught), "missed": len(missed), "skipped": len(skipped)},
        "missed": [{"ttp": r["ttp"], "attck": r["attck"]} for r in missed],
        "results": RESULTS,
    }


def _write_md(r: dict) -> None:
    s = r["summary"]
    lines = [
        f"# {r['title']}", "",
        f"_Generated {r['generated_at']} -- reproducible: `python pub_hardcore_ttp.py` (Windows)_", "",
        f"**Method:** {r['method']}", "",
        f"## {s['caught']}/{s['ran']} CAUGHT, {s['missed']} MISSED, {s['skipped']} skipped", "",
        "| TTP | ATT&CK | Verdict | mutation_state | findings | review |", "|---|---|---|---|---|---|",
    ]
    for x in r["results"]:
        if x["detected"] is None:
            lines.append(f"| {x['ttp']} | {x['attck']} | SKIPPED | - | {x.get('error','')[:40]} | - |")
        else:
            v = "CAUGHT" if x["detected"] else "**MISSED**"
            lines.append(f"| {x['ttp']} | {x['attck']} | {v} | {x['mutation_state']} | {','.join(x['findings'])} | {x['review_disposition']} |")
    lines += ["", "### Honest gaps (MISSED)", ""]
    if r["missed"]:
        for m in r["missed"]:
            lines.append(f"- **{m['ttp']}** ({m['attck']})")
    else:
        lines.append("_None._")
    lines.append("")
    MD_OUT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
