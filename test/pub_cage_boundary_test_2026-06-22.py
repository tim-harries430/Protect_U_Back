"""pub bwrap cage boundary probe -- 2026-06-22.

Bellard: "Using a container or a VM is the way to go when it is possible." This
measures how good pub's actual bwrap cage is -- prison or just a tall fence?
Runs REAL bwrap with build_cage_argv and probes from inside. Must run under Linux
(WSL) with `python3` (not python.exe -- bwrap is Linux-only).

    python3 pub_cage_boundary_test_2026-06-22.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/mnt/c/dev/sp")
from pub_os_cage import CageSpec, build_cage_argv, cage_available  # noqa: E402

PROBE = r'''
P="$PWD"
( echo data > "$P/inside.txt" && echo "A write-inside-project = OK (workspace fully writable)" ) || echo "A write-inside-project = FAIL"
( echo x > /etc/pub_escape 2>/dev/null && echo "B write /etc = OK *** LEAK ***" ) || echo "B write /etc = BLOCKED (ro)"
( echo x > "/pub_escape_root" 2>/dev/null && echo "C write / = OK *** LEAK ***" ) || echo "C write / = BLOCKED"
( [ -d "$HOME" ] && echo "D \$HOME ($HOME) = EXISTS" ) || echo "D \$HOME = ABSENT (not mounted)"
( cat "$HOME/.ssh/id_rsa" >/dev/null 2>&1 && echo "E read ~/.ssh/id_rsa = READABLE *** LEAK ***" ) || echo "E read ~/.ssh/id_rsa = ABSENT/BLOCKED"
( ls /home >/dev/null 2>&1 && [ -n "$(ls /home 2>/dev/null)" ] && echo "F /home = VISIBLE ($(ls /home|tr '\n' ' '))" ) || echo "F /home = EMPTY/ABSENT"
( head -1 /etc/passwd >/dev/null 2>&1 && echo "G read /etc/passwd = READABLE (system runtime)" ) || echo "G read /etc/passwd = BLOCKED"
( echo x > "$P/../escape_up.txt" 2>/dev/null && echo "H write ../ (parent) = OK *** LEAK ***" ) || echo "H write ../ (parent) = BLOCKED"
echo "I net-namespace interfaces = [$(awk -F: 'NR>2{gsub(/ /,"",$1);printf "%s ",$1}' /proc/net/dev)]"
( ls /mnt/c/dev/sp/ot_gate.py >/dev/null 2>&1 && echo "J read pub source = VISIBLE *** LEAK ***" ) || echo "J read pub source = ABSENT (outside project)"
'''


def run_cage(label: str, allow_net: bool) -> None:
    base = Path(tempfile.mkdtemp(prefix="pub_cage_"))
    proj = base / "repo"
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "src" / "app.py").write_text("x=1\n", encoding="utf-8")
    spec = CageSpec(project_root=str(proj), allow_net=allow_net)
    argv = build_cage_argv(["/bin/sh", "-c", PROBE], spec)
    print(f"\n=== CAGE: {label} (allow_net={allow_net}) ===")
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        print(r.stdout.rstrip() or "(no stdout)")
        if r.stderr.strip():
            print("  stderr:", r.stderr.strip().splitlines()[0])
    except Exception as exc:  # noqa: BLE001
        print(f"  cage run error: {exc.__class__.__name__}: {exc}")
        return
    # host-side reversibility check: did the in-cage write land on the REAL disk?
    landed = (proj / "inside.txt").exists()
    print(f"K reversibility: in-cage write persisted on host disk = {landed}  "
          f"({'NO overlay -- writes are permanent/irreversible' if landed else 'isolated'})")


def main() -> int:
    ok, reason = cage_available()
    print(f"cage_available = {ok} ({reason})")
    if not ok:
        print("bwrap not usable here; cannot probe.")
        return 1
    run_cage("default", allow_net=True)
    run_cage("net-locked", allow_net=False)
    print("\n--- read: a host with >1 interface inside = network reachable (fence); "
          "only 'lo' = network sealed (prison) ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
