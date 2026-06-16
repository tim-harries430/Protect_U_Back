from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence


CODE_ROOT = Path(__file__).resolve().parent
PACKAGE_ROOT = CODE_ROOT.parent if CODE_ROOT.name.lower() == "project" else CODE_ROOT
REPORTS_DIR = PACKAGE_ROOT / "reports"
TEST_DIR = PACKAGE_ROOT / "test"


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "menu":
        return run_menu()

    if args.command == "doctor":
        return run_protect(("doctor",))

    if args.command == "schema":
        return run_protect(("schema",))

    if args.command == "smoke":
        command = ["smoke"]
        if args.confirm_protect:
            command.append("--confirm-protect")
        return run_protect(tuple(command))

    if args.command == "demo":
        return run_local_script(CODE_ROOT / "demo_60s.py")

    if args.command == "audit":
        return run_audit(
            input_path=Path(args.input),
            output_path=Path(args.output) if args.output else None,
            input_format=args.input_format,
            source_adapter=args.source_adapter,
        )

    if args.command == "harness":
        return run_harness_connector(args)

    if args.command == "openclaw":
        return run_openclaw_connector(args)

    if args.command == "kimi":
        return run_kimi_connector(args)

    if args.command == "claude-code":
        return run_claude_code_connector(args)

    if args.command == "codex":
        return run_codex_connector(args)

    return run_menu()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ProtectUBack",
        description="Offline local launcher for Protect U Back.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("menu", help="Open the local launcher menu.")
    subparsers.add_parser("doctor", help="Run local module and schema checks.")
    subparsers.add_parser("schema", help="Print the local audit input schema.")

    smoke = subparsers.add_parser("smoke", help="Run one local dry-run smoke audit.")
    smoke.add_argument("--confirm-protect", action="store_true", default=True)

    subparsers.add_parser("demo", help="Run the 60-second evidence demo.")

    audit = subparsers.add_parser("audit", help="Audit a local JSON/JSONL case file.")
    audit.add_argument("input", help="Local JSON, JSONL, or cases[] file.")
    audit.add_argument("--output", help="Optional local JSON report path.")
    audit.add_argument(
        "--input-format",
        choices=("auto", "agent", "harness"),
        default="auto",
        help="Input normalizer.",
    )
    audit.add_argument(
        "--source-adapter",
        default="launcher",
        help="Adapter label stamped into ActionEnvelope testimony.",
    )

    harness = subparsers.add_parser("harness", help="Manage the local OpenHarness connector.")
    harness_subparsers = harness.add_subparsers(dest="harness_command", required=True)
    for command in ("status", "connect", "disconnect", "verify"):
        item = harness_subparsers.add_parser(command)
        item.add_argument("--openharness-root", help="Path to the installed openharness package root.")
        item.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    openclaw = subparsers.add_parser("openclaw", help="Manage the local OpenClaw connector.")
    openclaw_subparsers = openclaw.add_subparsers(dest="openclaw_command", required=True)
    for command in ("status", "connect", "disconnect", "verify"):
        item = openclaw_subparsers.add_parser(command)
        item.add_argument("--openclaw-root", required=True, help="Path to the installed openclaw package root.")
        item.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    kimi = subparsers.add_parser("kimi", help="Manage the local Kimi CLI connector.")
    kimi_subparsers = kimi.add_subparsers(dest="kimi_command", required=True)
    for command in ("status", "connect", "disconnect", "verify"):
        item = kimi_subparsers.add_parser(command)
        item.add_argument("--kimi-root", required=True, help="Path to the local kimi-cli repository root.")
        item.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    claude_code = subparsers.add_parser("claude-code", help="Manage the local Claude Code hook connector.")
    claude_code_subparsers = claude_code.add_subparsers(dest="claude_code_command", required=True)
    for command in ("status", "connect", "disconnect", "verify"):
        item = claude_code_subparsers.add_parser(command)
        item.add_argument(
            "--claude-project",
            default=".",
            help="Claude Code project root that owns the .claude settings directory.",
        )
        item.add_argument(
            "--protect-root",
            help="Protect U Back root as seen by Claude Code, for example /mnt/c/dev/sp.",
        )
        item.add_argument(
            "--python-bin",
            default=None,
            help="Python executable as seen by Claude Code; blank auto-detects per --platform.",
        )
        item.add_argument(
            "--platform",
            choices=("auto", "windows", "posix"),
            default="auto",
            help="Target platform for the hook command. auto matches this machine; "
            "windows uses py -3 and C:\\ paths; posix uses python3 and /mnt paths.",
        )
        item.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    codex = subparsers.add_parser("codex", help="Manage the local Codex shell guard connector.")
    codex_subparsers = codex.add_subparsers(dest="codex_command", required=True)
    for command in ("status", "connect", "disconnect", "verify"):
        item = codex_subparsers.add_parser(command)
        item.add_argument(
            "--codex-project",
            default=".",
            help="Codex project root that will receive the .pub_codex_guard launcher.",
        )
        item.add_argument(
            "--protect-root",
            help="Protect U Back root as seen by Codex, for example /mnt/c/dev/sp.",
        )
        item.add_argument(
            "--python-bin",
            default="python3",
            help="Python executable as seen by Codex.",
        )
        item.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    return parser


def run_menu() -> int:
    while True:
        print()
        print("Protect U Back - Local Launcher")
        print("No network. No account. No daemon. No telemetry.")
        print()
        print("1. Doctor")
        print("2. Schema")
        print("3. Smoke")
        print("4. 60s Demo")
        print("5. Audit local case file")
        print("6. OpenHarness connector")
        print("7. Connect OpenClaw")
        print("8. Connect Kimi CLI")
        print("9. Connect Claude Code")
        print("10. Connect Codex CLI")
        print("0. Exit")
        choice = input("> ").strip()

        if choice == "1":
            return_code = run_protect(("doctor",))
        elif choice == "2":
            return_code = run_protect(("schema",))
        elif choice == "3":
            return_code = run_protect(("smoke", "--confirm-protect"))
        elif choice == "4":
            return_code = run_local_script(CODE_ROOT / "demo_60s.py")
        elif choice == "5":
            path = input("Local case file path: ").strip().strip('"')
            if not path:
                print("No input path provided.")
                continue
            return_code = run_audit(input_path=Path(path))
        elif choice == "6":
            return_code = run_harness_menu()
        elif choice == "7":
            return_code = run_openclaw_menu()
        elif choice == "8":
            return_code = run_kimi_menu()
        elif choice == "9":
            return_code = run_claude_code_menu()
        elif choice == "10":
            return_code = run_codex_menu()
        elif choice == "0":
            return 0
        else:
            print("Unknown selection.")
            continue

        print()
        print(f"Command exited with code {return_code}.")


def run_harness_menu() -> int:
    print()
    print("OpenHarness connector")
    print("1. Status")
    print("2. Connect")
    print("3. Verify")
    print("4. Disconnect")
    choice = input("> ").strip()
    command = {"1": "status", "2": "connect", "3": "verify", "4": "disconnect"}.get(choice)
    if command is None:
        print("Unknown selection.")
        return 1
    root = input("OpenHarness package root (blank = import discovery): ").strip().strip('"')
    return run_harness_connector(
        argparse.Namespace(
            harness_command=command,
            openharness_root=root or None,
            json=False,
        )
    )


def run_openclaw_menu() -> int:
    print()
    print("Connect OpenClaw")
    print("1. Status")
    print("2. Connect OpenClaw")
    print("3. Verify")
    print("4. Disconnect")
    choice = input("> ").strip()
    command = {"1": "status", "2": "connect", "3": "verify", "4": "disconnect"}.get(choice)
    if command is None:
        print("Unknown selection.")
        return 1
    root = input("OpenClaw package root: ").strip().strip('"')
    if not root:
        print("OpenClaw package root is required.")
        return 1
    return run_openclaw_connector(
        argparse.Namespace(
            openclaw_command=command,
            openclaw_root=root,
            json=False,
        )
    )


def run_kimi_menu() -> int:
    print()
    print("Connect Kimi CLI")
    print("1. Status")
    print("2. Connect Kimi CLI")
    print("3. Verify")
    print("4. Disconnect")
    choice = input("> ").strip()
    command = {"1": "status", "2": "connect", "3": "verify", "4": "disconnect"}.get(choice)
    if command is None:
        print("Unknown selection.")
        return 1
    root = input("Kimi CLI repository root: ").strip().strip('"')
    if not root:
        print("Kimi CLI repository root is required.")
        return 1
    return run_kimi_connector(
        argparse.Namespace(
            kimi_command=command,
            kimi_root=root,
            json=False,
        )
    )


def run_claude_code_menu() -> int:
    print()
    print("Connect Claude Code")
    print("1. Status")
    print("2. Connect Claude Code")
    print("3. Verify")
    print("4. Disconnect")
    choice = input("> ").strip()
    command = {"1": "status", "2": "connect", "3": "verify", "4": "disconnect"}.get(choice)
    if command is None:
        print("Unknown selection.")
        return 1
    project = input("Claude Code project root (blank = current directory): ").strip().strip('"')
    protect_root = input("Protect U Back root visible to Claude Code (blank = launcher root): ").strip().strip('"')
    platform = input("Platform [auto/windows/posix] (blank = auto): ").strip().lower()
    python_bin = input("Python command visible to Claude Code (blank = auto-detect for platform): ").strip()
    return run_claude_code_connector(
        argparse.Namespace(
            claude_code_command=command,
            claude_project=project or ".",
            protect_root=protect_root or None,
            python_bin=python_bin or None,
            platform=platform or "auto",
            json=False,
        )
    )


def run_codex_menu() -> int:
    print()
    print("Connect Codex CLI")
    print("1. Status")
    print("2. Connect Codex CLI")
    print("3. Verify")
    print("4. Disconnect")
    choice = input("> ").strip()
    command = {"1": "status", "2": "connect", "3": "verify", "4": "disconnect"}.get(choice)
    if command is None:
        print("Unknown selection.")
        return 1
    project = input("Codex project root (blank = current directory): ").strip().strip('"')
    protect_root = input("Protect U Back root visible to Codex (blank = launcher root): ").strip().strip('"')
    python_bin = input("Python command visible to Codex (blank = python3): ").strip()
    return run_codex_connector(
        argparse.Namespace(
            codex_command=command,
            codex_project=project or ".",
            protect_root=protect_root or None,
            python_bin=python_bin or "python3",
            json=False,
        )
    )


def run_audit(
    *,
    input_path: Path,
    output_path: Path | None = None,
    input_format: str = "auto",
    source_adapter: str = "launcher",
) -> int:
    if output_path is None:
        REPORTS_DIR.mkdir(exist_ok=True)
        output_path = REPORTS_DIR / f"{input_path.stem}.audit.report.json"
    input_path = resolve_input_path(input_path)

    command = (
        "agent-audit",
        "--input",
        str(input_path),
        "--input-format",
        input_format,
        "--confirm-protect",
        "--source-adapter",
        source_adapter,
        "--output",
        str(output_path),
    )
    return_code = run_protect(command)
    if return_code == 0:
        print(f"Report: {output_path}")
    return return_code


def run_harness_connector(args: argparse.Namespace) -> int:
    from openharness_connector import (
        connect_openharness,
        disconnect_openharness,
        status_openharness,
        verify_openharness,
    )

    operations = {
        "status": lambda: status_openharness(args.openharness_root),
        "connect": lambda: connect_openharness(args.openharness_root, protect_root=CODE_ROOT),
        "disconnect": lambda: disconnect_openharness(args.openharness_root),
        "verify": lambda: verify_openharness(args.openharness_root),
    }
    try:
        result = operations[args.harness_command]()
    except Exception as exc:
        print(f"OpenHarness connector error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_connector_result(result)
    return 0


def run_openclaw_connector(args: argparse.Namespace) -> int:
    from openclaw_connector import (
        connect_openclaw,
        disconnect_openclaw,
        status_openclaw,
        verify_openclaw,
    )

    operations = {
        "status": lambda: status_openclaw(args.openclaw_root),
        "connect": lambda: connect_openclaw(args.openclaw_root, protect_root=CODE_ROOT),
        "disconnect": lambda: disconnect_openclaw(args.openclaw_root),
        "verify": lambda: verify_openclaw(args.openclaw_root),
    }
    try:
        result = operations[args.openclaw_command]()
    except Exception as exc:
        print(f"OpenClaw connector error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_connector_result(result)
    return 0


def run_kimi_connector(args: argparse.Namespace) -> int:
    from kimi_connector import (
        connect_kimi,
        disconnect_kimi,
        status_kimi,
        verify_kimi,
    )

    operations = {
        "status": lambda: status_kimi(args.kimi_root),
        "connect": lambda: connect_kimi(args.kimi_root, protect_root=CODE_ROOT),
        "disconnect": lambda: disconnect_kimi(args.kimi_root),
        "verify": lambda: verify_kimi(args.kimi_root),
    }
    try:
        result = operations[args.kimi_command]()
    except Exception as exc:
        print(f"Kimi connector error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_connector_result(result)
    return 0


def run_claude_code_connector(args: argparse.Namespace) -> int:
    from claude_code_connector import (
        connect_claude_code,
        disconnect_claude_code,
        status_claude_code,
        verify_claude_code,
    )

    platform = getattr(args, "platform", "auto")
    operations = {
        "status": lambda: status_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
            platform=platform,
        ),
        "connect": lambda: connect_claude_code(
            args.claude_project,
            protect_root=args.protect_root or CODE_ROOT,
            python_bin=args.python_bin,
            platform=platform,
        ),
        "disconnect": lambda: disconnect_claude_code(args.claude_project),
        "verify": lambda: verify_claude_code(
            args.claude_project,
            protect_root=args.protect_root or CODE_ROOT,
            python_bin=args.python_bin,
            platform=platform,
        ),
    }
    try:
        result = operations[args.claude_code_command]()
    except Exception as exc:
        print(f"Claude Code connector error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_connector_result(result)
    return 0


def run_codex_connector(args: argparse.Namespace) -> int:
    from codex_connector import (
        connect_codex,
        disconnect_codex,
        status_codex,
        verify_codex,
    )

    operations = {
        "status": lambda: status_codex(
            args.codex_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
        "connect": lambda: connect_codex(
            args.codex_project,
            protect_root=args.protect_root or CODE_ROOT,
            python_bin=args.python_bin,
        ),
        "disconnect": lambda: disconnect_codex(args.codex_project),
        "verify": lambda: verify_codex(
            args.codex_project,
            protect_root=args.protect_root or CODE_ROOT,
            python_bin=args.python_bin,
        ),
    }
    try:
        result = operations[args.codex_command]()
    except Exception as exc:
        print(f"Codex connector error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_connector_result(result)
    return 0


def print_connector_result(result: dict[str, object]) -> None:
    for key, value in result.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for child_key, child_value in value.items():
                print(f"  {child_key}: {child_value}")
        else:
            print(f"{key}: {value}")


def resolve_input_path(input_path: Path) -> Path:
    if input_path.is_absolute():
        return input_path

    cwd_candidate = Path.cwd() / input_path
    if cwd_candidate.exists():
        return cwd_candidate.resolve(strict=False)

    package_candidate = PACKAGE_ROOT / input_path
    if package_candidate.exists():
        return package_candidate.resolve(strict=False)

    test_candidate = TEST_DIR / input_path.name
    if test_candidate.exists():
        return test_candidate.resolve(strict=False)

    return (PACKAGE_ROOT / input_path).resolve(strict=False)


def protect_command(args: Sequence[str]) -> list[str]:
    return [
        sys.executable,
        str(CODE_ROOT / "protect_u_back.py"),
        "--project-root",
        str(PACKAGE_ROOT),
        *args,
    ]


def run_protect(args: Sequence[str]) -> int:
    return subprocess.run(protect_command(args), cwd=PACKAGE_ROOT, check=False).returncode


def run_local_script(script: Path, args: Sequence[str] = ()) -> int:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=PACKAGE_ROOT,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
