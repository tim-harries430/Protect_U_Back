"""Decidable, surface-only recognizer for opaque (Turing-complete) payloads.

Rice's theorem: the side effects of an arbitrary interpreter invocation are
*undecidable* from its text. This module does NOT attempt that. It decides only
the *decidable* meta-question --

    "Is this command an inline-code interpreter invocation, whose effects are
     therefore unmodellable from the command surface?"

-- so the gate can mark such a payload UNKNOWN instead of falsely certifying it
CLEAR. The seam this closes: `python -c "open('x','w').write(...)"` parses to no
write token and no extractable target path, so every lexical layer infers
READ_ONLY and the X-ray observes nothing (witness_count=0) while a real write
happens. We cannot predict the write (Rice). We CAN decide, on the surface, that
the command is the kind whose write we cannot predict -- and refuse to call it
clean.

Covenant: this reads ONLY the command surface (argv shape). It never inspects
file contents, never traces execution. It recognizes that the box is sealed; it
never opens the box.

Scope (v1): inline-code interpreter invocations + the POSIX `eval` builtin (v0),
PLUS interpreters/shells executing a SCRIPT FILE or `-m` module (`python
build.py`, `bash deploy.sh`) and code-running package managers / task runners
(`npm run`, `pip install`, `make`, `npx`). Rationale: the axis is "effect
undecidable from the command surface (Rice)", and a disk referent is exactly as
undecidable as inline code -- hashing `build.py` proves its bytes, never its
effect. So a referent is NOT a reason to call the box modellable; it only lets a
later autopsy hash it too. The long tail -- renamed/custom interpreters,
dropped-then-run binaries, awk/sed programs -- is still NOT fully covered and is
left to declaration in the threat model.

Scope (v2): the recognizer is now FAIL-CLOSED. Recognizing "is this code
execution?" by an allowlist of known interpreter NAMES is bypassable by any name
the attacker chose -- a versioned interpreter (`python3.11`), another interpreter
(`awk`), a local file (`./payload`), `source`/`.`, or `| bash`. So the default is
inverted: any command-position word NOT in a small set of modellable coreutils
(`_MODELLABLE_VERBS`) is opaque. Unknown verb -> unmodellable -> HOLD, which is
pub's default-deny-on-missing-evidence principle instead of contradicting it.
This trades friction (uncommon-but-benign tools now HOLD) for closing the whole
name-evasion bypass class. The allowlist is the part to tune, not the default.

This is a DECODER: it only widens what the pub core can SEE as unmodellable. It
never decides hold/kill and never opens the box.
"""

from __future__ import annotations

import re
import shlex

# shell control operators that end one command and begin another. An interpreter
# only counts when it stands in COMMAND position (segment start, after wrappers),
# never when it is merely an argument to something else (`echo python -c ...`).
_OPERATORS: frozenset[str] = frozenset(
    {"|", "||", "&&", ";", "&", "(", ")", "{", "}", "|&", "\n"}
)

# wrappers transparently pass control to the next command word.
_WRAPPERS: frozenset[str] = frozenset(
    {
        "env", "command", "builtin", "exec", "sudo", "doas",
        "nice", "ionice", "nohup", "setsid", "stdbuf", "time",
        "timeout", "xargs", "then", "do", "else",
    }
)
# wrappers that consume one bare VALUE token before the command (timeout 5 ...).
_WRAPPER_VALUE: frozenset[str] = frozenset({"timeout", "nice", "ionice", "stdbuf"})

_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")

_RECON_ENV_KEYS: frozenset[str] = frozenset(
    {
        "tz",
        "timezone",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "proxy",
    }
)
_RECON_HOST_TOKENS: tuple[str, ...] = (
    "ifconfig.me",
    "icanhazip",
    "ipify",
    "checkip",
    "ipinfo",
)

# interpreter basename -> inline-code flags that mean "arbitrary code follows in
# the argument vector". A flag matches a token if the token equals it or starts
# with it (covers glued forms like `python -cprint(1)`).
_INTERP_FLAGS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "python2": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "py": frozenset({"-c"}),
    "pypy": frozenset({"-c"}),
    "pypy3": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "php": frozenset({"-r"}),
    "rscript": frozenset({"-e"}),
}

# shells take a clustered short flag whose cluster contains `c` (e.g. -c, -lc, -ic).
_SHELLS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "busybox"}
)
_SHELL_CODE_FLAG = re.compile(r"^-[a-z]*c$")

# powershell family inline-code / encoded-command flags (prefix match, lowercased).
_PWSH: frozenset[str] = frozenset({"powershell", "pwsh"})
_PWSH_CODE_PREFIXES: tuple[str, ...] = ("-c", "-command", "-e", "-ec", "-enc", "-encodedcommand")

# (v1) Package managers / task runners. Decoder table only: each maps to the
# subcommands that EXECUTE project-defined, surface-invisible code. A query
# subcommand (`pip list`, `npm outdated`) is not here, so it stays modellable.
# An empty allow-set means the tool runs a recipe even with no subcommand
# (`make`, `gradle`) -- always opaque in command position.
_RUNNERS: dict[str, frozenset[str]] = {
    "git": frozenset({"add", "commit", "push", "pull", "fetch", "merge", "rebase", "cherry-pick", "stash", "apply", "am", "checkout", "switch"}),
    "npm": frozenset({"run", "run-script", "exec", "install", "i", "ci", "start", "test", "build", "rebuild"}),
    "pnpm": frozenset({"run", "exec", "dlx", "install", "i", "start", "test", "build"}),
    "yarn": frozenset({"run", "exec", "dlx", "install", "start", "test", "build"}),
    "pip": frozenset({"install"}),
    "pip3": frozenset({"install"}),
    "pipx": frozenset({"install", "run"}),
    "uv": frozenset({"run", "pip"}),
    "poetry": frozenset({"run", "install", "build"}),
    "cargo": frozenset({"run", "build", "test", "install", "bench"}),
    "go": frozenset({"run", "build", "test", "generate", "install"}),
    "bundle": frozenset({"exec", "install"}),
    "jupyter": frozenset({"nbconvert", "execute", "run"}),
    "deno": frozenset({"run"}),  # `deno eval` already matched above
    "bun": frozenset({"run"}),
    "make": frozenset(),
    "gradle": frozenset(),
    "gradlew": frozenset(),
    "mvn": frozenset(),
    "rake": frozenset(),
    "docker": frozenset({"build", "run", "exec", "compose", "push", "pull", "login", "tag", "rm", "rmi", "system", "volume", "network", "container", "image"}),
    "docker-compose": frozenset(),
    "kubectl": frozenset({"get", "describe", "apply", "create", "delete", "patch", "replace", "edit", "scale", "rollout", "exec", "cp", "logs", "config", "port-forward"}),
}

# Tools that execute fetched/arbitrary code in any invocation that has an operand.
_ALWAYS_RUNNERS: frozenset[str] = frozenset({"npx", "bunx", "tsx", "ts-node"})

# (v2) Coreutils / verbs whose surface effect IS decidable from argv -- the ONLY
# command-position words the recognizer treats as modellable. EVERYTHING else
# (interpreters python*/perl*/awk, shells, source/dot, local-file execution
# ./payload, unknown binaries) is opaque by default. Deliberately EXCLUDES every
# interpreter, every shell, source/eval/exec and net tools (nc/socat) so a name
# the attacker chose cannot wave itself through. This is a declared allowlist of
# the KNOWN-SAFE, not a denylist of the known-dangerous -- tune per environment.
_MODELLABLE_VERBS: frozenset[str] = frozenset(
    {
        # read / inspect (READ)
        "cat", "head", "tail", "less", "more", "bat", "nl", "tac", "rev", "fold",
        "grep", "egrep", "fgrep", "rg", "ag", "ack", "look",
        "ls", "dir", "find", "tree", "stat", "file", "readlink", "realpath",
        "wc", "sort", "uniq", "cut", "tr", "comm", "join", "paste", "column",
        "od", "xxd", "hexdump", "strings",
        "echo", "printf", "seq", "yes", "pwd", "basename", "dirname",
        "date", "cal", "which", "whereis", "type", "hostname", "whoami", "id",
        "uname", "printenv", "du", "df", "diff", "cmp",
        "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum", "jq", "yq",
        # write / modify (modeled)
        "touch", "mkdir", "tee", "cp", "copy", "mv", "move", "truncate",
        "mktemp",
        # delete (modeled; own KILL/HOLD path)
        "rm", "rmdir", "unlink",
        # in-place text edit (modeled as WRITE)
        "sed",
        # version control (subcommands modeled)
        "git",
        # network (modeled as NETWORK; own path)
        "curl", "wget",
        # privilege (modeled)
        "chmod", "chown",
        # NOTE: install / shred / ln / chgrp are deliberately EXCLUDED. They are
        # surface-equivalent to modeled verbs (install~cp write, shred~rm delete,
        # ln~write, chgrp~chown privilege) but NO effect layer (codex_bash_guard
        # verb branch, ot_gate, capability) models them -> they would be judged
        # READ, silently allowed, and slip the self-protection wall (red-team B1).
        # Absent an effect model they fail-closed to opaque -> HOLD. Re-add ONLY
        # together with an effect model.
        # PowerShell cmdlets whose effect is decidable -- MUST mirror the modellable
        # surface in parallel_audit.MODELLABLE_COMMAND_WORDS, or the v2 fail-closed
        # default over-blocks plain PowerShell I/O on Windows. (`:` stays excluded:
        # `: > file` is a truncate-via-redirect evasion that should read as opaque.)
        "get-content", "set-content", "add-content", "clear-content",
        "remove-item", "copy-item", "move-item", "new-item", "out-file",
        "select-string", "invoke-webrequest", "iwr", "icacls",
        # benign builtins / no-ops
        "true", "false", "test", "[", "cd", "export", "set", "unset", "read",
        "exit", "return", "alias", "unalias", "history", "clear", "sleep",
        "wait", "umask", "ulimit", "pushd", "popd", "dirs",
    }
)
_DIRECT_SCRIPT_EXTS: frozenset[str] = frozenset(
    {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".py", ".js", ".mjs", ".cjs", ".ts"}
)


def _norm(token: str) -> str:
    """Basename, lowercased, .exe stripped, surrounding quotes removed."""
    tok = token.strip().strip("'\"")
    tok = tok.replace("\\", "/").rsplit("/", 1)[-1]
    tok = tok.lower()
    if tok.endswith(".exe"):
        tok = tok[:-4]
    return tok


def _tokens(command_text: str) -> list[str]:
    try:
        return shlex.split(command_text, posix=True)
    except ValueError:
        return command_text.split()


def _segments(tokens: list[str]) -> list[list[str]]:
    """Split a token stream into command segments on shell control operators."""
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _OPERATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _command_word(segment: list[str]) -> tuple[str | None, list[str]]:
    """Resolve the command word of a segment, skipping assignments and wrappers.

    Returns (normalized_command_word, tokens_after_it). The command word is the
    first token that is neither an env-assignment nor a transparent wrapper --
    i.e. the thing actually being executed.
    """
    i, n = 0, len(segment)
    while i < n:
        tok = segment[i]
        # Strip subshell / group punctuation glued to the command word: `(cd`, `{cmd`.
        base = _norm(tok).lstrip("({")
        if not base:
            i += 1
            continue
        if _ASSIGNMENT.match(tok):
            i += 1
            continue
        if base == "cmd":
            # Windows cmd.exe `/c`|`/k` <inner>: the inner command is the real
            # executor. Skip cmd and its slash/dash options and judge the inner,
            # so `cmd /c dir` reads through to `dir` (modellable) while
            # `cmd /c python3.11 -c ...` reads through to the opaque interpreter.
            i += 1
            while i < n and segment[i].startswith(("/", "-")):
                i += 1
            continue
        if base in _WRAPPERS:
            i += 1
            while i < n and segment[i].startswith("-"):  # wrapper options
                i += 1
            if base in _WRAPPER_VALUE and i < n and not segment[i].startswith("-"):
                i += 1  # one consumed value (timeout 5, nice 10, ...)
            continue
        return base, segment[i + 1 :]
    return None, []


def _first_operand(rest: list[str]) -> str | None:
    """First non-option token after the command word: a script path, module, or
    subcommand. Lets us decide an interpreter is running a FILE (not just `-c`)
    or a runner is invoking a code subcommand. Pure surface read."""
    for tok in rest:
        if tok and not tok.startswith("-"):
            return tok
    return None


def is_opaque_executor(command_text: str) -> tuple[bool, tuple[str, ...]]:
    """Return (matched, evidence). Decidable; surface-only.

    `matched` is True when a command-position word invokes an interpreter with
    inline code (or is the POSIX `eval` builtin). The command-position rule means
    an interpreter named only as an argument -- `echo python -c x`, `git commit
    -m 'python -c'` -- does NOT match. `evidence` names the interpreter and flag
    so the blindspot signal is auditable without echoing the payload.
    """
    if not command_text or not command_text.strip():
        return False, ()

    for segment in _segments(_tokens(command_text)):
        if len(segment) == 1 and _norm(segment[0]) == "env":
            return True, ("executor:env", "code_flag:runtime-recon")
        base, rest = _command_word(segment)
        if base is None:
            continue

        if any(base.endswith(ext) for ext in _DIRECT_SCRIPT_EXTS):
            return True, (f"interpreter:{base}", "code_flag:script")

        # POSIX `eval` builtin: executes a string assembled at runtime.
        if base == "eval":
            return True, ("interpreter:eval", "code_flag:builtin")

        # `deno eval ...`
        if base == "deno" and rest and _norm(rest[0]) == "eval":
            return True, ("interpreter:deno", "code_flag:eval")

        if _is_runtime_recon_probe(base, rest):
            return True, (f"executor:{base}", "code_flag:runtime-recon")

        if base in _INTERP_FLAGS:
            flags = _INTERP_FLAGS[base]
            for tok in rest:
                if tok in flags or any(tok.startswith(flag) for flag in flags):
                    return True, (f"interpreter:{base}", f"code_flag:{tok}")
            if any(tok == "-" for tok in rest):  # code from stdin: `python -`
                return True, (f"interpreter:{base}", "code_flag:stdin(-)")
            if not rest:  # bare interpreter in command position: a REPL, or it
                # executes code piped to its stdin (`cat x.py | python3`). The
                # effect is undecidable from argv -- same axis as `-c`. (A known
                # interpreter is exempt from the fail-closed default below because
                # it is in _INTERP_FLAGS, so the bare form must be caught here.)
                return True, (f"interpreter:{base}", "code_flag:stdin")
            # (v1) not inline, but executing a -m module or a script FILE. The
            # referent is hashable, its EFFECT is still undecidable from the
            # surface (Rice) -- same axis as -c. `python build.py`, `node app.js`.
            # A bare `python --version` (no operand, no -m) stays modellable.
            if "-m" in rest or "--module" in rest:
                return True, (f"interpreter:{base}", "code_flag:-m")
            if _first_operand(rest) is not None:
                return True, (f"interpreter:{base}", "code_flag:script")

        if base in _SHELLS:
            for tok in rest:
                if tok == "-" or _SHELL_CODE_FLAG.match(tok):
                    return True, (f"interpreter:{base}", f"code_flag:{tok}")
            # (v1) shell executing a script FILE: `bash deploy.sh`, `sh setup`
            if _first_operand(rest) is not None:
                return True, (f"interpreter:{base}", "code_flag:script")

        if base in _PWSH:
            for tok in rest:
                low = tok.lower()
                if any(low.startswith(prefix) for prefix in _PWSH_CODE_PREFIXES):
                    return True, (f"interpreter:{base}", f"code_flag:{low}")
            # (v1) powershell running a .ps1 script file
            if _first_operand(rest) is not None:
                return True, (f"interpreter:{base}", "code_flag:script")

        # (v1) package managers / task runners whose subcommand executes
        # project-defined, surface-invisible code.
        if base in _ALWAYS_RUNNERS and _first_operand(rest) is not None:
            return True, (f"runner:{base}", "subcommand:exec")
        if base in _RUNNERS:
            allowed = _RUNNERS[base]
            sub = _first_operand(rest)
            if not allowed:  # runs a recipe even with no subcommand (make, gradle)
                return True, (f"runner:{base}", f"subcommand:{_norm(sub) if sub else '<default>'}")
            if sub is not None and _norm(sub) in allowed:
                return True, (f"runner:{base}", f"subcommand:{_norm(sub)}")

        # (v2) Fail-closed default: a command-position word whose effect we cannot
        # model is opaque -- the beast must SEE it (HOLD), never wave it through as
        # a silent READ. Flips the default from "unknown name -> PASS"
        # (default-ALLOW: the bypass class python3.11 / awk / ./payload / source /
        # `| bash`) to "unknown -> unmodellable -> HOLD" (default-DENY, pub's
        # actual principle). Modellable coreutils stay clear; so do the benign
        # forms of KNOWN tool families (`python --version`, `pip list`, `npm
        # outdated`) -- they already fell through their own blocks above, so we
        # exempt the family rather than re-hold them. Shells are NOT exempt: a bare
        # or piped shell (`cat x | bash`) has no surface code and is opaque.
        if (
            base not in _MODELLABLE_VERBS
            and base not in _INTERP_FLAGS
            and base not in _RUNNERS
            and base not in _ALWAYS_RUNNERS
            and base not in _PWSH
        ):
            return True, (f"executor:{base}", "code_flag:unmodellable")

    return False, ()


def _is_runtime_recon_probe(base: str, rest: list[str]) -> bool:
    lowered = tuple(str(token).strip().strip("'\"").lower() for token in rest)
    if base == "date":
        return any("%z" in token or "%Z" in token for token in rest)
    if base in {"printenv", "set"}:
        return not lowered or any(_norm(token) in _RECON_ENV_KEYS for token in lowered)
    if base == "hostname":
        return any(token.lower() == "-i" for token in rest)
    if base in {"curl", "wget", "invoke-webrequest", "invoke-restmethod", "iwr", "irm"}:
        return any(
            probe in token
            for token in lowered
            for probe in _RECON_HOST_TOKENS
        )
    return False


def opaque_marker(command_text: str) -> str | None:
    """Compact `interpreter:flag` marker for stamping a piece, or None."""
    matched, evidence = is_opaque_executor(command_text)
    if not matched:
        return None
    interp = next(
        (e.split(":", 1)[1] for e in evidence if e.startswith(("interpreter:", "runner:", "executor:"))),
        "?",
    )
    flag = next(
        (e.split(":", 1)[1] for e in evidence if e.startswith(("code_flag:", "subcommand:"))),
        "?",
    )
    return f"{interp}:{flag}"
