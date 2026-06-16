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

Scope (v0): inline-code interpreter invocations + the POSIX `eval` builtin. The
long tail -- renamed/custom interpreters, dropped-then-run binaries, awk/sed
programs, stdin-piped code without a flag -- is NOT fully covered here and is
left to declaration in the threat model. See `residual_tail` note below.
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
        base = _norm(tok)
        if _ASSIGNMENT.match(tok):
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
        base, rest = _command_word(segment)
        if base is None:
            continue

        # POSIX `eval` builtin: executes a string assembled at runtime.
        if base == "eval":
            return True, ("interpreter:eval", "code_flag:builtin")

        # `deno eval ...`
        if base == "deno" and rest and _norm(rest[0]) == "eval":
            return True, ("interpreter:deno", "code_flag:eval")

        if base in _INTERP_FLAGS:
            flags = _INTERP_FLAGS[base]
            for tok in rest:
                if tok in flags or any(tok.startswith(flag) for flag in flags):
                    return True, (f"interpreter:{base}", f"code_flag:{tok}")
            if any(tok == "-" for tok in rest):  # code from stdin: `python -`
                return True, (f"interpreter:{base}", "code_flag:stdin(-)")

        if base in _SHELLS:
            for tok in rest:
                if tok == "-" or _SHELL_CODE_FLAG.match(tok):
                    return True, (f"interpreter:{base}", f"code_flag:{tok}")

        if base in _PWSH:
            for tok in rest:
                low = tok.lower()
                if any(low.startswith(prefix) for prefix in _PWSH_CODE_PREFIXES):
                    return True, (f"interpreter:{base}", f"code_flag:{low}")

    return False, ()


def opaque_marker(command_text: str) -> str | None:
    """Compact `interpreter:flag` marker for stamping a piece, or None."""
    matched, evidence = is_opaque_executor(command_text)
    if not matched:
        return None
    interp = next((e.split(":", 1)[1] for e in evidence if e.startswith("interpreter:")), "?")
    flag = next((e.split(":", 1)[1] for e in evidence if e.startswith("code_flag:")), "?")
    return f"{interp}:{flag}"
