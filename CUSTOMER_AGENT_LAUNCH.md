# Customer Agent Launch Commands

After unpacking the release, the customer only needs to set two variables:

```bash
PUB=/path/to/ProtectUBack_early_access_1.2_local   # unpacked PUB release
WORK=/path/to/your/project                         # project to supervise; must be outside PUB
```

## Linux / Windows WSL2: Gate + Cage

Use this when `bubblewrap` (`bwrap`) is available and the agent can run as a native Linux process:

```bash
python3 "$PUB/project/pub_agent_launcher.py" cc --cage \
  --project-root "$WORK" \
  --protect-root "$PUB/project"
```

This performs the full launch flow:

```text
connect (POSIX hook) -> gate -> verify -> start claude inside the bwrap cage
```

## macOS Or Hosts Without bwrap: Gate Only

Use the same command without `--cage`:

```bash
python3 "$PUB/project/pub_agent_launcher.py" cc \
  --project-root "$WORK" \
  --protect-root "$PUB/project"
```

This still connects the POSIX hook, runs the gate, verifies the setup, and starts `claude`, but it does not provide the bwrap OS cage. macOS does not have bwrap; OS-level isolation for macOS would need a separate `sandbox-exec` path.

## Platform Matrix

| Platform | Command | Prerequisites |
| --- | --- | --- |
| Linux | Use `--cage` | `bwrap`, unprivileged user namespaces, native Linux `claude` |
| Windows | Run the `--cage` command inside WSL2 | Same as Linux; install `claude` in WSL with `npm i -g`, and verify it is not a Windows `.exe` |
| macOS | Omit `--cage` | Gate-only mode; no bwrap cage |

## Fail-Closed Guarantee

If `--cage` is requested but the host cannot build the cage, the launcher stops instead of silently running uncaged.

Typical reasons include:

- non-Linux host
- missing `bwrap`
- disabled unprivileged user namespaces
- `claude` resolving to a Windows `.exe` through WSL interop

The expected operator-facing message is:

```text
--cage requested but no cage on this host (...). Drop --cage to run gate-only.
```

## Important WSL Check

Inside WSL, `claude` must be the native Linux version. A Windows `.exe` reached through WSL interop cannot be confined by bwrap.

Check it before launching:

```bash
file "$(which claude)"
```

The result should identify a Linux executable or script path, not a Windows PE `.exe`.
