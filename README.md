# Protect U Back

Protect U Back (PUB) is a local pre-I/O audit gate and PUB-OS-like supervisor for AI coding agents.

It is built from one simple rule:

```text
An agent action should leave evidence before it is allowed to touch the world.
```

PUB is not a prompt filter. It does not decide whether language sounds safe. It audits proposed tool use, filesystem movement, shell/process surfaces, and the observable physical state around an action.

PUB-OS is an agent operating boundary, not a replacement for Windows, Linux, an endpoint security product, or a kernel sandbox. Its job is narrower: connected agents enter through PUB-controlled entrypoints, and their declared tool or shell movement is inspected before it reaches real side effects.

```text
Channel -> Envelope -> X-ray -> Admission -> Tool -> Autopsy -> OT
```

This README has three parts:

1. What PUB is in the 1.1 local release.
2. How to reproduce the credential-egress verification experiment.
3. How to launch an agent through PUB from bash.

---

# Part 1 - PUB 1.1 Overview

## What PUB Does

PUB sits between an agent/tool runner and real side effects.

It normalizes a proposed action into an auditable envelope, observes the protected surface before and after the motion, and sends unclear or changed movement to `HOLD` for later judgment.

The first goal is not to name every attack perfectly. The first goal is stricter:

```text
If a protected file, process surface, or boundary moved, changed, vanished, appeared, or became unobservable,
PUB must produce evidence and stop silent passage.
```

## From v0.14 To v1.1

v0.14 froze the first complete architecture slice:

- pre-tool admission before real I/O
- X-ray transport around the action window
- sphere-prison boundary model
- field coordinates for process movement
- enter/exit snapshots of protected pieces
- `P = A + S - T` process projection
- `Omega_process = O * (P_exit diff P_enter diff T_auth)` residual calculation
- `SceneSeed` for scene/environment parameters
- `SceneReplayGuard` for protecting untouched surroundings during replay
- Claude Code hook connector: `PreToolUse` and `PostToolUse`
- local release packaging for offline review

v1.0 kept that boundary and added connected-agent supervision and Windows observation work:

- Claude Code hooks match all tools with `matcher: "*"`, not only a small Bash/Edit set
- unmodelled Claude Code tools route to explicit review instead of silent allow
- hardened `safe_resolve()` path handling turns malformed or hostile paths into blind spots instead of auditor crashes
- NTFS reparse points are named as `reparse_point` and carry `reparse_tag`
- NTFS alternate data streams are separated by metadata-vector evidence instead of collapsing onto the host `file_id`
- `temporal_continuity.py` adds sequence memory for read-then-egress and read-then-opaque-exec patterns across separate, observed tool calls
- PUB-OS introduces supervised agent entry instead of trusting an already-running desktop session
- Claude Code (`cc`) is covered through all-tool hooks, fail-closed ledger witness, and explicit review for unmodelled tools
- Codex CLI (`cd`) is covered through a PUB shell guard entrypoint that records shell pre/post evidence and blocks dangerous side effects before execution

v1.1 keeps the same audit boundary and makes the local operator path clearer:

- the release carries a customer-facing agent launcher
- `cc --cage` can start Claude Code inside a Linux/WSL2 `bwrap` cage when the host supports it
- gate-only mode remains available for macOS or hosts without `bwrap`
- `--cage` is fail-closed: if the cage cannot be built, the launcher stops instead of silently running uncaged
- the package includes additional daily-workflow, redteam, and evidence reports under `test/` and `reports/`
- Codex and Claude Code remain supervised only when they enter through PUB-owned entrypoints

The important boundary is unchanged:

```text
X-ray observes.
PUB audits.
OT decides.
No single layer owns execution authority.
```

## X-ray

X-ray is the isolated witness layer.

It is modeled as a closed sphere-prison filled with a potential field. A command or tool call enters as an envelope `R(m)`. X-ray takes an enter snapshot, watches the bound pieces, takes an exit snapshot, and reports residual movement.

X-ray does not grant permission. It does not execute tools. It does not kill processes. It only returns suspicion, witnesses, field pressure, continuity state, and `HOLD` signals.

## Process Equation

PUB maps tool movement into a process form:

```text
P = A + S - T

A = agency / source pushing the action
S = surface / contact mechanism
T = time window / execution scale
```

Then X-ray compares the process before and after the action:

```text
Omega_process = O * (P_exit typed-diff P_enter typed-diff T_auth)
```

`typed-diff` is a typed difference, not arithmetic subtraction.

`O` is the observation operator. If the scene is complete, PUB computes residuals. If observation is partial, it computes the visible part and reports blind spots. If the state is unknown, unobserved, or scene-contaminated, PUB does not fake continuity proof. It holds.

Core rule:

```text
Observed mutation can be under-classified.
Unobserved mutation cannot be silently accepted.
```

## Scene Seed

`SceneSeed` is not evidence and not an autopsy report.

It describes the scene around the action: OS/filesystem behavior, boundary root, permission mode, path rules, clock semantics, hook configuration, and untouched surrounding paths.

`SceneReplayGuard` protects those surroundings. It scans before replay and after replay. If an untouched surrounding object changes, disappears, appears, or cannot be fully hashed, the scene becomes contaminated or unobserved and must `HOLD`.

Seed keeps the crime scene stable. X-ray observes the body. Autopsy explains the damage.

## Why This Is Not A Prompt Filter

Prompt filters inspect text.

PUB inspects action movement.

A malicious agent can hide intent in wording, aliases, shell syntax, hardlinks, alternate data streams, junctions, timing, or filesystem metadata. PUB is designed to ask a harder question:

```text
Did the proposed process touch or alter the protected physical state?
```

If yes, it must leave a receipt.

## Current Limits

PUB 1.1 is still a local pre-I/O audit gate and supervised agent boundary. It is not yet a host-wide syscall monitor.

Current boundaries:

- PUB supervises connected agent entrypoints it owns.
- Claude Code enters through PUB hooks and, on Linux/WSL2, can be launched inside a `bwrap` cage.
- Codex CLI enters through the PUB shell guard path.
- Already-running desktop agents are outside this boundary unless they were started through a PUB-controlled connector.
- Effects hidden entirely inside an opaque child process remain admissible only when they are visible through the supervised tool/shell surface or the cage boundary. Otherwise they must `HOLD` or be caught later by stronger host sensors.
- Downloaded or externally produced files remain suspect inputs and must be admitted again before trust.

These are not reasons to weaken the boundary.

```text
No update may silently weaken the audit boundary.
```

---

# Part 2 - Quick Credential-Egress Verification

This section explains how to reproduce the credential-egress verification experiment.

The experiment uses fake API keys only. No real account is touched. The point is to show the difference between:

- PUB's pre-I/O judgment before the request runs
- the real network/server response if the gate is deliberately bypassed for the experiment

## TL;DR

A fake GitHub token is sent to GitHub's API endpoint.

Expected result:

```text
HTTP 401 Bad credentials
```

If the response includes `x-github-request-id`, the request reached GitHub's servers and was processed by GitHub. The fake token was rejected server-side.

The important claim is not that the fake key works. It does not. The claim is that a real egress attempt can be observed, blocked by PUB, and independently reproduced.

## Read The Published Result

Open:

```text
runs/blast-p2-github/autopsy.md
runs/blast-p2-github/summary.json
```

In `summary.json`, look for these fields:

```json
"gate_dryrun": { "decision": "KILL", "reason_code": "CRITICAL_KILL" }
"bypassed_gate": true
"real_egress": { "http_status": 401, "http_reason": "Unauthorized" }
"github_request_id": "..."
```

Meaning:

- PUB said the action should be killed before execution.
- The experiment deliberately bypassed the gate to observe reality.
- GitHub returned a real `401 Unauthorized` response.
- A GitHub request ID proves the request reached GitHub-side infrastructure.

## Reproduce The Headline With curl

You do not need PUB to reproduce GitHub's server-side behavior. You only need `curl`.

Mac/Linux/WSL/Git Bash:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer ghp_THIS_IS_A_FAKE_TOKEN_xxxxxxxxxxxxxxxxxx" \
  -H "User-Agent: blast-probe" \
  https://api.github.com/user
```

Expected output:

```text
HTTP 401
```

Now print the status, request ID, and message:

```bash
curl -s -D - \
  -H "Authorization: Bearer ghp_THIS_IS_A_FAKE_TOKEN_xxxxxxxxxxxxxxxxxx" \
  -H "User-Agent: blast-probe" \
  https://api.github.com/user | grep -iE "HTTP/|x-github-request-id|message"
```

Expected output should look like:

```text
HTTP/2 401
x-github-request-id: 813F:0C22:27BDD6C:2D18EBE:6A2E55A2
  "message": "Bad credentials",
```

The request ID changes every run. That is normal. The invariant is:

```text
HTTP 401 + a GitHub request ID exists
```

## Verify Published Files Were Not Tampered With

Each run folder ships a `SHA256SUMS.txt` file. It records the SHA-256 of every other file in that folder at the time the evidence was generated.

Example:

```bash
cd runs/blast-p2-github
```

Linux:

```bash
sha256sum -c SHA256SUMS.txt
```

macOS:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

Expected output:

```text
autopsy.json: OK
autopsy.md: OK
seed.json: OK
summary.json: OK
```

If any line says `FAILED`, the file was changed after sealing.

## What This Proves

Proves:

- A fake credential egress attempt can reach a real server-side auth surface.
- GitHub correctly rejects the fake credential with `401 Bad credentials`.
- PUB's dry-run gate classified the same movement as `KILL` before execution.
- The evidence files can be checked with ordinary SHA-256 tools.

Does not prove:

- Anything about a real or valid account.
- That GitHub is insecure.
- That PUB is a kernel-level network monitor.
- That every opaque child process is fully visible without stronger host sensors.

The experiment is useful because it separates gate judgment, controlled bypass, real network response, and sealed evidence.

---

# Part 3 - Launching PUB From bash

After unpacking the release, set two variables:

```bash
PUB=/path/to/ProtectUBack_early_access_1.1_local   # unpacked PUB release
WORK=/path/to/your/project                         # project to supervise; must be outside PUB
```

`WORK` must be outside `PUB`. Do not run the agent with the protected PUB source tree as the writable project.

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

Expected operator-facing message:

```text
--cage requested but no cage on this host (...). Drop --cage to run gate-only.
```

## Important WSL Check

Inside WSL, `claude` must be the native Linux version. A Windows `.exe` reached through WSL interop cannot be confined by bwrap.

Check before launching:

```bash
file "$(which claude)"
```

The result should identify a Linux executable or script path, not a Windows PE `.exe`.

## Minimal Release Audit Command

From a local release package, you can still run a direct audit case:

```bash
python3 "$PUB/project/protect_launcher.py" audit "$PUB/test/sandbox_gateway_cases.json"
```

This is a quick package sanity check. It is separate from launching a supervised agent.

## Review Targets

If you are reviewing PUB, attack these boundaries:

1. Can PUB reliably sit before agent tool use without becoming the executor?
2. Are X-ray enter/exit observations enough to prove protected movement?
3. Is `HASH_MUTATED -> HOLD` a defensible first verdict?
4. Is `SceneSeed` cleanly separated from evidence and autopsy output?
5. Can redteam cases create silent escape rather than only under-classification?
6. Does any layer accidentally claim execution authority?
7. Does an agent ever get to self-report containment instead of entering through PUB-owned launch paths?

Good reviews should include a reproducible case, not only an opinion.

## One-Sentence Summary

Protect U Back is a local pre-I/O audit gate and PUB-OS-like supervisor for AI agents: it passes safe proposals, holds ambiguous proposals, and kills dangerous side effects with an autopsy trail before tools execute.

## Personal Preference

Protect your back.
