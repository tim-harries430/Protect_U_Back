# Protect U Back

Protect U Back (PUB) is a local pre-tool audit kernel for AI agents.

It is built from one simple rule: an agent action should leave evidence before it is allowed to touch the world.

PUB is not a prompt filter. It does not try to decide whether language sounds safe. It audits proposed tool use, filesystem movement, and the physical state around an action.

```text
Channel -> Envelope -> X-ray -> Admission -> Tool -> Autopsy -> OT
```

## Current release and paper evidence

- Latest offline package: [`ProtectUBack_early_access_1.3_local.zip`](releases/ProtectUBack_early_access_1.3_local.zip)
- ZIP SHA-256: `6186cb4f643707aaa99a91607ad0a20b788c72e6d2f6cfe93fbbbed69bb12329`
- Feature wiring levels: [`FEATURE_REACHABILITY.json`](FEATURE_REACHABILITY.json)
- Paper experiment map: [`PAPER_EXPERIMENTS.md`](PAPER_EXPERIMENTS.md)
- Frozen reproducibility package: [`paper_artifact/paper-jisa-v1`](paper_artifact/paper-jisa-v1/)

The paper artifact includes the complete red-team, daily-probe, 49,806-row
soak, baseline/ablation, scoring and figure-reproduction materials. Product
1.3 is published separately so later fixes are not substituted into the frozen
paper results.

## What It Does

PUB sits between an agent/tool runner and real side effects.

It normalizes an action proposal into an auditable envelope, observes the protected surface before and after the motion, and sends unclear or changed movement to HOLD for later judgment.

The first goal is not to prove every attack name. The first goal is stricter:

```text
If a protected file or process surface moved, changed, vanished, appeared, or became unobservable,
PUB must produce evidence and stop silent passage.
```

## The v1.0 Local Baseline

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

v1.0 keeps that boundary and adds the missing connection and Windows
observation work:

- Claude Code hooks now match all tools with `*`, not only a small Bash/Edit
  set
- unmodelled Claude Code tools are routed to explicit review instead of silent
  allow
- legacy `pub_gate_switch.json` disarm requests are ignored; blocking stays armed
- hardened `safe_resolve()` path handling turns malformed or hostile paths into
  blind spots instead of auditor crashes
- NTFS reparse points are named as `reparse_point` and carry `reparse_tag`
- NTFS alternate data streams are separated by metadata-vector evidence instead
  of collapsing onto the host `file_id`
- `temporal_continuity.py` adds a sequence-memory layer for read-then-egress and
  read-then-opaque-exec patterns **across separate, observed tool calls**. A
  single opaque subprocess that performs both the read and the egress internally
  is not caught — see "Current Limits"

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

X-ray does not grant permission. It does not execute tools. It does not kill processes. It only returns suspicion, witnesses, field pressure, continuity state, and HOLD signals.

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

This is the core rule:

```text
Observed mutation can be under-classified.
Unobserved mutation cannot be silently accepted.
```

## Scene Seed

`SceneSeed` is not evidence and not an autopsy report.

It describes the scene around the action: OS/filesystem behavior, boundary root, permission mode, path rules, clock semantics, hook configuration, and untouched surrounding paths.

`SceneReplayGuard` protects those surroundings. It scans before replay and after replay. If an untouched surrounding object changes, disappears, appears, or cannot be fully hashed, the scene becomes contaminated or unobserved and must HOLD.

Seed keeps the crime scene stable. X-ray observes the body. Autopsy explains the damage.

## Why This Is Not A Prompt Filter

Prompt filters inspect text.

PUB inspects action movement.

A malicious agent can hide intent in wording, aliases, shell syntax, hardlinks, alternate data streams, junctions, timing, or filesystem metadata. PUB is designed to ask a harder question:

```text
Did the proposed process touch or alter the protected physical state?
```

If yes, it must leave a receipt.

## Current Verification

Current v1.0 local checks include:

```text
Release / connector / hook / temporal / Windows checks: 46 passed
Temporal continuity + Windows hardcore checks:          17 passed
Windows reparse / ADS evidence cases:                   4 / 4 intercepted
```

The light regression covers:

- `SceneSeed`
- `SceneReplayGuard`
- access field coordinates
- T-axis time grid
- `Omega_process`
- transition X-ray
- sphere prison / field / transport
- Claude Code hooks and connector
- Claude Code all-tool hook coverage and unknown-tool review
- temporal continuity sequence-memory tests
- NTFS junction / reparse point observation
- NTFS alternate data stream observation
- OpenClaw / Kimi / OpenHarness connector guards
- local release packaging
- Windows redteam cases

External hardcore redteam is treated as pressure testing, not as the release gate. The current useful distinction is:

```text
silent escape          -> unacceptable
caught but unnamed     -> autopsy precision gap
environment blocked    -> replay/host capability issue
```

## Quickstart

From a local release package:

```powershell
cd ProtectUBack_early_access_1.3_local
python project\protect_launcher.py audit test\sandbox_gateway_cases.json
```

From the source tree:

```powershell
cd C:\dev\sp
python -m pytest test_scene_seed.py test_scene_replay_guard.py test_access_field.py test_access_time_grid.py test_access_process_equation.py -q
```

Build a local review package:

```powershell
cd C:\dev\sp
python build_local_release.py
```

## Claude Code Hook

PUB can connect to Claude Code through local hooks:

```text
PreToolUse  -> pretool_admission.py
PostToolUse -> posttool_autopsy.py
```

The hook layer blocks before Claude's own permission ask when PUB has enough reason to hold. After allowed tool execution, posttool autopsy closes the X-ray window and writes evidence.

The connector is local and reversible. It modifies Claude Code project hook settings; it does not require a cloud service.

In v1.0 the connector uses `matcher: "*"` so every Claude Code tool enters the
hook. Tools PUB can model are audited directly. Tools it cannot model are held
for explicit review with `UNKNOWN_CAPABILITY` rather than being silently allowed.

`pub_gate_switch.json` is now legacy compatibility only. A stale or requested
off state is recorded as ignored; it cannot stop blocking, escalation, posttool
autopsy, or fail-closed behavior.

## Windows Evidence

v1.0 adds a focused Windows evidence report:

```text
evidence/windows_reparse_ads_report.md
evidence/windows_reparse_ads_report.json
```

The report covers four NTFS cases:

- junction / reparse point escaping the boundary
- junction / reparse point staying inside the boundary but still carrying a
  redirect surface
- alternate data stream sharing the host file id
- alternate data stream hidden from normal directory enumeration

All four were intercepted. The important result is not that every mechanism name
is final; it is that these Windows-specific disguises no longer pass as ordinary
files or folders.

## What To Review

If you are reviewing this project, please attack these boundaries:

1. Can PUB reliably sit before agent tool-use without becoming the executor?
2. Are X-ray enter/exit observations enough to prove protected movement?
3. Is `HASH_MUTATED -> HOLD` a defensible first verdict?
4. Is `SceneSeed` cleanly separated from evidence and autopsy output?
5. Can redteam cases create silent escape rather than only under-classification?
6. Does any layer accidentally claim execution authority?

Good reviews should include a reproducible case, not only an opinion.

## What PUB Does Not Do

PUB is not:

- an antivirus engine
- an endpoint security replacement
- an OS sandbox
- a cloud service
- a prompt moderation layer
- a final judge with sole execution authority

PUB is a local evidence gate. It should make unsafe or unclear tool movement visible before it reaches the real world.

## Current Limits

v1.0 is still an early-access local release. It improves the audit shell and
Windows observation layer before solving every forensic label.

Known next work:

- fuller `P_auth` authorization delta
- direct runtime integration for temporal continuity where required
- better hardlink / junction / ADS mechanism labels
- stronger mtime/ctime replay semantics
- multi-auditor voting and separated verdict panels
- cleaner public evidence docs

Known limitation (red-team, reproducible):

PUB infers an action's effects from the tool-call surface — the command text and
its declared targets. An opaque subprocess such as `python script.py` is a black
box to that surface: it parses to "read-only, no targets", so a secret read plus
a network egress performed *inside one subprocess* passes every layer (spatial
gate, X-ray review, X-ray transition snapshot, and the temporal sequence judge).
The snapshot layers are blind here by construction — a read copies bytes without
mutating any file, leaving no state delta to observe, and PUB does not watch the
network. Spelling the same action out in the command (e.g. `curl ... "$(cat
.env)"`) is correctly killed.

This is the advisory-vs-mandatory boundary: PUB is a cooperative, user-space
reference monitor over declared tool calls. Catching effects hidden inside an
opaque child process requires mandatory interposition at the syscall boundary
(minifilter/WFP on Windows, eBPF on Linux) feeding the same gate — tracked above
as "direct runtime integration".

These are not reasons to weaken the boundary.

```text
No update may silently weaken the audit boundary.
```
## One-Sentence Summary

Protect U Back is a local pre-commit audit gate for AI agents: it passes safe
proposals, holds ambiguous proposals, and kills dangerous side effects with an
autopsy trail before tools execute.

## Personal Preference

u better protect ya back.
