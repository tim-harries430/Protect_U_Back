# Protect U Back

Protect U Back (PUB) is a local pre-I/O audit kernel and PUB-OS supervisor for AI agents.

It is built from one simple rule: an agent action should leave evidence before it is allowed to touch the world.

PUB is not a prompt filter. It does not try to decide whether language sounds safe. It audits proposed tool use, filesystem movement, process surfaces, and the physical state around an action.

PUB-OS is an agent operating boundary, not a host operating system. It does not claim to replace Windows, Linux, an endpoint security product, or a kernel sandbox. Its job is narrower: connected agents enter through PUB-controlled entrypoints, and their declared tool or shell movement is observed before it reaches real side effects.

```text
Channel -> Envelope -> X-ray -> Admission -> Tool -> Autopsy -> OT
```

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

v1.0 keeps that boundary and adds the missing connection, agent-supervision, and Windows observation work:

- Claude Code hooks now match all tools with `*`, not only a small Bash/Edit
  set
- unmodelled Claude Code tools are routed to explicit review instead of silent
  allow
- `pub_gate_switch.json` can disable blocking without disabling observation
- hardened `safe_resolve()` path handling turns malformed or hostile paths into
  blind spots instead of auditor crashes
- NTFS reparse points are named as `reparse_point` and carry `reparse_tag`
- NTFS alternate data streams are separated by metadata-vector evidence instead
  of collapsing onto the host `file_id`
- `temporal_continuity.py` adds a sequence-memory layer for read-then-egress and
  read-then-opaque-exec patterns **across separate, observed tool calls**
- PUB-OS introduces supervised agent entry instead of trusting an already-running
  desktop session
- Claude Code (`cc`) is covered through all-tool hooks, fail-closed ledger
  witness, and explicit review for unmodelled tools
- Codex CLI (`cd`) is covered through a PUB shell guard entrypoint that records
  shell pre/post evidence and blocks dangerous side effects before execution

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
PUB-OS / Codex / connector regression:                 93 passed, 1 xfailed
Packaged PUB-OS release tests:                           83 passed
Windows reparse / ADS evidence cases:                    4 / 4 intercepted
Codex CLI guard probe: read PASS, write PASS, opaque HOLD, delete KILL
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
cd ProtectUBack_early_access_1.0_local
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

`pub_gate_switch.json` is an operator escape hatch: turning the gate off stops
blocking/escalation, but the hook still records the audit trail. It is not a
permission grant and should not be treated as a clean verdict.

## Codex CLI Guard

PUB can connect to Codex CLI through a local shell guard launcher. The launcher starts Codex inside a shell overlay where `/bin/bash` and `/bin/sh` route through `codex_bash_guard.py` before real shell execution.

The guard is not a Codex binary patch and does not grant permission. It records pre/post shell evidence, keeps `can_execute=false` and `can_grant_permission=false`, allows ordinary local read/code-work commands, holds opaque writer surfaces when targets are unclear, and kills destructive side effects such as `rm -rf` before execution.

An already-running Codex Desktop session is outside this boundary. It must be treated as unsupervised unless it entered through a PUB-controlled connector.

## Windows Evidence

v1.0 keeps the focused Windows evidence report:

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
- a host OS replacement or kernel sandbox
- a cloud service
- a prompt moderation layer
- a final judge with sole execution authority

PUB is a local evidence gate and agent supervision boundary. It should make unsafe or unclear tool movement visible before it reaches the real world.

## Current Limits

v1.0 is the first PUB-OS local release. It improves the audit shell, Windows observation layer, and connected-agent interception surface before solving every forensic label.

Known next work:

- fuller `P_auth` authorization delta
- kernel-level runtime sensors where required (minifilter/WFP on Windows, eBPF on Linux)
- better hardlink / junction / ADS mechanism labels
- stronger mtime/ctime replay semantics
- multi-auditor voting and separated verdict panels
- cleaner public evidence docs

Current boundary (red-team, reproducible):

PUB-OS now covers the connected agent entrypoints it owns. Claude Code enters through all-tool hooks. Codex CLI enters through the PUB shell guard. In that connected mode, ordinary local code reading is not killed just because it uses `2>/dev/null`, project-local shell writes are visible, opaque writer surfaces are held when targets cannot be proved, and destructive shell side effects such as `rm -rf` are killed before execution.

The remaining limit is host-wide mandatory interposition. PUB-OS does not retroactively attach to an already-running desktop agent, and it is not yet a kernel syscall monitor for every child process on the PC. Effects hidden inside an opaque child process remain admissible only when they are visible through the supervised tool or shell surface; otherwise they must HOLD or be caught later by a future minifilter/WFP/eBPF style sensor feeding the same PUB gate. Downloaded or externally produced files are still suspect inputs and must be re-admitted before trust.

These are not reasons to weaken the boundary.

```text
No update may silently weaken the audit boundary.
```

# How to read (and reproduce) the blast key experiment

This is a no-prior-knowledge walkthrough. Copy-paste the commands. Each step says
exactly what you should see. If you see something else, that's a finding — tell us.

---

## TL;DR (the one claim)

We took a **fake API key** (a worthless honeytoken) and made a **real network
request** with it, on purpose, to see what a real server does. Two targets:

| target | what came back | what it means |
|---|---|---|
| **GitHub** `api.github.com` | `HTTP 401 Bad credentials` **with a real `x-github-request-id`** | the request reached GitHub's auth servers, the fake key was actually checked, and rejected |
| Anthropic `api.anthropic.com` | `HTTP 403 "Request not allowed"`, **no** request-id | blocked at the edge/WAF before auth — never reached key checking (kept only as an honest negative) |

No real account was touched. The key is fake. The I/O is real.

---

## Part 1 — Read the result with ZERO tools (just open a file)

Open this file in any text viewer:

```
runs/blast-p2-github/autopsy.md
```

Then open this one:

```
runs/blast-p2-github/summary.json
```

In `summary.json`, only **four lines** matter. Find them:

```
"gate_dryrun": { "decision": "KILL", "reason_code": "CRITICAL_KILL" }   <- our gate said: block this
"bypassed_gate": true                                                   <- we deliberately ran it anyway
"real_egress": { "http_status": 401, "http_reason": "Unauthorized" }    <- the real server's answer
"github_request_id": "EB5E:3D7F3D:..."                                  <- proof it hit GitHub's servers
```

That's the whole story: *our own gate would have killed this; we bypassed it to
show what reality does; reality returned a real, server-side 401.*

---

## Part 2 — Reproduce the headline yourself in 10 seconds

You do **not** need our code for this. You only need `curl` (preinstalled on
Mac/Linux; on Windows use Git Bash or WSL).

Paste this:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -H "Authorization: Bearer ghp_THIS_IS_A_FAKE_TOKEN_xxxxxxxxxxxxxxxxxx" \
  -H "User-Agent: blast-probe" \
  https://api.github.com/user
```

**You should see:**

```
HTTP 401
```

Now see the body and the proof-of-arrival header:

```bash
curl -s -D - \
  -H "Authorization: Bearer ghp_THIS_IS_A_FAKE_TOKEN_xxxxxxxxxxxxxxxxxx" \
  -H "User-Agent: blast-probe" \
  https://api.github.com/user | grep -iE "HTTP/|x-github-request-id|message"
```

**You should see something like:**

```
HTTP/2 401
x-github-request-id: 813F:0C22:27BDD6C:2D18EBE:6A2E55A2
  "message": "Bad credentials",
```

> Pedant note: the `x-github-request-id` value is **different every run** — it's a
> fresh per-request ID minted by GitHub. The point is not that it matches ours;
> the point is that one *exists*. That header is GitHub telling you the request
> reached their servers and was processed. A fake key can't fake that.

---

## Part 3 — Verify our published files weren't tampered with

Every run folder ships a `SHA256SUMS.txt`: the SHA-256 of every other file in
that folder, recorded at the moment we generated it. You can re-hash the files
yourself and confirm they match bit-for-bit.

```bash
cd runs/blast-p2-github      # or runs/blast-p1, or runs/blast-p2
```

**Linux:**
```bash
sha256sum -c SHA256SUMS.txt
```

**Mac:**
```bash
shasum -a 256 -c SHA256SUMS.txt
```

**You should see:**

```
autopsy.json: OK
autopsy.md: OK
seed.json: OK
summary.json: OK
```

If any line says `FAILED`, the file was changed after we sealed it. (Tip: don't
open the files in an editor that "fixes" line endings before you check — verify
the files exactly as you downloaded them.)

---

## Part 4 — What's reproducible vs what's live (don't get confused)

- **`seed_hash`** in `seed.json` is **deterministic**. Re-run our harness on any
  machine and you get the *identical* hash. For the GitHub run it is always:
  ```
  sha256:6e679f2e925c8b053c4d772620b1011d7184fca112abdb53764a34d65b780a33
  ```
  This proves the *setup* (boundary, scope, environment) is exactly what we say.

- **The HTTP response** (status + `request-id`) is **live**. You get a fresh
  401 and a fresh request-id every time you run the curl above. The invariant is
  `401 + a request-id exists`, not a matching ID.

Two different kinds of proof: one cryptographic (the seed/file hashes), one
empirical (the live 401 you can trigger yourself).

---

## What this proves — and what it does NOT

**Proves:**
- The request really left the machine and really reached GitHub's auth layer.
- A fake credential is evaluated and rejected server-side with a real, traceable
  request ID.
- Our gate flagged the action as `KILL` *before* it ran; the egress only happened
  because we explicitly bypassed the gate.

**Does NOT prove:**
- Anything about a real/valid account — the token is fake by construction.
- That GitHub is insecure — a 401 on a bad token is GitHub working correctly.
- That our gate is bulletproof — see the companion note: the gate inspects the
  *command*, not the syscalls a spawned process makes at runtime. Egress buried
  inside `python somescript.py` is a structural blind spot. That's the point of
  the experiment, not a footnote.

---

## File map

```
runs/blast-p1/            phase 1: local-only loopback (no internet), gate behavior
runs/blast-p2/            phase 2 vs Anthropic  -> 403 edge block (honest negative)
runs/blast-p2-github/     phase 2 vs GitHub     -> real 401 (the headline)
  ├─ summary.json         machine-readable result (read this)
  ├─ autopsy.{json,md}    why our gate said KILL (human-readable .md)
  ├─ seed.json            deterministic setup + seed_hash
  └─ SHA256SUMS.txt       integrity manifest (Part 3)
```

## One-Sentence Summary

Protect U Back is a local pre-I/O audit gate and PUB-OS supervisor for AI
agents: it passes safe proposals, holds ambiguous proposals, and kills dangerous
side effects with an autopsy trail before tools execute.

## Personal Preference

u better protect ya back.
