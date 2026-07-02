# The PUB Codex — All the Rules of an AI Gatekeeper Kingdom

> **For everyone (including non-technical readers).** Plain language comes first; uppercase English **reason codes** follow (these are the real charge names in the codebase, for engineers to cross-check — every rule in this codex is drawn from code, not invented).

---

## What This Is (One Sentence)

An AI assistant (agent) on your machine helps you work — writing code, deleting files, installing things, going online. **pub stands between the agent and your computer like a gatekeeper:** before the agent does anything, **it must ask pub**, and pub decides whether to allow it.

The gatekeeper has three actions:

- **PASS** — Normal. Proceed.
- **HOLD** — Suspicious. Blocked until **you approve** (no approval, no action).
- **KILL** — Dangerous. **Denied outright**; the gate does not open.

---

## The Gatekeeper’s Temperament (Seven Core Principles)

1. **When in doubt, block.** If something is opaque, evidence is incomplete, or intent is unclear — deny by default (better to block wrongly than to let harm through).
2. **The strictest voice wins.** Several judges may review the same action; **if any one says “dangerous,” that verdict stands.** A “safe” vote **never overrides** a “dangerous” one.
3. **Only ever tighten, never loosen.** Later judges may escalate toward stricter outcomes; they may never relax an earlier verdict.
4. **The AI saying “yes” does not count.** Only pub’s approval counts.
5. **Different agents, different rules.** The same command may be treated differently for different AI assistants (more trust → slightly more room; less trust → full scrutiny).
6. **Destructive ops only when recoverable.** Destructive actions are allowed only when **a backup can be taken first and mistakes can be restored**; if backup is not possible, block.
7. **Trust what is observable, not what is claimed.** The gatekeeper reads real file fingerprints and identity metadata — not self-declarations of good intent.

---

## The Kingdom’s Judges (Twelve Roles)

> Under each judge: plain language describes what it governs; uppercase English names are the **charge codes** it can issue.

### 1. OT Gate · Three Chief Judges (`ot_gate.py`) — The Constitutional Court

> **In plain terms: “Did this command cross a line, and was it well-behaved?”** Three lenses: ① boundary (did it touch forbidden places?) ② intent (do words match actions?) ③ evidence (who are you, and are you authorized?).

**Boundary — immediate denial (KILL):**

- Delete/modify protected core areas `CRITICAL_PROTECTED_PHI_WRITE` · touch the registry `CRITICAL_REGISTRY_READ`
- Dangerous deletion (not “delete one small in-project file”) `CRITICAL_DESTRUCTIVE_COMMAND`
- Privilege escalation `CRITICAL_PRIVILEGE_ESCALATION`
- Download-then-execute (classic trojan pattern) `CRITICAL_NETWORK_EXECUTE`
- Touch secrets `CRITICAL_SECRET_ACCESS` · tamper with audit/permissions `CRITICAL_AUDIT_BYPASS`
- Write/delete **outside the project** `CRITICAL_EXTERNAL_WRITE`

**Pause and ask you (HOLD):** read protected zones `PROTECTED_PHI_READ_REQUIRES_APPROVAL` · read outside project `EXTERNAL_READ_REQUIRES_APPROVAL` · environment variables / network `ENV_OR_NETWORK_REQUIRES_APPROVAL`.

**Identity unclear — also blocked:** `MISSING_ACTOR_ID` (unknown who you are) · `UNKNOWN_ACTOR` (not registered) · `ACTOR_FROZEN` (prior serious offense; frozen).

### 2. Capability Wall (`capability_wall.py`) — “Do You Have Permission for This?”

> **In plain terms: each AI gets a capability manifest at onboarding. Anything outside the manifest is blocked.**

Unauthorized delete side effect `CAPABILITY_SIDE_EFFECT_DENIED` · out-of-scope privilege/audit change `CAPABILITY_PERMISSION_MUTATION_DENIED` / `_AUDIT_MUTATION_DENIED` · path not on manifest `CAPABILITY_PATH_DENIED` · contact unknown domain `CAPABILITY_NETWORK_DOMAIN_DENIED` · forge internal credential `CAPABILITY_PROBE_MINT_UNAUTHORIZED` · skip required safety step `CAPABILITY_SKILL_REQUIRED_STEP_SKIPPED`.

### 3. Dual-Court Deliberation (`parallel_audit.py`) — Two Chambers, Strictest Wins

> **In plain terms: one chamber reads “what the command looks like”; the other reads “what it would cause.” Verdicts merge — strictest wins.**

Opaque command surface `COMMAND_SURFACE_OPAQUE_EXECUTION` (see Judge 4) · unknown command surface `UNKNOWN_COMMAND_SURFACE` · chambers conflict → strict HOLD `DUAL_COURT_CONFLICT_HOLD`.

### 4. Opaque-Execution Detector (`opaque_executor.py`)

> **In plain terms: `python ...`, `bash some_script`, bare `> file` — the gatekeeper cannot see inside. Opaque does not auto-KILL, but it **HOLDs** first; no guessing.**

### 5. X-Ray Inspection (`transition_xray.py` and allies) — The File’s True Identity

> **In plain terms: rename malware to `.txt` to blend in? The gatekeeper ignores extensions and reads real fingerprints.**

Disguised type, hidden data streams (ADS), timestamp tampering, bait-and-switch, hard-link alias (`HARD_LINK_ALIAS`), enter/exit fingerprint mismatch (changed mid-flight) `FRAME_DRIFT_MISMATCH` — all exposed.

### 6. Fourth Judge · Sequential Actions (`temporal_continuity.py`)

> **In plain terms: each step alone looks fine; chained together it’s wrong — “read secrets, download something, then exfil.” This judge watches sequences.** Only ever tightens.

Accumulated exposure at exit `TEMPORAL_ACCUMULATED_EXPOSURE_EXIT` · taint egress `TEMPORAL_TAINT_EGRESS`.

### 7. Scene Judge · Surroundings Tampering (`scene_continuity.py`)

> **In plain terms: between two actions, was pub’s own gatekeeper code altered off-band? If yes → HOLD.** (Note: ordinary project files you create/delete for work are **not** its concern — that’s normal activity.)

Off-band pub module tampering `SCENE_DISCONTINUOUS`.

### 8. Protect Scan (`protect_scan.py`) — Guardrails on Your Private Machine

> **In plain terms: protects the most sensitive things on your computer — keys, passwords, browser data, email, personal documents, pub’s own code. Touch them → HOLD or deny.**

Secret exfil `PROTECT_SECRET_SURFACE_DENIED` / `PROTECT_NETWORK_EXFIL_DENIED` · mutate pub itself `PROTECT_PUB_INTERNAL_MUTATION_DENIED` · alter `.git` hooks (backdoor vector) `PROTECT_GIT_SURFACE_WRITE_DENIED` · personal docs / browser / email `PROTECT_PERSONAL_DOCUMENT_*` / `_BROWSER_PROFILE_*` / `_EMAIL_CACHE_*` (touch = deny, read = ask) · silent boundary-weakening patch `PATCH_AUDIT_SILENT_BOUNDARY_WEAKENING`.

### 9. Green Channel (`llm_channel.py`) — Fast Lane for Obviously Safe Daily Work

> **In plain terms: routine safe ops like `git commit` may use a green lane — but any hint of danger (network, secrets, out-of-project delete, opacity) cancels the lane and sends the action back for full review.** This is a convenience layer; it only allows, never helps attackers.

### 10. Registry + Chronicler (`registry_admission` · `event_ledger` · `task_guard`)

> **In plain terms: register on entry (who you are, what you want); the chronicler keeps score — **two serious offenses freeze the agent**; continued kills **terminate the task**.**

Two fatal actions → freeze `BUGCHECK` · repeated kills → `TASK_TERMINATED`.

### 11. Cell and Cage (`pub_os_*`) — Last Resort: Confine the AI

> **In plain terms: beyond gate review, pub can **lock the AI in a compartment (cage)** — one project only, nowhere else on the machine. Even if the gate misjudges, it cannot escape.** If the cage cannot be built, **work does not start**; never run bare.

Witness lost `PUB_OS_LEDGER_WITNESS_LOST` (HOLD) · pre-delete backup failed `PUB_BACKFILL_JOURNAL_FAILED` (HOLD) · cage unavailable `cage_unavailable:*` (fail-closed).

### 12. Access Physics / Time Grid (`access_*`) — Low-Level “Can This Move?” Calculus

> **In plain terms: underlying formulas for whether a file may move now (how much authority, exposure, trust). Also tracks identity drift — file ID changed, pointer moved, timestamp altered — all reported.** Engineers need not read this daily; the gatekeeper uses it internally.

---

## When Sentences Are “Reduced” (Allowlist + Safety Locks)

> **In plain terms: the gatekeeper is not only a blocker. The routines below are clearly safe and may pass — but each has a safety lock; if the lock fails, the action is blocked again. Allowlisting lists only known-safe cases; missing an entry means “blocked once more,” never “accidental hole.”**

1. **Delete/rename one small in-project file:** real delete/rename command + targets inside project + not recursive/wildcard/home-dir → allow. **Bare `> file` (truncate with no verb) still blocked.** Trusted `claude_code` only.
2. **Delete an in-project folder (recursive):** inside project, contents enumerable → allow, **but every file inside must be backed up first**; if backup fails (too large / uncountable) → HOLD.
3. **Leave a trail on delete:** first allowed scoped delete records evidence in the autopsy trail for later audit.
4. **Routine `git` ops** (add/commit/checkout/…): single command, no dangerous flags like `--hard` / `--force` → allow; `reset --hard`, `push`, `clean` still blocked.
5. **In-project chmod/tar/zip:** ordinary ops allowed; setuid or out-of-project touch blocked. **`ln` (create link) not allowed** — escape vector; stays behind the wall.

---

## Ballast Meta-Rules

- **Strictest wins:** many judges → take the strictest; dual-court conflict → strict HOLD.
- **Escalate only:** after the gate, sequential judge → scene judge → cage witness may only tighten, never relax.
- **Directory exemption:** folders naturally have link count ≥ 2; that is normal structure, **not** treated as alias suspicion.
- **Two ancestral rules:** ① Do not try to “list all evil” — the list is always incomplete; the deny side defaults to **deny**. ② Do not trust speech — anchor on physical facts only.
- **Wall > Gate > Exit:** first a cage that can catch failures (wall), then judges (gate), then smooth egress (exit); **never loosen the wall to make work easier.**

---

_Every charge in this codex is a real reason code in the codebase (single source of truth). Change a verdict in code → update the corresponding law here._
