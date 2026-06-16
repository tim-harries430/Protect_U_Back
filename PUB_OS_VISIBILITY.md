# PUB-OS Visibility Slice

This slice does not change the PUB approval chain.

It adds one missing input surface: structured local receipts for objects touched
by an agent running inside a PUB kingdom. A receipt is evidence only. It cannot
execute, grant permission, or replace Admission, Channel, Capability, Protect,
X-ray, or OT.

## Laws

- Existing approval semantics stay unchanged.
- PUB-OS does not add another judge; it makes PUB see the target.
- Required local sensors must be ready before the agent is born.
- Network sensor support is optional in v1 and is recorded as absent.
- With no network sensor, opaque runtime execution holds by default.
- Downloaded artifacts must be admitted again before read, exec, import, move,
  unpack, or use.
- Sensor receipts do not capture payloads.
- Sensor receipts are not LLM-visible by default.
- Sensor receipts reject authority claims such as `can_execute`,
  `can_grant_permission`, `permission_granted`, `allow`, `execute`, `grant`,
  and `kill`.
- A sensor `READY` status means the sensor interface is present, not that
  observation is occurring. A launch barrier PASS is not proof that any object
  touch was witnessed.
- Every touch carries an `observation_source`. It defaults to `PROPOSAL` and is
  only `SENSOR` when a real local sensor observed the touch. v1 ships no such
  sensor, so live-pipeline touches are `PROPOSAL`: they are reconstructed from
  the agent's own declared action through the same lexical extraction the
  proposal chain already uses.
- A PASS / clear receipt over a `PROPOSAL` touch is a declaration that nothing
  modellable looked wrong, not an eyewitness record. It must never be read as
  "PUB watched the object being touched." Side effects hidden inside an opaque
  payload produce no touch at all; the compensating control is that opaque
  execution HOLDs, not that the hidden effect is seen.

## New Files

- `project/pub_os_visibility.py`
  - `KingdomSession`: launch barrier and sensor readiness.
  - `ObjectTouchEvent`: process/file/network/artifact touch receipt. Carries an
    `observation_source` (`PROPOSAL` by default, `SENSOR` only for real sensor
    observations) so a receipt never overstates how the touch was learned.
  - `SensorFeed`: testimony-only bundle for real object touch observations.
  - `receipt_for_touch()`: visibility gap detector.
  - `action_envelope_from_touch()`: maps observed object touch into the existing
    `ActionEnvelope` shape.
- `project/tests/test_pub_os_visibility.py`
  - launch barrier witness
  - network sensor absent witness
  - opaque execution HOLD witness
  - unknown runtime HOLD witness
  - downloaded artifact admission witness
  - testimony-only `SensorFeed` witness
  - no payload / no LLM visibility witness
  - no authority-claim witness
- `project/pub_os_authorization.py`
  - `CapabilityLease`: short-lived, scoped runtime lease issued only after an
    existing PUB approval result is PASS.
  - `check_lease_for_touch()`: syscall/object-touch lease matcher.
  - `consume_lease_after_match()`: one-shot consumption helper.
- `project/pub_os_touch_pipeline.py`
  - `touches_from_claude_event()`: maps a `cc` hook event into
    `ObjectTouchEvent`.
  - `touches_from_codex_shell_argv()`: maps a `cd` shell guard argv into
    `ObjectTouchEvent`.
  - `authorize_touch_for_lease()`: runs visibility first, then existing PUB
    audit, and mints a runtime lease only after PASS.
- `project/tests/test_pub_os_authorization.py`
  - PASS-only lease issue witness
  - non-PASS rejection witness
  - one-shot match/consume witness
  - missing/expired/pid/op/object mismatch witnesses
  - file-id match witness for renamed paths
- `project/tests/test_pub_os_touch_pipeline.py`
  - visibility HOLD short-circuit witness
  - PASS-to-lease witness
  - non-PASS audit no-lease witness
  - unsupported network lease witness
  - `cc` hook and `cd` shell guard touch mapping witnesses
- `project/pub_os_profiles.py`
  - `check_codex_profile()`: confirms `cd` is routed through the PUB shell
    guard connector.
  - `check_claude_code_profile()`: confirms `cc` has all-tool hooks and
    the gate switch is armed.
  - `check_agent_runtime()`: admits only the active `cd` or `cc` runtime that
    has entered through its PUB boundary.
  - `check_kingdom_supervision()`: compatibility wrapper for active-profile
    runtime admission.
- `project/pub_os_runner.py`
  - `prepare_agent_run()`: checks active profile admission, launch sensors, and
    agent argv before a session can start.
  - `start_agent_run()`: starts only through an explicit supervisor executor.
  - `append_ledger_entry()`: writes low-token append-only session receipts.
- `project/tests/test_pub_os_profiles.py`
  - `cd` supervised/HOLD witnesses
  - `cc` supervised/HOLD witnesses
  - active-profile runtime admission witnesses
- `project/tests/test_pub_os_runner.py`
  - active `cd`/`cc` runner witnesses
  - `cd` sandbox/approval bypass argument HOLD witnesses
  - `cc` hook/permission bypass argument HOLD witnesses
  - executor-required and session-ledger witnesses

## First Runtime Boundary

`pub-os run <agent>` should make PUB the agent supervisor. The supervisor starts
the agent only after process, filesystem, scene, and audit sensors report READY.
All sensor events share a `session_id` and `event_id`, then feed the existing PUB
approval path as evidence.

The v1 network stance is deliberately narrow: network text and declared targets
are still handled by the existing audit chain, while low-level network sensor
absence is recorded. This is not a claim that hidden network egress is solved.
The compensating rule is that opaque execution is HOLD unless a stronger runtime
profile is present.

## Runtime Lease Boundary

PUB approval is still unchanged and still cannot execute. A runtime lease is a
separate supervisor artifact created only after the existing approval result is
`PASS`.

The lease is scoped to one session, actor, operation, object, optional pid/root
pid, and a short expiry window. A syscall or object-touch event without a
matching lease holds. A matching one-shot lease is consumed after use. Leases
cannot grant permission onward.

## Touch Pipeline

`cd` and `cc` now converge on the same object-touch language. Their native
events are mapped into `ObjectTouchEvent`, then `authorize_touch_for_lease()`
checks visibility before invoking the existing PUB audit path. Visibility HOLD
stops before audit. Non-PASS audit stops before lease. A PASS audit can mint a
scoped runtime lease and immediately verify that the lease matches the same
touch. Network touches do not mint file leases in this slice.

## cd And cc Supervision

PUB-OS v1 is scoped to the agent session that enters the kingdom. `cd` and `cc`
are supported profiles, but they are not a global product matrix and they are
not required to be present at the same time.

If the active profile is `cd`, PUB checks only the `cd` boundary: the Codex
runtime must be routed through the PUB shell guard connector. If the active
profile is `cc`, PUB checks only the `cc` boundary: Claude Code must have
all-tool hooks and the gate switch armed.

The `cd` runner fails closed on Codex's two open security rails. pub cannot
reach inside Codex past its closed hook layer, so `approval` and `sandbox` are
the whole of pub's cd leverage and the launch clamp must be a positive
allowlist, not just a blacklist:

- Sandbox must be positively declared as `workspace-write` or `read-only`. An
  undeclared sandbox, an unknown value, or `danger-full-access` all HOLD
  (`CD_SANDBOX_NOT_DECLARED` / `CD_SANDBOX_NOT_CONTAINED`).
- Approval must be positively declared as `on-request` or `untrusted`, so pub
  stays the approver and keeps eyes on Codex's exec stream. Undeclared or
  unknown HOLDs (`CD_APPROVAL_NOT_DECLARED` / `CD_APPROVAL_NOT_CONTAINED`);
  `never` is rejected.

Both direct flags (`--sandbox`, `--approval-policy`, `--ask-for-approval`) and
`--config` overrides are read, last value wins. The known bypass flags
(`--dangerously-bypass-approvals-and-sandbox`, `--full-auto`, etc.) are still
rejected first as defense in depth, but the allowlist is what refuses a future
flag or a silent config default that the blacklist has never heard of. The
containment that results is Codex's own sandbox plus this clamp -- pub does not
add a cage of its own to cd and must not claim containment beyond what Codex's
sandbox provides.

The `cc` runner rejects launch arguments that skip hooks or native permission
checks, including `--bare`, `--safe-mode`,
`--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`,
`--permission-mode bypassPermissions`, and `--permission-mode dontAsk`.

Missing connectors, partial `cc` hook matchers, a disarmed `cc` gate switch,
unexpected `cd` boundary routing, profile mismatch, or authority leakage all
produce HOLD. This is agent runtime supervision, not a system-wide security
product.

## cc Cage (prototype)

Codex and Claude Code give pub opposite halves. Codex exposes a sandbox (hands)
but a closed hook (narrow eyes); Claude Code exposes open hooks (wide eyes) but
no built-in sandbox (no hands). Claude Code also mutates the filesystem with
in-process Node fs calls, not through a shell, so the cd-style shell guard
cannot reach its `Write`/`Edit`. The only thing with teeth is to confine the
WHOLE `claude` process. cc therefore needs a cage pub brings itself.

`pub_os_cage.py` renders that cage as a bubblewrap (`bwrap`) command -- an
unprivileged user-namespace sandbox, not a kernel module. Load-bearing
invariants:

- Exactly one writable real-estate inside the cage: `project_root`.
- The control plane that lives inside the project (`.claude/settings*.json`,
  `pub_gate_switch.json`) is re-bound read-only over the writable project, so a
  caged agent cannot rewrite its own hook registration to disarm pub.
- Anything not bound does not exist in the cage, so a path spelled to escape
  (drive-relative, `~`, `..`, absolute-outside) lands on an unmounted path and
  fails at the OS, not at a path parser.
- No bwrap, no run: `make_cage_spawn` raises `CageUnavailable` rather than
  launch an uncaged agent (same fail-closed stance as the cd clamp).
- pub's own source must live outside `project_root` (asserted), else the project
  bind hands the agent its own enforcement code.

The witness does not share the cell with the prisoner. `pub_os_ledger.py` runs a
`LedgerSupervisor` OUTSIDE the cage as the only writer; the ledger file lives
outside and is never bind-mounted in, so no in-cage process can open, truncate,
or rewrite it. The in-cage hook records by calling `emit_event` over a unix
socket whose node is the only thing bind-mounted in (`CageSpec.ledger_socket`):
connecting delivers an event, it does not grant file access. The supervisor
rejects any event carrying a payload or authority field, stamps a monotonic
sequence, and links each row into a hash chain so the ledger is tamper-evident
even against a writer bug (`verify_chain`). `emit_event` fails closed -- it
raises if the supervisor is unreachable or withholds an ack, so a lost witness
tightens rather than loosens (the in-cage hook is expected to map that to HOLD).

The one remaining seam to close is wiring the live CC hook entry to call
`emit_event` (and map `LedgerUnavailable` to HOLD); that touches the original
hook code and is a separate, authorized step.
