# PUB-OS Broker Contract — the prison-door window

> 本质:broker 是牢门上那扇小窗。它只能「收」与「过」。它没有钥匙(判决权),
> 没有手(执行权)。让监狱安全的一切,都是这扇窗**拒绝去做**的事。

The broker is the single, dumb, unbypassable aperture between the confined
workload (**the box** — `pub_os_cage` / `pub_os_runner`) and the outside world
(**pub-core**: the eyes that decode, the beast that judges, the warden that
executes). It is the ONLY thing the box can reach. Therefore it must hold **zero
authority** — anything it can do, a prisoner who finds a bug in it can do.

Roles are split so the prisoner-reachable component is powerless:

| Role | Where | May do | Box can reach? |
|------|-------|--------|----------------|
| **Window (broker)** | on the door | relay opaque frames; drop frames | **yes — the only one** |
| **Eyes + Beast (pub-core)** | outside | decode + judge | never |
| **Warden (executor)** | outside | perform the allowed op on a verdict | never (and is NOT the broker) |

---

## 1. Interface — what it DOES (the whole of it)

- **One channel.** A single bidirectional endpoint (vsock / unix socket / named
  pipe). This endpoint is **the box's only egress** — no FS outside the project
  root exists to the box, no network route exists except this socket. Complete
  mediation is a property of the BOX (no other path), not of the window.
- **Opaque framing only.** A frame is a length prefix + N opaque bytes. The
  window reads the length, reads N bytes, forwards them. It never looks inside.
- **Two relays, verbatim:**
  - inbound (box → pub-core): accept a request frame, forward it unchanged.
  - outbound (pub-core → box): accept an **authenticated** verdict/result frame,
    forward it unchanged.
- **Drop on any doubt.** If it cannot deliver (peer gone, overflow, malformed
  length, timeout), it drops the frame and closes. A dropped request is a denial.

That is the entire behaviour. The window's action set is exactly
`{ forward a frame, drop a frame }`.

---

## 2. Prohibitions — what it MUST NOT do (the heart of the spec)

1. **MUST NOT decode / parse / interpret** request or verdict payloads. It treats
   them as opaque bytes. (No parser attack surface is reachable from the box.)
2. **MUST NOT decide / classify / judge / allow / deny.** It has no verdict
   authority. Judgement happens behind it, in pub-core.
3. **MUST NOT execute or perform any operation on a resource** — no file read or
   write, no `connect`/socket, no `exec`/`spawn`/`fork`, no env mutation. It is
   not the warden.
4. **MUST NOT hold any capability, credential, key, or token** that could
   authorize an action. In particular it **MUST NOT hold the verdict-signing
   key**.
5. **MUST NOT synthesize, modify, reorder-for-advantage, or forge** a frame. It
   may drop; it may never fabricate an "allow" or alter a payload.
6. **MUST NOT keep security-relevant state** — no verdict cache, no memory of past
   decisions, no allow-list it grows. Stateless; every request is re-judged.
7. **MUST NOT expose any second channel, side path, fallback, or "degraded
   mode"** that reaches an effect without a pub-core verdict. One aperture, period.
8. **MUST NOT touch the host** beyond its two socket fds — no host FS, registry,
   network config, services, drivers, or privilege. (Portability rule: the window
   pollutes nothing and needs no admin.)
9. **MUST NOT be reconfigurable from inside the box.** Its behaviour is fixed at
   build; the prisoner cannot reprogram the window.
10. **MUST NOT fail open.** Any error, ambiguity, overflow, or timeout → drop →
    denial.

---

## 3. Invariants — what must always hold

- **I1 — Complete mediation.** The box has exactly one egress and it is the
  window; there is no path to external effect that does not produce a frame
  through it. *(Guaranteed by box construction, not by the window.)*
- **I2 — Powerlessness.** The window's entire action set is `{forward, drop}`.
  Nothing in it can cause or authorize an external effect.
- **I3 — Unforgeability.** A verdict is honoured by the warden only if
  authenticated by pub-core's key, which the window never holds. A compromised
  window cannot manufacture an "allow".
- **I4 — Fail-closed.** Window crash / hang / compromise ⇒ frames stop ⇒ requests
  are denied. A broken window makes the prison **tighter**, never looser.
- **I5 — Tamper-isolation.** Eyes, beast, and warden live outside the box and are
  unreachable from it except via authenticated frames the window relays.
  Compromise of the window does not reach them.
- **I6 — Verifiability.** Small enough to audit line-by-line: a single source file,
  no third-party dependencies, no content-dependent branching, target < ~150 LOC.

---

## 4. Threat model (consequences of the above)

- **Box fully compromised (RCE):** can emit arbitrary frames → all judged outside
  → gains no new authority. Can flood the window → DoS → denial (I4), not escape.
- **Window compromised:** can drop / delay (DoS, fail-closed) but cannot forge
  allows (I3) or perform actions (I2). Worst case is denial of service, never
  escape. *This is why the window's powerlessness is not hygiene — it is the
  precondition for I4 to hold.*
- **pub-core compromised:** out of scope here; verified separately. The window's
  dumbness means the box can only reach pub-core through frames that get judged.

---

## 5. Verification checklist — how we prove it harmless (nail it down first)

- [ ] Source references **zero resource APIs** (no host-file open/read/write, no
      `connect`, no `exec`/`fork`/`spawn`) except its two socket fds.
- [ ] **No branch depends on payload content** — only on length / framing.
- [ ] **No signing/verification key** is present in the window's address space.
- [ ] **No state persists** across frames (a stateless relay loop).
- [ ] **No config or exec path** is reachable from the box side.
- [ ] **Every error path** ends in drop/close — there is no default that forwards
      or allows.
- [ ] **Line count under budget, no third-party deps**; the whole file is auditable
      in one sitting.
- [ ] An **authenticated-verdict** check lives in the *warden*, not the window.

---

## 6. Relation to existing PUB-OS pieces

- `pub_os_cage` / `pub_os_runner` build **the box** and guarantee I1 (single
  egress) — the window does not enforce mediation, the box's lack of any other
  path does.
- `pub_os_ledger` (the out-of-cage ledger socket) is **pub-core's** audit
  surface, written by the beast/warden — **not** by the window.
- The window is the new, minimal piece that sits between them and must be proven
  harmless **before** anything else in the prison is trusted to grow on top of it.

---

**One line:** the window can pass a tray and it can stay shut. It holds no key and
has no hands. Everything that makes the prison safe is a thing the window refuses
to do.
