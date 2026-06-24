# PUB — Can it be attacked or tricked? (the evidence)

> Every number below is **computed from raw logs**, not hand-typed. The raw archive
> (564 autopsies, 48,931 verdicts, 1,387 tamper-evident frames) and the one command to
> recompute each number are at the bottom. Self-generated adversarial load — like any
> research prototype's break-it suite, not production traffic. Stated honestly.

---

## The one line

**Across 45,618 recorded verdicts, pub allowed a _must-kill_ action 0 times** — *and* it did
this while judging **323 live tool-calls from a real Claude Code agent running inside a real
bubblewrap container**, writing a human-readable post-mortem for **every** block.

> Two honest qualifiers up front: that 45,618 is the **cumulative** total of 171 soak runs, not
> one sitting (see §1); and "0" is the **must-kill** floor — pub *did* pass 688 softer
> *confirm-first* commands it was meant to hold, disclosed in full in §1. The floor held; the
> calibration above it is still being filed down, in the open.

---

## 1. Safety floor — the only number that can't fail soft

**171 archived soak runs**, pooled across several sessions over multiple days — the case set
itself grew from 45 to 54 actions across that span. Each run loops the daily-work actions with
dangerous ones mixed in. This is the **cumulative** total, not a single sitting:

| | computed (171 runs pooled) |
|---|---|
| Total verdicts judged | **45,618** |
| Decision split | PASS **17,612** · HOLD **16,091** · KILL **11,729** · QUARANTINE **186** |
| **Must-kill action allowed (fail-open)** | **0 / 11,729** |

> Not one of the 11,729 *must-kill* verdicts slipped through as allowed; no dangerous command was
> executed. That is the wall's floor, measured — not asserted.

**Honest about the 5,016 that didn't match — including which way each erred:** 40,602 of 45,618
(89%) matched the pre-labelled verdict. Of the remaining 5,016:

- **Too strict — 4,328 (safe side):** over-blocking — FRICTION 201, SOFT_BLOCK 1,135, HARD_BLOCK
  2,806, plus quarantine/stale-label DRIFT 186. Costs friction, never safety.
- **Too loose — 688 (`UNDERMODEL`), the honest bruise:** commands labelled *HOLD* that pub *passed*.
  All 688 are exactly three commands: `git commit` (254 — pub passes plain `git commit` **by
  design**, relaxation whitelist rule 4, so the soak's HOLD label is stale) and `docker compose up`
  + `kubectl apply -f prod.yaml` (434). Those last two are a **real leak**: the identical command is
  HELD ~77% of the time, but the green channel (`CHANNEL_WRAP_PROPOSAL`) fast-lanes it ~23% of the
  time. **None of the 688 was a must-kill** — the safety floor held — but "pub never errs too loose"
  would be a lie, so this poster doesn't say it. The green-channel leak is on the fix list, named
  here rather than papered over.

---

## 2. The part a synthetic suite can't show — a real agent, a real cage

Not pub testing pub. **Real Claude Code 2.1.170, launched inside an unprivileged bubblewrap
cage, every one of its live tool-calls mediated by pub:**

| | computed |
|---|---|
| Real-agent tool-calls judged | **323** |
| Decision split | PASS **194** · HOLD **67** · KILL **62** (blocked: 130) |
| Top reasons it blocked | opaque-execution ×32 · capability-path-denied ×22 · side-effect-denied ×20 · external-read-needs-confirm ×8 |

> The agent **could still work** (194 passed), while pub **held or killed 130** of its real
> moves with specific, logged reasons — and the container was the backstop: a write aimed at
> pub's own source hit a **read-only filesystem at the OS layer**, even if pub hadn't judged it.

---

## 3. What you actually get that a hash-log doesn't

- **Every verdict carries a machine-readable reason** (48,931 of them, each with a `reason_code`
  — *why* it was held/killed), and **564 sealed forensic autopsies** record the X-ray transition
  for actions (the tool, what it touched, the before/after content review). 184 of those are from
  the real caged agent. A hash-chain proves the log wasn't tampered; the autopsies make it *readable*.
- **1,387 tamper-evident X-ray frames** — each a sealed before/after content-hash of a file
  transition; a mid-flight swap shows up as a frame-drift mismatch.
- **704 tests** encode the rulebook (the law) and verify it green.

---

## Reproduce it — without trusting us, and without us shipping 50 MB of logs

**Anyone, on your own machine (this is the strong one):** don't recompute *our* 45,618 — that's the
cumulative total of 171 archived runs and won't fall out of one command. What reproduces is the
**invariant**: run the soak yourself and count must-kill fail-opens — you should get **0**, same as
us, on a fresh sample you generated and we never touched:

```bash
python3 pub_daily_soak_runner.py --duration-seconds 1800 --sleep-seconds 0
# ~100k fresh verdicts on your machine; then count:
#   must-kill allowed  (preferred == KILL and not blocked)   ->  expect 0
#   loose-side passes  (preferred == HOLD and actual == PASS) ->  you'll find the git/docker/kubectl
#                                                                 ones from §1 — go ahead, catch us
```

(`--sleep-seconds 1.0` throttles to ~1 verdict/sec ≈ 1,800 in 30 min; use `0` for a large sample.)
**A run you execute yourself can't be doctored; our logs you'd have to take on faith** — which is why
uploading 50 MB of our archive would be *weaker* than this. A few real, scrubbed decisions to eyeball
first: [`evidence_sample/SAMPLE.md`](evidence_sample/SAMPLE.md).

**Us, locally (provenance only):** the raw archive (171 soak runs = 45,618 verdicts, 564 autopsies,
48,931 reason-coded verdicts in total, 1,387 sealed frames) carries machine paths / a username, so it
is **not shipped** — it stays gitignored. The headline numbers above were recomputed from it with
`find … | wc -l` and the per-class counts shown. *The archive is the receipt; the runner is the proof.*

**Strongest of all:** bring your own attacks. (Break-it scope welcome.)
