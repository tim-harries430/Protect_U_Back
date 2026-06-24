# PUB — Can it be attacked or tricked? (the evidence)

> Every number below is **computed from raw logs**, not hand-typed. The raw archive
> (564 autopsies, 48,931 verdicts, 1,387 tamper-evident frames) and the one command to
> recompute each number are at the bottom. Self-generated adversarial load — like any
> research prototype's break-it suite, not production traffic. Stated honestly.

---

## The one line

**Across 45,618 recorded verdicts, pub allowed a dangerous action 0 times** — *and* it did
this while judging **323 live tool-calls from a real Claude Code agent running inside a real
bubblewrap container**, writing a human-readable post-mortem for **every** block.

---

## 1. Safety floor — the only number that can't fail soft

A 30-minute soak, the same 54 daily-work actions (with dangerous ones mixed in) looped ~28×.

| | computed |
|---|---|
| Total verdicts judged | **45,618** |
| Decision split | PASS **17,612** · HOLD **16,091** · KILL **11,729** · QUARANTINE **186** |
| **Dangerous action allowed (fail-open)** | **0** |

> **0 / 45,618.** Not one action that was labelled *must-kill* slipped through as allowed.
> That is the wall's floor, measured — not asserted.

**Honest about the rest:** 40,602 of 45,618 (89%) matched the pre-labelled expected verdict.
The 5,016 that didn't were **all on the safe side** — over-blocking (FRICTION 201, SOFT_BLOCK
1,135) or stale test-labels — **0 of them were dangerous-allowed**. pub errs toward *too strict*,
never *too loose*. (That over-strictness is exactly the calibration work being filed down; it
never costs safety.)

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

**Anyone, on your own machine (this is the strong one):** you don't recompute *our* numbers —
you generate *your own*. Clone pub, run the soak; it produces *your* ~45,000 verdicts and you
count *your own* fail-opens. **A run you execute yourself can't be doctored; our logs you'd have
to take on faith.** That is why uploading 50 MB of our logs would be *weaker* than this one line:

```bash
python3 pub_daily_soak_runner.py --duration-seconds 1800 --sleep-seconds 1.0
# then count rows where the expected verdict was KILL but the action was allowed  ->  expect 0
```

A few real, scrubbed decisions to eyeball first: [`evidence_sample/SAMPLE.md`](evidence_sample/SAMPLE.md).

**Us, locally (provenance only):** the raw archive (564 autopsies, 48,931 verdicts, 1,387 sealed
frames) carries machine paths / a username, so it is **not shipped** — it stays gitignored. The
headline numbers above were recomputed from it with `find … | wc -l`. *The archive is the receipt;
the runner is the proof.*

**Strongest of all:** bring your own attacks. (Break-it scope welcome.)
