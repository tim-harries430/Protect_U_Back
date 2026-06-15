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
