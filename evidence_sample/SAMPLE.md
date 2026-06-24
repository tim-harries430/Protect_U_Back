# Sample: real Claude Code tool-calls, judged live by pub (scrubbed)

> A few real decisions pub made on a live Claude Code agent in a bwrap cage.
> Scrubbed of machine paths/usernames. Full archive stays local (privacy).

| tool | target | effects | verdict | reason |
|---|---|---|---|---|
| Bash | `—` | read | **HOLD** | `COMMAND_SURFACE_OPAQUE_EXECUTION` |
| Bash | `/mnt/c/dev/pub_work/.claude/.pub_codex_guard` | read, write | **KILL** | `PROTECT_PROBE_MINT_UNAUTHORIZED` |
| Bash | `https://example.com` | network, read | **KILL** | `CAPABILITY_SIDE_EFFECT_DENIED` |
| Bash | `/mnt/c/dev/pub_work/.claude/pub_gate_switch.js` | read | **KILL** | `CAPABILITY_PROTECTED_TARGET_DENIED` |
| Bash | `—` | read | **HOLD** | `PROTECT_AUDIT_SURFACE_REQUIRES_CONFIRMATION` |
| Bash | `/mnt/c/dev/pub_work/.claude/pub_gate_switch.js` | audit_change, read, write | **KILL** | `PROTECT_AUDIT_SURFACE_MUTATION_DENIED` |
| Bash | `—` | read | **PASS** | `CHANNEL_WRAP_PROPOSAL` |
| Bash | `—` | read | **PASS** | `CHANNEL_WRAP_PROPOSAL` |
