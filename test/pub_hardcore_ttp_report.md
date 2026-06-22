# Red-team round 4 -- real Windows filesystem TTPs vs pub's real transition_xray

_Generated 2026-06-20T17:10:18 -- reproducible: `python pub_hardcore_ttp.py` (Windows)_

**Method:** ATT&CK-style primitives fired inside pub's enter/exit X-ray window; detection = mutation_state != STABLE or any finding.

## 8/9 CAUGHT, 1 MISSED, 0 skipped

| TTP | ATT&CK | Verdict | mutation_state | findings | review |
|---|---|---|---|---|---|
| write_on_readonly | T1565.001 | CAUGHT | MUTATED | HASH_MUTATED | PASS |
| delete_in_window | T1070.004 | CAUGHT | MUTATED | HASH_MUTATED | PASS |
| timestomp_content_tamper | T1070.006 | CAUGHT | MUTATED | HASH_MUTATED | PASS |
| hardlink_alias_mutation | T1547/alias | CAUGHT | MUTATED | HASH_MUTATED | QUARANTINE |
| junction_path_redirection | T1547.009 | CAUGHT | MUTATED | HASH_MUTATED | PASS |
| ads_stream_smuggling | T1564.004+T1070.006 | CAUGHT | MUTATED | HASH_MUTATED | PASS |
| atomic_rename_swap | T1036/masquerade | CAUGHT | MUTATED | HASH_MUTATED | PASS |
| transient_blindspot_file | snapshot-gap | **MISSED** | STABLE |  | PASS |
| compound_chain | multi | CAUGHT | MUTATED | HASH_MUTATED | QUARANTINE |

### Honest gaps (MISSED)

- **transient_blindspot_file** (snapshot-gap)
