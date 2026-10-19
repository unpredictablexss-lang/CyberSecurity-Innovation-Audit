# A-line parallel queue addendum — D26

### D26 — Preferences CR-0020–CR-0021 shared_ptr race detector replay

```text
Role: A-line C/C++ shared_ptr race detector developer.
Continuous goal: identify and fix only source-backed generic rule gaps observable through the production M2 CLI, preserving evidence limits and original A0 states.
Inputs: frozen A0 CR-0020–CR-0021 rows; exact Preferences commit/tree/blob/SHA; shared_ptr_race production CLI adapter and current rule.
Steps: independently verify source identity; replay target header and bounded implementation files via the CLI; trace same-object writes, reads, synchronization, lifetime and build context; keep candidate regression disposition separate from case disposition.
Done when: a reproducible narrow production-path gap is fixed with bounded controls and replay, or a no-change report records exact identities, CLI results, source review, parser coverage and remaining evidence obligations.
Boundaries: no file/CVE/repository hardcoding; no shared parser/API/Catalog/A0 edits; no race or safety claim from syntax candidates or zero findings; retain queue statuses.
```

D26 completed with **no detector change**. The production M2 CLI detects both exact header candidates (line 37 write, line 42 read), also when both concrete N-API implementation files are in scope. All three selected files parse complete. The source does not prove unsynchronized overlap on one live proxy, so both queue rows remain `not_testable / paused_pending_evidence`.

See the [source-bound report](d26_preferences_shared_ptr_replay_20261020.md), [raw header replay](d26_preferences_header_20261020.json), [bounded replay](d26_preferences_bounded_20261020.json), and [verifier](verify_d26_preferences_race.py).
