# A-line parallel queue addendum — D25

### D25 — DataShare CR-0013–CR-0015 shared_ptr race detector replay

```text
Role: A-line C/C++ shared_ptr race detector developer.
Continuous goal: identify and fix only source-backed generic rule gaps observable through the production M2 CLI, preserving evidence limits and original queue states.
Inputs: frozen A0 CR-0013–CR-0015 rows; exact DataShare commit/tree/blob/SHA; shared_ptr_race production CLI adapter and current rule.
Steps: independently verify source identity; replay target header and bounded implementation/queue files via the CLI; trace member initialization, later writes, reads, synchronization and the limits of thread/lifetime evidence; keep candidate regression disposition separate from case disposition.
Done when: a reproducible narrow production-path gap is fixed with controls and replay, or a no-change report records exact identities, CLI results, source review, parser coverage and remaining evidence obligations.
Boundaries: no file/CVE/repository hardcoding; no shared parser/API/Catalog/A0 edits; no race or safety claim from syntax candidates or zero findings; retain queue statuses.
```

D25 completed with **no detector change**. The current CLI finds the CR-0013 and CR-0015 `uvQueue_` constructor assignments at their exact lines; it does not emit the CR-0014 `extension_` constructor initializer as a candidate. No later assignment to either field was found in the bounded source search. This does not prove absence of a race because object publication, concurrent destruction, product build and thread scheduling remain unbound. All three rows remain `not_testable / paused_pending_evidence`.

The exact source identities, two production-path JSON replays, source access review and reproduction commands are in the [D25 report](d25_datashare_cr0013_15_replay_20261020.md). The [verifier](d25_datashare_cr0013_15_replay_20261020.py) checks the frozen queue rows and Git object identities without changing the queue.
