# A-line parallel queue addendum — T62

### T62 — dSoftBus CVE-2025-26690 independent static replay acceptance

```text
Role: independent A-line static regression acceptance.
Continuous goal: independently replay source-bound null-dereference cases and keep A0 identities/states immutable.
Inputs: D22 exact communication_dsoftbus vulnerable/fixed objects; current CLI and null_dereference detector; frozen A0 queue.
Steps: validate commit/tree/blob/raw source hashes; rerun both variants in this independent scanner worktree; compare finding locations, parsing and detector coverage; verify fixed patch guards; run mechanism controls and inspect safe/unrelated control availability; reconcile A0 and prior case status.
Completion: independent results, machine JSON, reproducible verifier and remaining evidence blockers are committed.
Boundaries: do not alter detector, fixtures, A0 queue, or development disposition; no candidate is promoted to a confirmed vulnerability.
```

T62 reran the pinned pair from a separate scanner worktree and reproduced five candidates at lines 71, 82, 97, 108, and 123 in the vulnerable file and zero same-rule candidates in the fixed file. Both target files parse completely, while the detector remains `blocked` with `partial` semantic coverage (0/1 complete) in both runs. The upstream commit objects, trees, path blobs, and raw source hashes match D22; the fixed commit is a descendant of the vulnerable commit and its patch inserts a null check at each of the five candidate sites.

The object store contains Git `FETCH_HEAD` entries naming `https://gitcode.com/openharmony/communication_dsoftbus` for both full commit IDs. This independently verifies the local Git object graph and fetch record, but does not provide a signed provenance attestation. The fixed commit is a source-backed comparison; safe/unrelated controls are limited to the detector's mechanism fixtures/tests and are not dSoftBus source controls. The 21 focused detector tests pass.

Disposition remains **PARTIAL/BLOCK**. This case is a historical case in `matrix.json`, not one of the 345 A0 candidate rows; T62 verified that all 345 A0 candidate IDs and original/queue states remain intact. Required for full closure: a product build profile and compilation context; independently bound dSoftBus safe and unrelated source controls; detector semantic coverage sufficient to resolve guards/dominance; and evidence for caller reachability, allocation-failure trigger, and concrete impact. A target-derived allocation-failure test is needed before claiming runtime reproduction. Zero fixed findings is not a safety conclusion.

See [independent report](t62_dsoftbus_cve_2025_26690_independent_acceptance_20261020.md), [machine results](t62_dsoftbus_cve_2025_26690_independent_acceptance_20261020.json), [verifier](verify_t62_dsoftbus_cve_2025_26690.py), and the captured [vulnerable](a_static_baseline_20261019/t62-cve-2025-26690-vulnerable.json) / [fixed](a_static_baseline_20261019/t62-cve-2025-26690-fixed.json) CLI outputs.
