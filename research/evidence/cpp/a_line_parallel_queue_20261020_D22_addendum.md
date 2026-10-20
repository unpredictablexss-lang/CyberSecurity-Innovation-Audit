# A-line parallel queue addendum — D22

This additive task entry records the current-source replay of CVE-2025-26690. It does not revise the original A0 candidate ID or the historical source ledger.

### D22 — dSoftBus null-dereference source replay (development/replay)

```text
Role: A-line C/C++ static detector replay owner.
Continuous goal: bind the disclosed dSoftBus allocation-failure root to exact vulnerable/fixed objects and establish current null-dereference candidate behavior without treating partial semantic coverage as complete.
Inputs: A0 source ledger commits for CVE-2025-26690; current CLI and null_dereference v0.6.0; exact communication_dsoftbus Git objects.
Steps: verify commit/tree/blob/raw SHA; replay the vulnerable and exact fixed object; compare candidate lines to the guard patch; preserve parse and detector coverage separately; run positive/fixed/safe/unrelated/partial mechanism controls; record product-context blockers.
Done when: source-bound current CLI outputs, rule identity, candidate/fixed differential, exact commands, and remaining semantic/product limits are reproducible; change scope and diff checks pass.
Boundaries: do not rewrite historical raw evidence, treat an unassessed candidate as a confirmed vulnerability, infer safety from zero fixed findings, or change shared Catalog/API/parser.
```

D22 completed with no detector change. The exact vulnerable object produced five candidates at lines 71, 82, 97, 108, and 123; the exact fixed object produced zero same-rule candidates. Both source files parse completely, but detector semantic coverage is `partial/blocked` (0/1 semantically complete), so the case remains **PARTIAL**. No product build, runtime allocation-failure test, dSoftBus-specific safe/unrelated source controls, caller reachability, or impact evidence was established. See [D22 replay report](d22_cve_2025_26690_upstream_object_replay_20261020.md) and [machine-readable source identities](d22_cve_2025_26690_upstream_object_replay_20261020.json).
