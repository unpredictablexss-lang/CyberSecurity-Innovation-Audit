# D64: retain Pasteboard route candidates when guard provenance is unknown

## Scope and lineage

D64 follows frozen D63 commit `c2447a0449ba90622ee77ddc5434e282f28fb7db`. T63 acceptance commit `c593be5543d5e6c28d7bc97fa50df3a8ae2f516f` showed that a permission token indexed through arbitrary identifiers such as `untrustedState[...]` or `bluetoothResult[...]` still suppressed the D52 candidate. Identifier and token spelling cannot establish that a value came from an authoritative Pasteboard permission API.

D64 therefore removes permission-guard suppression from this local matcher. It retains the narrow candidate route: Binder `GET_PASTE_DATA` mapping, `OnRemoteRequest` dispatch, and an `OnGetPasteData` handler that reads and returns Pasteboard data. When that route matches, it adds a structured `permission_guard` evidence obligation with status `unknown`. No variable-name allowlist or helper-name heuristic is used to claim guard provenance.

The detector version is `0.19.8`. D59, D61, and D63 frozen commits remain unchanged. CVE identity and sibling detector identities are unchanged.

## Validation

The focused suite passed: `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` (32 tests). Tests now confirm candidate retention and `permission_guard=unknown` for `untrustedState[READ_PASTEBOARD]`, `bluetoothResult[PERMISSION_READ_PASTEBOARD]`, the D63 helper examples, unrelated permission checks, and the existing ordering/dead/mixed/post-read controls. The route's fixed and safe fixtures retain the source candidate because this matcher cannot resolve their guard provenance. Other corpus controls remain unchanged.

`git diff --check` passed. T64 independent review is pending.

## Limits

This is a source-only candidate. The route shape does not establish CVE causality, product identity, product inclusion, attacker reachability, runtime behavior, or vulnerability status. The permission guard remains explicitly unknown until a downstream review can resolve the actual permission API and value provenance and show denial dominates the read. This rule performs no CFG, dataflow, interprocedural, alias, or API-contract proof and does not classify product safety.
