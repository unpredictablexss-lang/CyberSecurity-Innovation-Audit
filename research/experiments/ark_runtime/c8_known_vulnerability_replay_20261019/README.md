# AC-REPLAY-02 pinned replay audit and C3/C4/C8 reconciliation

## Scope and pinned identities

This slice audits, but does not recreate, the pinned artifacts from `origin/codex/c-line-ark-runtime-replay-20261019`.

- Review commit: `a7962043cda3cbb99f79ada7418508709fc951ca`, tree `684c42e94c4797640113f0f2ffeca5a0c988a136`.
- History replay directory tree: `699be8e43ea0413255250202930672c8bca9ca6f`.
- Frontend holdout tree: `28711cdedf2fd15347ec7604d1b5d5651af1e02a`.
- Runtime-core holdout tree: `128564f9b1edd34ec98fd25284e9ece2a9e72556`.
- Local work base: `7af25f5ced471e5d6acc8cf5efd4c696275ce940`, tree `11f53fe00d79d477c383e7e9b49ad3b1adcae86c`.
- C8 reconciliation input tree: `a0b1de2277566e490fabd527e5b5fefd94f5d22e`.

All reads used local pinned Git objects with `GIT_NO_LAZY_FETCH=1` and `GIT_ALLOW_PROTOCOL=''`. No fetch, checkout, reset, push, public contract, Runner or Catalog change was performed.

## Audit result

`AC-REPLAY-02` is **partially satisfied**.

| AC-REPLAY-02 control | Result | Boundary |
|---|---|---|
| vulnerable hit | not satisfied | `typedarray_parent` blob bytes are verified, but the frozen 0.3.1 implementation and commit/tree proof were unavailable; no detector result was emitted. |
| fixed miss | not satisfied | `typedarray_fix` was also blocked. Under the frozen rule the preserved patch makes the expected fixed result `unknown`, not a miss. The C4 guard-fix pair is not covered by this replay. |
| safe control | not satisfied | `safe_Set_control` remained blocked and was not run. |
| unrelated control | disposition satisfied | `Map` stayed `not_analyzed` because it is outside the frozen caller profiles. This is non-applicability, not safety. |
| unknown | status preservation satisfied | blocked/unknown was not converted to safe or miss; the six C3 and C4 unknown cases were not algorithmically replayed. |
| missing-object fail-closed | satisfied | Missing commit/tree and frozen code remained blockers. Source blob-byte checks were kept separate and did not count as detector passes. |

`skip/error/blocked/not_analyzed` are not counted as pass. `validated_vulnerability=0`. No Precision/Recall or zero FP/FN claim is eligible.

## Declared hash-manifest defect

The pinned Git object identities and directory trees match. The sidecar correctly hashes `hash-manifest.json`, but two declared file digests do not match the pinned bytes:

- `research/experiments/ark-runtime-history-replay-20261018/README.md`: declared `02ede663...d8d8d`, pinned bytes `91b2bf44...fdb7a`.
- `docs/项目现状与下一步.md`: declared `e358abe6...22df`, pinned bytes `8af3cbfb...b92c`.

Therefore `declared_hash_manifest_passed=false`. This is an artifact provenance defect, not a detector result. The review commit and trees remain fixed and auditable.

## C3/C4/C8 reconciliation

`finding_rule_control_reconciliation.json` maps all 12 C8 findings to detector/rule/control/source identity:

- Six C3 type-origin counterexample source SHA-256 values match `expected-regressions.json`, but the pinned replay did not execute them. They remain `blocked_not_replayed`, never pass.
- C4 Filter/Map/ToReversed/order entries map to `ark.runtime.typedarray-allocation-exception-guard` controls, but the pinned replay is TypeSafety 0.3.1 plus a separate exception-propagation probe. These entries remain `blocked_not_replayed`.
- C7 dependency/replay limitations receive only substitute fail-closed evidence from the pinned replay. The referenced C7 directories remain missing.

## Holdout and patches

The two pinned packets contain 41 reviewer rows and 0 nonempty labels. They are coverage/development frames, not independent truth. The runtime-core packet explicitly says `counts_as_independent_holdout=false`; the frontend packet is a clustered applicability/false-match frame. Metrics remain ineligible.

Two exact pinned patches were reviewed and hashed, with no new patch fabricated:

- `type-origin-parent-fix.patch` is the minimal receiver-token to result-type-token repair. Its new type read precedes pending-exception handling, which explains why frozen 0.3.1 expects `unknown`, not fixed miss.
- `exception-parent-fix.patch` belongs to the separate slowpath exception-propagation probe and is not combined with C4.

## Verification

Exact commands, environment and outcomes are in `run-manifest.json` and `verification-manifest.json`.

- Pinned audit: exit 0, wall `2.696s`, peak RSS `20520 KiB`.
- Focused static reconciliation test: 5 tests passed in `0.126s`, peak RSS `16616 KiB`, after correcting a test-only `ROOT.parents[4]` path error to `parents[3]`.
- `py_compile`, six output JSON parses and `git diff --check` passed.
- No Ark detector unittest or historical detector replay was rerun. The sibling 68-test result is not restated as this environment's result.

Earlier pre-pivot fixture drafts under `fixtures/` are retained for dirty-worktree transparency but are excluded from this audit and must not be used as replay evidence.

## Continuing dependencies

See `continuation_dependencies.json`. The blocking items are the byte-identical frozen 0.3.1 implementation (or a new versioned freeze), Ark historical commit/tree/dependency objects, C7 ledgers, a frozen replay that actually covers C3/C4 controls, independent labels, and product/runtime impact evidence. Alias merge, cross-function effect summaries, macro/cross-TU binding and ToReversed semantics remain later algorithm slices after replay provenance closes.
