# C10 Ark Runtime latest semantics consolidation

## Scope and provenance

- Checkout: `E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019`
- Baseline: `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457`
- Baseline tree: `d15b91627c94d9c3043d7d58d47fcf9af7e42454`
- Remote: `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- Pinned C-line review: `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`, tree `307ac8237263db793028e0bf34a82a85f60821a5`
- No commit, push, merge, reset, checkout or fetch was executed.
- The integration dirty repair remains preserved. C10 did not modify `contracts`, Runner, Catalog, `known_cves`, `receiver_guard.py`, `runtime_ir.py`, `syntax.py`, `size_overflow.py`, or the pre-existing dirty `tests/detectors/test_known_disclosed_cves.py`.

Exact source/blob/SHA-256 records are in `source-hashes.json`. The scoped patch is `minimal.patch`, SHA-256 `ec19c64836b08569587762b8aa7678028395c81ab6fd612ebfbb91d513980dd2`.

## Semantic fixes

1. `type_origin.py` now invalidates old type/HClass facts for global unknown calls and unknown member calls. A local unescaped fresh allocation may retain identity and a candidate distinct-origin obligation, but an old token never proves current type equality after an unknown effect.
2. By-value calls preserve C++ binding but do not revalidate previously sampled type facts. Only reviewed type-stable operations preserve type identity. Passing a fresh result to a callback invalidates its sampled type.
3. Stale token equality cannot create a same-type proof. Fresh samples after an effect can establish a new local relation; old copies remain stale.
4. Exact builder receiver summaries are required. `builder.SetParameters` and `BuiltinsArrayStubBuilder::GetTaggedValueWithElementsKind` are accepted only with the reviewed receiver; `foreign.*` stays unknown.
5. Assignment, compound declaration/assignment, `tag++`, `++tag`, assignment nested in `Int32Add`, `output=input`, branch-condition assignment, indirect/reference writes and unmodelled host effects fail closed as unknown. They cannot leave an old token live.
6. `has_type_origin_flow` now recognizes both `StoreTypedArrayElement` and `FastSetPropertyByIndex`, plus `NewTypedArraySameType`, so the CVE-2025-24304 Map parent and exact fixed shape are both inspected instead of silently falling out of the semantic selector.
7. `_verified_generated_branch_owners` and generated callback-path analysis were recovered from the local C9 exception-guard evidence (`b2f1cc42f449d6f4c77020b003a1f7c0cbdd0e86`) and adapted to the pinned `FunctionSyntax` API. The contract admits only the exact `StubBuilder::Branch` true/false mapping and a non-overriding derived owner. Missing/wrong contracts remain unknown.

## Known-case controls

All controls are self-authored source-bound fixtures, not independent labels or product vulnerability proof.

| Root shape | Positive parent | Fixed/safe control | Unrelated | Unknown control |
|---|---|---|---|---|
| CVE-2025-24304 / Map species-sensitive result type origin | candidate | fixed `NewTypedArraySameType` matched, no same-root candidate | not analyzed | unknown after global effect |
| IBS5YG / Filter result type origin | candidate | fixed `NewTypedArraySameType` matched, no same-root candidate | not analyzed | old output token after global effect is unknown |
| C3 old-token counterexamples | candidate only before effect | fresh post-effect token can match locally | not analyzed | assignment/update/nested effect forms remain unknown |

The matrix is implemented in `tests/detectors/ark_runtime/test_c10_known_case_controls.py` and `tests/detectors/ark_runtime/fixtures/c10_semantics/`. `safe_same_type.cpp` is a local matched control only; it is explicitly not a safe/security verdict.

## Verification

Windows and WSL used the same explicit subprocess environment contract. Full argv, cwd, exact environment, exit code, wall time, stdout and stderr are recorded in `check-records-win.json`, `check-records-wsl.json`, `logs-win/` and `logs-wsl/`.

| Check | Windows | WSL | Interpretation |
|---|---:|---:|---|
| `tests.detectors.test_known_disclosed_cves` | 21 pass | 21 run, 2 errors | Windows passes; WSL Git resolves the worktree `.git` file as a Windows absolute path and cannot read pinned fixture blobs. This pre-existing cross-shell issue is outside C10 and is not a pass |
| Ark discover | 151 pass, 3 skipped | 151 pass, 3 skipped | Latest Ark suite is runnable |
| `test_type_origin` | 27 pass | 27 pass | Type-origin focused suite |
| `test_c3_mechanisms` | 29 pass | 29 pass | Includes tag++, ++tag, nested `Int32Add`, compound/branch writes and stale-token controls |
| `test_runtime_exception` | 35 pass | 35 pass | Generated branch contract and exception-order controls |
| `test_receiver_guard` | 4 pass, 1 skipped | 4 pass, 1 skipped | Historical exact pair skipped without pinned Ark store |
| `test_exception_guard` | 11 pass, 1 skipped | 11 pass, 1 skipped | Historical exact pair skipped without pinned Ark store |
| C10 known-case matrix | 2 pass | 2 pass | Positive/fixed/safe/unrelated/unknown controls |

Skips require pinned official Ark Git stores and are not passes. No zero-FP/FN or Precision/Recall claim is made.

## Remaining unknowns and migration boundary

- The CVE-2025-24304 to `!11130` mapping remains a strong inference, not a verified one-to-one source binding.
- C10 proves local rule behavior on source-bound controls. It does not provide a product build, real entry/privilege chain, attacker control, CIA impact, runtime PoC or fixed-product retest.
- Full official Ark parent/fixed replays must be rerun from pinned Git objects through the production adapter. Current historical exact tests are skipped because the Ark Git stores are not supplied.
- C10 does not compute independent accuracy. Candidate remains candidate/unassessed; unknown/partial/blocked/zero findings are not safe.
- Latest `analysis.py` remains fail-closed on unsupported host writes. The model is still function-local and is not a whole-program type/CFG/alias proof.
- The recovered generated-branch implementation is semantically tested against the pinned local syntax API; future syntax.py/owner-model changes require a compatibility test before migration.
- WSL known_disclosed_cves remains blocked by the worktree .git file containing a Windows absolute path; Windows execution passes. The pre-existing dirty test was not modified in C10.
- The old C8 `type_origin.py` patch must not be applied verbatim: latest tests intentionally retain G11/two-stale cases as candidate while rejecting stale-token equality.

## Next minimal slice

1. Pin and hash the exact official Ark parent/fixed Git objects for CVE-2025-24304 and IBS5YG; replay through `ArkRuntimeTypeSafetyDetector` and retain source-bound 1->0 root-specific results.
2. Add an independently reviewed holdout with positive/fixed/safe/unrelated/unknown labels split by root lineage. Freeze detector/model before scoring.
3. Expand C++ effect summaries from visible declarations only; add mutation tests proving that old type facts cannot be revived across unknown effects.
4. Build an authorized isolated runtime harness only after product/build/entry/impact bindings exist; revalidate fixes and record performance separately.

## Parallel follow-up lines and continuous goals

### C11-ARK-REAL-PIN-REPLAY

Vibe prompt: "You are a source-provenance replay engineer. Work only from locally pinned Ark Git objects. Bind commit/tree/blob/source SHA, detector/model version and scope before every run. Replay CVE-2025-24304 Map and IBS5YG Filter exact parent/fixed pairs through the production detector, preserve positive/fixed/safe/unrelated/unknown controls, and never convert partial or zero findings into safety. Continuous goal: maintain a reproducible root-specific parent->fixed evidence matrix with exact commands and hashes."

### C12-ARK-EFFECT-SSA

Vibe prompt: "You are a bounded C++ effect/SSA semantics engineer. Extend the Ark local model only from reviewed declarations. Prove with mutation tests that assignment, compound writes, update expressions, nested assignments, reference/pointer aliases, unknown global effects and callback escapes cannot revive stale type tokens. Continuous goal: every unsupported effect fails closed to unknown while valid local candidates survive independently."

### C13-ARK-EXCEPTION-CFG

Vibe prompt: "You are an exception-order and generated-CFG engineer. Verify `StubBuilder::Branch` contracts from exact source bodies and inheritance, including overrides and true/false edge mapping. Keep callback result conversion before pending-exception checks as candidate and exact dominating guards as fixed controls. Continuous goal: no branch spelling, macro name or generated label is trusted without source contract evidence."

### C14-ARK-EVIDENCE-ACCEPTANCE

Vibe prompt: "You are an evidence-gate and evaluation engineer. Build an independent labelled holdout split by root/commit lineage, freeze rules before scoring, record coverage/partial/unknown separately, and calculate Precision/Recall only on reliable labels. Continuous goal: every result remains source-bound and auditable, with limitations and negative controls preserved."

