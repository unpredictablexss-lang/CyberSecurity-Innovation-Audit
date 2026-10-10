# cpp.lifetime evidence review record (2026-10-09)

## 1. Scope and baseline

- Workspace: `C:\Users\work_work\.codex\worktrees\393f\CyberSecurity-Innovation-Audit`
- Local branch: `codex/teammate-a-cpp-detectors-393f`
- Intended remote branch for owner review: `codex/teammate-a-cpp-detectors`
- Base before this evidence-chain round: `3914a09 tests: bound auto shadowing scopes`
- Scope: `cpp.lifetime` source-bound review evidence only. No bounds, null-deref,
  double-free, CFG or taint capability was added.

## 2. Result semantics reviewed

- Detector findings remain `assessment=candidate` and `review_status=unassessed`.
- `completed` means only that the selected compatible source units were analyzed.
  It is not a safe result, and empty findings are not a safety result.
- `partial`, `failed`, `blocked`, `not_run`, timeout and detector exception remain
  unknown or incomplete coverage. They are not assigned as misses.
- A source unit with no matching language is `not_applicable`, not a miss.
- `vulnerable`, `fixed`, `unrelated`, `safe`, `unknown` and `not_applicable`
  evidence groups are separate runs and cannot be mixed by the review sidecar.
- Every candidate binding records real source path, line, column, `rule_id`,
  `evidence_type`, symbol and source SHA-256, plus a deterministic binding ID.
- `benchmark_outcome` is always `not_assigned` in this local review sidecar.

## 3. Pinned coverage and failure status

| Group / boundary | Pinned or tested evidence | Status |
|---|---|---|
| vulnerable development | 3 complete synthetic units | 3 candidate shapes in each ablation mode |
| fixed | `fixed_alias_rebind.cpp` | base=1, alias-liveness=0, final=0 |
| similar safe controls | `safe_use_before_reset.cpp`, `safe_shadowed_scope_bindings.cpp` | selected scope completed, 0 candidate shapes |
| lexical binding / shadowing | pointer and `auto` shadow, scoped shadow, use-before-shadow regressions | deterministic tests passed |
| partial parse | `partial_parse_macro_context.cpp` | `blocked`, unknown |
| failed parse | `failed_parse_unbalanced.cpp` | `blocked`, unknown |
| not run | `not_run_parse_pending.cpp` | `blocked`, unknown |
| missing symbol | `missing_symbol_unresolved_alias.cpp` | `blocked`, `unknown_unresolved_rule_symbols` |
| incomplete scope | `incomplete_scope_unmodeled_owner.cpp` | `blocked`, `unknown_incomplete_analysis` |
| no matching language | `unsupported_language_note.js` | no analyzed file, `not_applicable_no_matching_language` |
| exception / abnormal input | runner crash, timeout and invalid-input tests; review line/column and metadata tamper tests | failure is isolated or input is rejected, never a miss |

Lifetime slice final counts:

- `vulnerable`: 3 units; base=3, alias-liveness=3, sync=3; each mode `completed`.
- `fixed`: 1 unit; base=1, alias-liveness=0, sync=0; each mode `completed`.
- `safe`: 2 units; all modes 0 and `completed` for the selected scope only.
- `unknown`: 5 units; all modes 0 and `blocked`.
- `not_applicable`: 1 unit; all modes 0 and `blocked`, with no analyzed C++ file.

The separate bounds research slice completed with 5 observations:
base source/sink candidate shapes=2; plus guard shape candidate shapes=1.
This is research-only compatibility verification and is not part of the
`cpp.lifetime` review population.

## 4. Reproducible commands and results

The host is Windows and native `python` is unavailable. Commands were therefore
run through WSL Ubuntu 22.04 with `python3`; module arguments are identical to
the requested `python -m ...` commands.

1. Requested: `python -m unittest discover -s tests -v`
   Actual: `python3 -m unittest discover -s tests -v`
   Result: `Ran 232 tests in 17.425s`, `OK`.
2. Requested: `python -m unittest tests.detectors.test_cpp_lifetime_detector -v`
   Actual: `python3 -m unittest tests.detectors.test_cpp_lifetime_detector -v`
   Result: `Ran 19 tests in 4.480s`, `OK`.
3. Requested: `python -m research.experiments.cpp.lifetime_sync_slice`
   Actual: `python3 -m research.experiments.cpp.lifetime_sync_slice`
   Result: exit 0; evidence groups remained separate and used the counts above.
4. Requested: `python -m research.experiments.cpp.bounds_length_parcel_slice`
   Actual: `python3 -m research.experiments.cpp.bounds_length_parcel_slice`
   Result: exit 0; research-only observations listed above.

Additional focused verification:
`python3 -m unittest tests.detectors.test_cpp_lifetime_detector tests.detectors.test_cpp_lifetime_review_evidence tests.detectors.test_cpp_research_slices tests.detectors.test_cpp_runner_integration -v`
returned `Ran 47 tests in 11.666s`, `OK` after the final semantic fixes.

Raw logs are stored under ignored `outputs/logs/` and are not commit inputs.

## 5. Artifact hashes

- Fixture manifest bytes SHA-256:
  `7cad65cca52f3f684a064db276f0bb6251987278c9d6b306c457dce3b5da06fa`
- Fixture snapshot digest stored in the manifest:
  `cf301aa06fc5ff93c15758ba4f62a04f6f85cd1a2dd28e8261b879816f24a06c`
- `lifetime_detector.py` SHA-256:
  `b543bb2075459149e2bc8c4f2949758c2cf64adb1ff8d40acca21474bff11757`
- `lifetime_review.py` SHA-256:
  `044e2b901a798b257271090745a8bb7148fe1823d09c9fd2532463dc7da3ec22`
- Method card SHA-256:
  `4a3c6ae9cf12cb5e5b6ea9cf7b9519b60f3b923239c15208b8aac7b4f5ecda47`
- Holdout plan SHA-256:
  `90d2cde4e265ebed9ce169327958fcc1fde405c2d0f75b93bb6a51b5c6783b2b`
- Contract Change Request SHA-256:
  `d4ca449e090e4644ef32b2fe6f78923e605593242f06fef481d0e53821ce27ad`
- Final raw-log SHA-256 values:
  - full suite `5427b4402c91c4b4b1c1eb68e9b086c5edb63f7e5199fa47d39d78d4a65654b7`
  - focused detector `970c0a6f18b3e600363855c3dc062841de6cc29ecec64153ca37133e4d91d6a1`
  - lifetime slice `64602201864329c0d6fa8805bfe24bd0069e23468a66e474506e2698a196f864`
  - bounds slice `2eaa4f95f1a06cb983eb7a56eb276e12c31568b08d771aabdbca7e39e5f7ee71`

Per-file fixture source SHA-256 values remain pinned in
`tests/detectors/fixtures/cpp_lifetime/manifest.json`.

## 6. Package consistency

- The method card now names the exact narrow syntax shape and distinguishes
  necessary rule facts from facts that do not prove reachability, timing or impact.
- The holdout plan isolates development and future holdout by
  `root_cause_instance_id`, freezes labels access, and requires source-bound runs.
- Regression tests cover evidence-class mixing, source-hash staleness, binding-ID
  edits, location tampering, language selection and incomplete-run semantics.
- The public `src/ohscanner/contracts.py` was not changed. The source-hash field
  gap is documented in
  `docs/contracts/ohscanner_detector_contract_v1_cpp_lifetime_source_binding_ccr.md`.
- The detector, sidecar, fixture loader, research slice, method card and tests are
  one reviewable evidence-chain change. Generated logs stay outside the commit.

## 7. Limitations and absent validation

- All pinned sources are self-authored synthetic development fixtures, not real
  OpenHarmony repository samples.
- The independent holdout has not been collected, frozen or run.
- There is no product build or runtime validation for this detector line.
- Macro expansion, templates, lambdas, complex declarators, cross-function
  transfers, CFG dominance, exception paths and concurrency are not fully modeled.
- Public result schemas do not yet carry a source hash on each diagnostic; the
  local review sidecar and CCR cover that gap for review only.
- No accuracy metric or generalized safety conclusion is supported by this work.
