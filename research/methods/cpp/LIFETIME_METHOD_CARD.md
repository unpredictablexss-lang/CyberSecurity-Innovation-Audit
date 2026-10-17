# C/C++ unique_ptr raw-alias lifetime method card v0.4

> Current contracts and status authority remain `docs/架构与公共协议.md` and
> `docs/项目现状与下一步.md`. This card describes the narrow detector method and
> its controlled PoC; it is not a whole-program lifetime proof.

## Identity

- Detector: `ohscanner.cpp.lifetime`, version `0.4.0`. Rule ID remains stable.
- Rule: `ohcpp-lifetime-unique-raw-alias-reset-001` (stable historical rule ID).
- Candidate CWE: CWE-416. Output remains syntax-level `candidate/unassessed`.

## Expanded invalidation model

For a same-function explicit `std::unique_ptr<T>` owner and a raw alias created
with `owner.get()` (directly, by later local assignment, or through a simple
same-function alias chain), the detector records these owner lifetime changes:

- `owner.reset(...)`;
- owner assignment, including `owner = nullptr` and replacement by a new object;
- `std::move` transfer out of the owner.

Move semantics are scope-sensitive. A raw alias can remain valid while the
destination owner is alive. The detector requires the destination owner's
lexical scope to end before the later alias use; immediate use while the
destination remains alive is not promoted by this rule.

The v0.4 bounded CFG view rejects a reset/use pair only when the two positions are
in the explicit `if` and `else` bodies of the same statement. A use outside the
owner's lexical binding scope is treated as an owner-scope-end invalidation when
the raw alias binding itself outlives that owner. Other reachability questions
remain unknown.

Unconditional straight-line `alias = owner.get()` rebinding remains a narrow
suppression. Conditional rebinding, loops, early returns, exceptions, destructor
timing, escapes and cross-function transfers remain unknown.

## Evidence gate

A finding does not prove UAF, attacker control, a real entry boundary, CIA
impact or exploitability. Promotion still requires reachable sensitive
operation, trigger conditions and concrete impact evidence.

## Failure-to-pass record

- Failure gate: `27` lifetime tests with `4` failures for version and missing
  null/replacement/move invalidation coverage.
- Expanded detector regression: `27/27` passed.
- PoC contract tests: `5/5` passed.
- Final close-out suite after detector/PoC evidence checks: `577` executed, `569`
  passed and `8` skipped. The implementation-bound control replay is separately
  source-hash bound and does not turn these regression counts into benchmark data.
- v0.4 failure-to-pass additions: local `alias = owner.get()`, a simple alias chain,
  explicit `if`/`else` branch exclusion, owner scope end and an owner-still-alive
  control. Lifetime detector unit gate `32/32`; combined detector unit gate `71/71`;
  combined detector/PoC gate: `117` tests, `109` passed and `8` skipped.

## Controlled PoC

`src/ohscanner/poc/cpp_lifetime_uaf.py` and
`src/ohscanner/poc/harnesses/cpp_lifetime_unique_ptr_alias/` execute a
hash-bound self-authored workload under AddressSanitizer.

Historical run-004 remains unchanged. The v0.4 rerun is summarized in
`research/evidence/cpp/detector_enhancement_20261015/evidence.json`; raw local
build/runtime artifacts remain under
`outputs/poc/detector-enhancement-20261015/lifetime/` and are not committed.

| variant | detector boundary | ASan result |
|---|---|---|
| `reset_vulnerable` | `owner.reset()` | `3/3` triggered |
| `null_assignment_vulnerable` | `owner = nullptr` | `3/3` triggered |
| `replacement_vulnerable` | owner replacement | `3/3` triggered |
| `move_transfer_vulnerable` | move + destination scope end | `3/3` triggered |
| `fixed_rebind` | unconditional alias rebind | `3/3` clean |
| `safe_use_before_reset` | use precedes invalidation | `3/3` clean |

The 2026-10-15 v0.4 rerun reproduced all four ASan invalidation variants `3/3`
and both controls clean `3/3`. `validated_vulnerability=0`; this is controlled
self-authored dynamic evidence, not a real product vulnerability result.

## Remaining unknowns

- Full CFG dominance, loops, early returns, exceptions and destructor timing. Only explicit sibling `if`/`else` exclusion is modeled.
- Cross-function alias escape/transfer, pointer/reference alias graphs and member aliases.
- Member aliases, pointer/reference aliasing and templates/macros.
- Real OpenHarmony entry/privilege boundaries and product builds.
- No Precision/Recall claim is made from these authored controls.
## Four-class development controls (2026-10-15)

- Control package: `research/tests/cpp_detector_controls/manifest.json`,
  SHA-256 `8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`.
- The lifetime slice contains 4 vulnerable, 4 fixed, 3 safe and 1 unrelated
  source-bound controls. It covers reset, owner null assignment, owner
  replacement, restricted `std::move` transfer, raw aliases, stable owner
  pointers, scope shadowing, comment/literal false positives and unrelated raw
  pointers.
- Each source binds a repository-relative path, byte count, SHA-256 and Git blob
  SHA-1. The combined control snapshot is
  `d4333621872fcd3d135d08b95fae32d4d7035fc88735bcf90a36236a255d28b7`.
- Every fixed control applies a concrete `authored_control_remediation_patch`
  with `patch -p1 --fuzz=0`; patched bytes must exactly match the fixed source
  hash. These patch artifacts are executable remediation controls, not claimed
  upstream OpenHarmony patches.
- Detector regression observed one candidate for each vulnerable invalidation
  shape and zero findings for all fixed/safe/unrelated controls. Zero findings
  remain negative controls only and are not benchmark misses or safety proof.
- Native ASan validation built every control with clang++ 14.0.0 and executed
  every control three times under `setarch x86_64 -R`: vulnerable controls were
  `3/3` sanitizer-triggered and fixed/safe/unrelated controls were `3/3` clean.
- Final evidence: `research/evidence/cpp/four_class_controls/run-005/results.json`
  (SHA-256 `0f51c32d160de44c0dc0acc694f0c80f6ea301831bb03969718f6d688fb38174`)
  and `results.md` (SHA-256
  `4d5fadf81107c6a6529993e3e02fb24387eabcbcbeaddcc2f7195c24847210c7`).
- Exact replay:
  `.venv-web/bin/python research/experiments/cpp/run_four_class_controls.py --output research/evidence/cpp/four_class_controls/run-next --work-dir outputs/poc/cpp-four-class-controls-20261015/run-next --compiler clang++ --repeats 3`.
- Version caveat: the requested control baseline is `0.3.0`, while the dirty
  worktree observed `0.4.0` during execution. The evidence records both values
  and does not relabel the observed worktree as the baseline.
- Synthetic controls are not independent labelled data; no Precision/Recall,
  product reachability, attacker control or CIA impact claim is made.
## Implementation-bound control package rerun (2026-10-15)

The old baseline package remains unchanged at `research/tests/cpp_detector_controls/manifest.json`
(SHA-256 `8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`) with baseline
versions `0.4.0` / `0.3.0`. This rerun uses the separate implementation-bound package
`research/tests/cpp_detector_controls_impl_20261015/manifest.json` (SHA-256
`b12711b567fa59c2b562fa1f353fd1bd1ee31d2780ad6f6cb597e4e9cb70eb3a`) rather than rewriting
the baseline or treating the observed version as baseline.

The current dirty-worktree implementation is bound by source SHA-256 and Git blob:
`lifetime_detector.py` SHA-256 `480d724d81be041eef46246c4162b4c087a1dca0608ff4ff870d3cbbafd895d8`,
blob `c2448558f8dbd386b8ea6eb69a9d10fa9ebe17d2`, observed version `0.4.0`, checkout
HEAD `0dd71fd78baa01283df081f9bd02fe4b7f2df326`, tree
`20ec92e835803f486d088eef183c7db08564926b`, scope
`cpp_unique_ptr_raw_alias_invalidation_v0_4`, profile
`ohscanner_cpp_lifetime_straight_line_alias_v0_4`. The baseline `0.3.0` remains separate.

Exact replay used Ubuntu clang 14.0.0, repeats=3, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`,
`PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1`,
`ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:handle_segv=1`,
`TSAN_OPTIONS=halt_on_error=1:exitcode=66`, with argv
`.venv-web/bin/python research/experiments/cpp/run_four_class_controls.py --manifest research/tests/cpp_detector_controls_impl_20261015/manifest.json --output research/evidence/cpp/implementation_bound_controls_20261015/run-002 --work-dir outputs/poc/cpp-detector-controls-impl-20261015/run-002 --compiler clang++ --repeats 3`.

The rerun passed the lifetime slice's 4 vulnerable, 4 fixed, 3 safe and 1 unrelated controls.
All four invalidation shapes were ASan-triggered 3/3; fixed/safe/unrelated controls were clean
3/3. The `unique_ptr`/raw-alias family PoC reproduced reset, null assignment, replacement and
restricted move transfer 3/3 under ASan, while `fixed_rebind` and `safe_use_before_reset`
were clean 3/3. Exact commands, environment, raw logs, hashes and pass/fail/skip counts are in
`research/evidence/cpp/implementation_bound_controls_20261015/run-002/`.
The run-002 `results.json` SHA-256 is
`2be497117214f5dd060d3e4f15cf68d3ebecdc025a3c03ee6ee3af4dff7345cc`; the complete
evidence checklist is `research/evidence/cpp/implementation_bound_controls_20261015/EVIDENCE_CHECKLIST.md`.

These are synthetic controls and self-authored local dynamic evidence. The 0-finding controls
are narrow negatives only; no Precision/Recall, zero-FP/FN, product reachability, attacker
control, CIA impact or global safety claim is made.
