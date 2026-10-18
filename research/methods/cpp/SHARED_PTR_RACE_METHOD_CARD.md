# shared_ptr mixed atomic/non-atomic method card v0.5

> Current implementation and contract authority: [项目现状与下一步](../../../docs/项目现状与下一步.md)
> and [架构与公共协议](../../../docs/架构与公共协议.md). This card records the narrow
> detector method and its synchronization applicability boundary; it is not a global
> concurrency proof.

## Identity and output

- Detector: `ohscanner.cpp.shared_ptr_race`; detector version `0.5.3`. Rule ID remains stable.
- Rule: `ohcpp-shared-ptr-race-candidate-001`.
- Input: fixed `SourceUnit` C/C++ text with `parse_status=complete`; no target execution,
  external scanner result or historical verdict is required.
- Output: source-bound syntax candidates (`candidate/unassessed`), candidate CWE-362,
  and `EvidenceObligation(kind="synchronization_proof", status="unknown")` whenever the
  synchronization relation is not established by the narrow model.
- `completed` only means the selected lexical units were processed. It does not mean the
  scan is complete and is not a safe verdict.

## Access record and pairwise analysis

Each modeled member access records its source unit/hash, `initialization/read/write`,
`atomic/non-atomic`, reliable lock identities, unreliable lock reasons, function
identity/span, and source position. v0.5 adds three bounded semantic views:

- accesses to the same unique declaration identity (source path + qualified
  class/member) are paired across selected source units, including out-of-line
  definitions; duplicate class names in separate declarations are not merged, and
  an incomplete selected-unit access set remains `coverage=partial`, not a complete
  product protocol;
- constructor initializer-list storage is classified as `initialization`, and
  initialization followed only by reads is a stable-owner shape rather than an
  observed owner mutation pair;
- simple intra-function object aliases (`Holder *p = &h; p->member`) bind to the
  modeled class. Unresolved pointer/reference expressions remain unknown.

Potential conflicting pairs are evaluated independently:

- atomic read/write against ordinary read/write is mixed and is not suppressed without
  a shared reliable synchronization protocol. When both sides hold the same reliable
  mutex, the pair receives narrow pairwise suppression; otherwise the ordinary access
  remains `candidate/unknown`.
- two ordinary accesses conflict when at least one is a write. They are suppressed only
  when both sides have reliable RAII lock identity coverage through at least one shared
  mutex.
- different mutexes, one-sided locking, unresolved lock identity, `try_to_lock`,
  `defer_lock`, `adopt_lock`, aliases and cross-function protocol gaps do not suppress.
  `try_to_lock` and `defer_lock` retain `blocked/unknown` run coverage when observed.
- one-sided locking reports the unprotected access, not the access already covered by a
  reliable lexical mutex.
- The atomic API model includes `atomic_load/store`, their `_explicit` forms,
  `atomic_exchange(_explicit)` and strong/weak compare-exchange forms.
- atomic-only access sets and all-ordinary
  conflicting pairs covered by pairwise reliable shared mutexes are narrow negative
  controls. They are not proofs of thread safety.

The legacy `fixed_atomic_shared_ptr.cpp` shape mixes atomic and mutex/ordinary paths.
Under this boundary it is intentionally `candidate/unknown`, not a safe negative.

## Evidence gate

Candidates stay unassessed. Promotion to confirmed/reportable still requires a realistic
entry or privilege boundary, reachable sensitive operation, trigger conditions, concrete
CIA impact, and auditable synchronization/interleaving evidence. AST and lexical matches
do not prove ownership, guard dominance, lock alias identity, concurrency, attacker
control or impact.

## 0.5.2/0.5.3 precision controls

- Constructor-body member assignment is classified as `initialization`, not a
  later race `write`; constructor-only initialization followed by stable reads is quiet.
- Function parameters shadow same-named members for unqualified accesses;
  `this->member` and `Class::member` remain member accesses.
- Controls include constructor-body stable owner, non-constructor `Init()` mutable owner,
  and a raw-pointer parameter named like a shared_ptr member.
- These controls reduce syntax noise only. They do not prove concurrency,
  happens-before, product reachability or CIA impact.

## Regression record

- Failure gate before implementation: targeted suite `31` tests, `9` failures; the mixed
  atomic/mutex test still expected zero findings and missing synchronization obligations.
- Failure-to-pass gate after pairwise implementation and corrected mixed assertions:
  targeted suite `31/31` passed.
- Static detector module: `60/60` passed.
- Full suite with `.venv-web/bin/python`: `485` passed, `8` skipped.
- Controls retained: atomic-only, all ordinary accesses under the same reliable lexical
  mutex, non-target type and unrelated shape.

- Expanded atomic API regression: `34/34` targeted tests passed after the failure gate.
- PoC unit/integration contract: `9/9` passed.
- Controlled DelayedSingleton PoC: vulnerable and upstream-fix variants reproduced
  ThreadSanitizer data races in `3/3` race repeats; the fully-atomic patch was clean
  in `3/3`; all single-thread controls were clean.

- Combined C/C++ detector/PoC gate after lifetime expansion: `75/75` targeted,
  `66/66` static-module and `505` full-suite tests passed with `8` skipped.
- Final close-out suite after detector/PoC evidence checks: `577` executed, `569`
  passed and `8` skipped. The implementation-bound control replay is separately
  source-hash bound and does not turn these regression counts into benchmark data.
- v0.5 failure-to-pass additions: cross-file write/read pairing, cross-file shared
  mutex suppression, constructor initialization/stable-owner control, a simple
  intra-function object alias positive, and duplicate-declaration non-merge control.
  Shared_ptr detector unit gate `39/39`; combined detector unit gate `71/71`;
  combined detector/PoC gate: `117` tests, `109` passed and `8` skipped.

These are project regression controls, not an independent labelled benchmark. No
Precision/Recall, zero-FP/FN or product-level completeness claim is made.

## Family PoC

`src/ohscanner/poc/cpp_shared_ptr_race.py` binds detector `0.5.0` to the historical
`commonlibrary_c_utils` DelayedSingleton sample and compiles a workload against the
preserved vulnerable/upstream-fix `singleton.h` bytes. Historical run-002 remains
unchanged. The v0.5 rerun is summarized in
`research/evidence/cpp/detector_enhancement_20261015/evidence.json`; raw local
build/runtime artifacts remain under
`outputs/poc/detector-enhancement-20261015/shared_ptr/` and are not committed.

Observed controlled behavior:

| revision | detector | race result | patch role |
|---|---|---|---|
| vulnerable `bdfafdaa...` | 2 candidates | TSan `3/3` | attack reproduction |
| upstream fix `9a3f2811...` | 3 candidates | TSan `3/3` | residual mixed race |
| fully-atomic local patch | 0 findings | clean `3/3` | remediation revalidation |

The 2026-10-15 v0.5 rerun reproduced the same counts and outcomes in all three
race repeats. Single-thread controls were clean. `validated_vulnerability=0`.

This is controlled component-level dynamic evidence. `validated_vulnerability` remains
`0`, and the package remains `candidate/unassessed`.

## Remaining unknown boundaries

- Cross-function synchronization protocols, call-graph reachability and escape are not
  proven. Pairwise mutex suppression is deliberately narrow: a common reliable RAII
  mutex establishes ordering only for the modeled conflicting access pair. It does not
  prove that the selected units contain every access or a complete product happens-before
  relation.
- Lock aliases, pointer/reference expressions beyond simple intra-function object
  aliases, recursive/multiple lock policies and manual lock APIs remain unresolved.
- Template instantiation, macros/preprocessor variants, overload resolution and
  unresolved object expressions are not modeled as complete program semantics.
- The current local `commonlibrary_c_utils` Git object store lacks the two historical
  commits. Preserved source bytes are SHA-256 and quote verified, but Git-object
  provenance remains unknown and is not upgraded.
- No compiler CFG, complete happens-before proof, real product build configuration,
  thread schedule, dynamic race trace or attacker-controlled entry analysis is performed.
  A narrow pairwise mutex result is not promoted to a global synchronization proof.
- Historical reports, IDs and reviews are not rewritten. Absence of a finding remains
  `unknown` under the declared scope, not evidence of safety.
## Four-class development controls (2026-10-15)

- Control package: `research/tests/cpp_detector_controls/manifest.json`,
  SHA-256 `8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`.
- The shared_ptr slice contains 3 vulnerable, 2 fixed, 2 safe and 1 unrelated
  source-bound controls. It covers DelayedSingleton, explicit locking,
  atomic exchange/compare-exchange, mixed atomic/non-atomic access, reset and
  same-member/different-class false-positive shapes.
- Each source binds a repository-relative path, byte count, SHA-256 and Git blob
  SHA-1. The combined control snapshot is
  `d4333621872fcd3d135d08b95fae32d4d7035fc88735bcf90a36236a255d28b7`.
- The two fixed controls apply concrete `authored_control_remediation_patch`
  artifacts with `patch -p1 --fuzz=0`, then compare the patched bytes with the
  fixed source hash. They are real executable patch artifacts but are not
  claimed to be upstream OpenHarmony patches.
- Detector regression observed one candidate for each vulnerable control and
  zero findings for each fixed/safe/unrelated control. Safe/unrelated zero
  findings are narrow negative observations, not safe or miss verdicts.
- Native TSan validation built every control with clang++ 14.0.0 and executed
  every control three times under `setarch x86_64 -R`: vulnerable controls were
  `3/3` sanitizer-triggered and fixed/safe/unrelated controls were `3/3` clean.
- Final evidence: `research/evidence/cpp/four_class_controls/run-005/results.json`
  (SHA-256 `0f51c32d160de44c0dc0acc694f0c80f6ea301831bb03969718f6d688fb38174`)
  and `results.md` (SHA-256
  `4d5fadf81107c6a6529993e3e02fb24387eabcbcbeaddcc2f7195c24847210c7`).
- Exact replay:
  `.venv-web/bin/python research/experiments/cpp/run_four_class_controls.py --output research/evidence/cpp/four_class_controls/run-next --work-dir outputs/poc/cpp-four-class-controls-20261015/run-next --compiler clang++ --repeats 3`.
- Version caveat: the requested control baseline is `0.4.0`, while the dirty
  worktree observed `0.5.0` during execution. The evidence records both values
  and does not relabel the observed worktree as the baseline.
- These are synthetic development controls, not an independent holdout, and no
  Precision/Recall or zero-FP/FN claim is made.
## Implementation-bound control package rerun (2026-10-15)

The old baseline package remains unchanged at `research/tests/cpp_detector_controls/manifest.json`
(SHA-256 `8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`) with baseline
versions `0.4.0` / `0.3.0`. To avoid rewriting that baseline, this rerun uses a separate
implementation-bound package at `research/tests/cpp_detector_controls_impl_20261015/manifest.json`
(SHA-256 `b12711b567fa59c2b562fa1f353fd1bd1ee31d2780ad6f6cb597e4e9cb70eb3a`).

The current dirty-worktree implementation is bound by source SHA-256 and Git blob:
`shared_ptr_race_detector.py` SHA-256 `70197fb273054a20e2e6de82aa4eaa6bdeeaf4951ead6d5076b0e9832c65e230`,
blob `c05ac6bc96b68f8ebacd16f1b7d856a7242e5fb3`, observed version `0.5.0`, checkout
HEAD `0dd71fd78baa01283df081f9bd02fe4b7f2df326`, tree
`20ec92e835803f486d088eef183c7db08564926b`, scope
`cpp_shared_ptr_class_or_static_member_access_v0_5`, profile
`ohscanner_cpp_shared_ptr_race_lexical_sync_v0_5`. The baseline `0.4.0` remains separate
and is not relabeled as observed.

Exact replay used Ubuntu clang 14.0.0, repeats=3, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`,
`PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1`,
`ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:handle_segv=1`,
`TSAN_OPTIONS=halt_on_error=1:exitcode=66`, with argv
`.venv-web/bin/python research/experiments/cpp/run_four_class_controls.py --manifest research/tests/cpp_detector_controls_impl_20261015/manifest.json --output research/evidence/cpp/implementation_bound_controls_20261015/run-002 --work-dir outputs/poc/cpp-detector-controls-impl-20261015/run-002 --compiler clang++ --repeats 3`.

The rerun passed 20 detector controls, 6 zero-fuzz patch revalidations, 3 detector regression
commands, 20 native controls and both family PoCs. The shared slice had 3 vulnerable controls
with 3/3 TSan-triggered runs each; fixed/safe/unrelated controls were clean 3/3. The family
DelayedSingleton PoC reproduced the vulnerable and upstream-fix race modes 3/3 and the
fully-atomic patch was clean 3/3, with single-thread controls clean. Raw command logs, exact
argv/environment, hashes and pass/fail/skip counts are in
`research/evidence/cpp/implementation_bound_controls_20261015/run-002/` with
`results.json`, `verification.json`, `execution.json`, `SHA256SUMS.txt` and `work_binaries.sha256`.
The run-002 `results.json` SHA-256 is
`2be497117214f5dd060d3e4f15cf68d3ebecdc025a3c03ee6ee3af4dff7345cc`; the complete
evidence checklist is `research/evidence/cpp/implementation_bound_controls_20261015/EVIDENCE_CHECKLIST.md`.

These remain synthetic development controls and controlled local dynamic evidence. Zero
findings are narrow negative controls only; no Precision/Recall, zero-FP/FN, product
reachability, attacker control, CIA impact or global safety claim is made.

## Real-source component case: JSProxy::instance_ (2026-10-18)

The first pinned real-source component case is
`openharmony/distributeddatamgr_kv_store@acfb22aac16161d8fb0cefb6cc9b92f04f489a80`.
The detector reports two `instance_` candidates in
`frameworks/common/js_proxy.h`: the `SetInstance` write at line 37 and the
`GetInstance` read at line 42.

A self-authored TSan harness uses the exact pinned header bytes for the
vulnerable variant and a mutex-protected copy for the fixed variant. With
Ubuntu clang 14.0.0, `-fsanitize=thread`, `setarch x86_64 -R` and three repeats:

- vulnerable: exit `66/66/66`, data race reported in all three runs;
- fixed: exit `0/0/0`, no data race reported in all three runs.

`patch/js_proxy_mutex.patch` is the minimal component fix and passes
`git apply --cached --check` against the pinned Git blob. Evidence, source/blob
hashes, logs and limitations are under
`research/evidence/cpp/jsproxy_case_20261018/`.

This is component-level evidence only. It does not establish a product entry,
permission boundary, attacker control, CIA impact or product build; the case
remains `candidate/unassessed` with `validated_vulnerability=0`.
