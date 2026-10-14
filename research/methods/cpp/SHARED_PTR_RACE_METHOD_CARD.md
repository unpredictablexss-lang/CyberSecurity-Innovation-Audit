# shared_ptr mixed atomic/non-atomic method card v0.4

> Current implementation and contract authority: [项目现状与下一步](../../../docs/项目现状与下一步.md)
> and [架构与公共协议](../../../docs/架构与公共协议.md). This card records the narrow
> detector method and its synchronization applicability boundary; it is not a global
> concurrency proof.

## Identity and output

- Detector: `ohscanner.cpp.shared_ptr_race`; detector version `0.4.0`.
- Rule: `ohcpp-shared-ptr-race-candidate-001`.
- Input: fixed `SourceUnit` C/C++ text with `parse_status=complete`; no target execution,
  external scanner result or historical verdict is required.
- Output: source-bound syntax candidates (`candidate/unassessed`), candidate CWE-362,
  and `EvidenceObligation(kind="synchronization_proof", status="unknown")` whenever the
  synchronization relation is not established by the narrow model.
- `completed` only means the selected lexical units were processed. It does not mean the
  scan is complete and is not a safe verdict.

## Access record and pairwise analysis

Each modeled member access records `read/write`, `atomic/non-atomic`, reliable lock
identities, unreliable lock reasons, function identity/span, and source position.
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

These are project regression controls, not an independent labelled benchmark. No
Precision/Recall, zero-FP/FN or product-level completeness claim is made.

## Family PoC

`src/ohscanner/poc/cpp_shared_ptr_race.py` binds detector `0.4.0` to the historical
`commonlibrary_c_utils` DelayedSingleton sample and compiles a workload against the
preserved vulnerable/upstream-fix `singleton.h` bytes. The recorded run is:

`research/evidence/cpp/shared_ptr_delayed_singleton/run-002/`; raw local build/runtime artifacts remain under `outputs/poc/` and are not committed.

Observed controlled behavior:

| revision | detector | race result | patch role |
|---|---|---|---|
| vulnerable `bdfafdaa...` | 2 candidates | TSan `3/3` | attack reproduction |
| upstream fix `9a3f2811...` | 3 candidates | TSan `3/3` | residual mixed race |
| fully-atomic local patch | 0 findings | clean `3/3` | remediation revalidation |

This is controlled component-level dynamic evidence. `validated_vulnerability` remains
`0`, and the package remains `candidate/unassessed`.

## Remaining unknown boundaries

- Cross-function synchronization protocols, call-graph reachability and escape are not
  proven. Same-translation-unit pairwise mutex suppression is deliberately narrow.
- Lock aliases, pointer/reference expressions, recursive/multiple lock policies and
  manual lock APIs are unresolved unless the lexical expression has a simple stable
  identity.
- Template instantiation, macros/preprocessor variants, overload resolution and
  unresolved object expressions are not modeled as complete program semantics.
- The current local `commonlibrary_c_utils` Git object store lacks the two historical
  commits. Preserved source bytes are SHA-256 and quote verified, but Git-object
  provenance remains unknown and is not upgraded.
- No compiler CFG, happens-before proof, real product build configuration, thread
  schedule, dynamic race trace or attacker-controlled entry analysis is performed.
- Historical reports, IDs and reviews are not rewritten. Absence of a finding remains
  `unknown` under the declared scope, not evidence of safety.