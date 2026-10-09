# Method card: lifetime_uaf

Status: research design for a future C/C++ detector. No OHScanner detector or
public contract implementation is included here.

## Target mechanism

Concurrent publication and destruction of a shared object can produce a
lifetime/use-after-free race when pointer state is read and written without a
single ownership or synchronization discipline. The pinned historical patch
changes `DelayedSingleton` publication/destruction semantics.

A future candidate detector may use syntax and limited ownership/synchronization
facts to flag suspicious shared-state lifetime transitions. A `.reset()`,
pointer name, shared_ptr type or rule match alone is not evidence of UAF.

## Evidence unit

| Role | sample_id | Exact commit | Scope |
|---|---|---|---|
| vulnerable | `c_utils-singleton-uaf-2026-01` | `bdfafdaafddb01ab7ae13354ce2ada9555d7935c` | `base/include/singleton.h`, DelayedSingleton pair |
| fixed | `c_utils-singleton-uaf-2026-01` | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | same analysis unit |
| safe | `c_utils-singleton-uaf-2026-01` | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | separate `Singleton<T>::GetInstance` |

The full source/tree/blob/file hashes and line scopes are in
`research/corpus/native/lifetime_uaf.json` and the reproducible generated
`outputs/reports/static_baselines/evidence_units.json`.

## Evidence identity

The generated evidence unit binds repository, full commit, revision, sample ID,
analysis-unit scope, source artifact and source/tree/blob hashes to one
tool/version/configuration and `run_id`. Its `scan_context_identity` follows
PR #5 `ScanRequest`/`SourceUnit`/`ScanContext` field names and omits third-party
source text. Vulnerable, fixed and safe controls remain separate units and
never share evidence or counts. This historical metadata package records prior
baseline states only; no scanner was rerun in this round.

## Proposed analysis obligations

1. Bind repository, exact commit, source file hash, scope and tool run.
2. Resolve the relevant object/ownership operation and its synchronization
   context when source facts allow it.
3. Record unresolved types, templates, macros and missing headers as coverage
   gaps, not misses.
4. Emit a `candidate`/`possible_hit` diagnostic only. Promotion requires
   independent evidence review and runtime validation outside this round.
5. Keep vulnerable, fixed and safe units separate.

Potential future features are pointer ownership transitions, shared state
publication, concurrent access sites and destruction paths. Feature extraction
must be original; third-party rules/code require license and originality review
before use.

## Existing baseline observation

For the pinned pair across eight tools: `possible_hit=1`, `miss=7`,
`unknown=4`, `not_applicable=4`. Semgrep OH produced one vulnerable-only
candidate and no fixed match. Cppcheck was unknown with an unresolved symbol;
Joern was unknown with CAST problems; Clang SA and CodeQL were explicitly
incompatible with this header-only snapshot for their configured analysis
units. These are cell states, not vulnerability or accuracy metrics.

## Limitations

- No runtime race trigger, TSan result, product build or exploitability test.
- Template instantiation and full synchronization context are missing.
- The safe control is shape-based and does not prove global safety.
- A candidate match cannot establish concurrent interleaving, attacker control
  or use-after-free impact.
- The sample informed family selection and therefore belongs to the design set,
  not an independent holdout.

## Holdout and acceptance

A future holdout must use an unseen lifetime root-cause instance, preferably
from another repository, with fixed vulnerable/fixed hashes and safe controls.
The detector and method card must be frozen before the owner reveals the
holdout. Report raw cell states and coverage; do not compute Precision/Recall or
claim zero false positives/negatives from this small corpus.