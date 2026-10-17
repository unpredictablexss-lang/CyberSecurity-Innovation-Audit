# A-NULL-01 C/C++ NULL dereference method card v1

> Gate notice: repository evidence currently records A-CCR-04 as
> `proposed/awaiting_owner_approval`. This card and its fixtures are preimplementation
> research assets only. No detector, catalog entry, runner integration or public
> contract is implemented by this change. Public implementation remains blocked until
> the owner approval is recorded in an auditable repository artifact.

## Identity and intended output

- Change request: `A-NULL-01`.
- Proposed detector: `ohscanner.cpp.null_dereference`.
- Proposed detector module version: `0.1.0` for the first implemented v1 slice.
- Proposed rule: `ohcpp-null-dereference-candidate-001`.
- Candidate CWE: CWE-476.
- Languages: explicit C and C++ source units only.
- Output state: `candidate/unassessed`. A match is syntax-bound evidence, not proof of
  dereference failure, attacker control, product reachability or CIA impact.

A later implementation must use the existing first-party Detector contract and emit
source-bound schema v2 diagnostics. It must not call CodeQL, Clang Static Analyzer,
Infer, Joern, another scanner or a historical verdict as a production dependency.

## Narrow source and sink model

The v1 method recognizes only same-function lexical shapes with a stable base symbol:

| Required fact | v1 observation |
|---|---|
| Null source | local pointer initialized to `nullptr`; parameter pointer treated as potentially null; member pointer explicitly initialized to `nullptr`; pointer initialized from a function return with unknown nullability |
| Pointer sink | unary `*p`, member `p->field`, method `p->method()`, subscript `p[i]`, and a sink through a simple same-function alias |
| Guard | `p == nullptr`, `p != nullptr`, `!p`, `p`, and equivalent direct comparisons over the same base symbol |
| Error path | whether the null branch terminates with `return` on every modeled path or falls through to the sink |
| Pointer roles | parameter, return value, member pointer and local pointer are recorded independently |

A source and sink pair becomes a candidate only when both use the same modeled symbol or
a simple same-function alias whose rebinding is visible. Return values, member pointers,
escaped aliases and unresolved callees remain candidate/unknown rather than proven null
sources.

## Bounded guard and error-path semantics

This is not a complete CFG. The implementation design allows only a bounded lexical
region tree over straight-line code, nested blocks and simple `if`/`else` statements.

- A null guard dominates a sink only when every modeled path to that sink passes through
  a positive guard or a null branch that returns before the sink.
- `if (p == nullptr) return ...;` is an early-return error path and suppresses the narrow
  candidate only when the return covers the entire null branch and no reassignment or
  alias escape occurs before the sink.
- `if (p != nullptr) { p->field; }` is a bounded positive guard.
- A guard in one branch that does not enclose or return before the sink is
  `guard_relation=not_dominating`.
- Loops, switch fallthrough, goto, exceptions, destructor order, conditional alias
  rebinding and unresolved control transfer are `guard_relation=unknown`.

Zero findings mean only that this narrow rule did not match. They are not a safety
verdict. Negative fixtures retain `compile_context=missing` and are not product proofs.

## Unknown and candidate boundary

The implementation must return `unknown` analysis coverage or retain a candidate with
unknown obligations when any of these are observed:

- CFG or dominance is not complete for the modeled path.
- Cross-function alias or return-value nullability is unresolved.
- Macros, templates, exceptions or destructor sequencing affect the shape.
- Compiler defines, include graph, language mode or other build context is missing.
- Function pointers or indirect calls cannot be resolved.
- Parsing is partial/failed, a source hash does not bind, or a finite analysis budget is
  exhausted.

No nearest-node substitution, default lock state, empty path or zero finding may fill an
unknown fact.

## EvidenceObligation contract

Every emitted candidate must retain the source file/hash and use obligations equivalent
to:

```python
EvidenceObligation("guard_dominance", "Establish complete CFG dominance for every sink.", "unknown")
EvidenceObligation("cross_function_alias", "Resolve parameter, return, member and escaped aliases.", "unknown")
EvidenceObligation("compile_context", "Bind compiler, defines, includes, language mode and instantiations.", "missing")
EvidenceObligation("entry_or_privilege_boundary", "Establish a realistic reachable entry and privilege boundary.", "missing")
EvidenceObligation("attacker_control", "Show attacker influence over the null source or trigger.", "missing")
EvidenceObligation("sensitive_operation_reachability", "Show the sink is reachable in the affected build.", "missing")
EvidenceObligation("trigger_conditions", "Record reproducible trigger conditions and observed behavior.", "missing")
EvidenceObligation("cia_impact", "Establish concrete confidentiality, integrity or availability impact.", "missing")
```

Promotion to confirmed/reportable requires all applicable obligations to be satisfied by
auditable evidence. The detector must promote when that gate is met; it must not keep a
verified case permanently at candidate.

## Coverage semantics

| `file_outcomes` | Required meaning |
|---|---|
| `complete` | The bounded lexical slice was processed. Semantic obligations can still be unknown. |
| `partial` | A candidate may be retained, but macro/template/exception/destructor/alias/CFG/build facts are incomplete. |
| `failed` | Parsing, integrity or analysis execution failed. No absence or safe conclusion. |
| `not_analyzed` | Unsupported language or out-of-scope unit. No C/C++ conclusion. |

An aggregate `blocked` run must preserve valid partial candidates and obligations.
`completed` never means that the product is safe.

## Fixture and regression matrix

The self-authored synthetic package is
`research/tests/a_null_01/`:

- `fixtures/`: 18 source-bound vulnerable, fixed, safe, unrelated, unknown and
  not-analyzed controls.
- `regression_matrix.json`: expected observation, coverage, source role, sink role,
  guard relation, error path and EvidenceObligation requirements for every fixture.
- `manifest.json`: source SHA-256, Git blob SHA-1, byte length, parse status and the
  combined snapshot hash.
- `verify_fixtures.py`: deterministic fixture and matrix integrity check.

Observed fixture verification on 2026-10-15:

```text
fixtures: 18
manifest SHA-256: 2630248684a61688d2bce9f00d64ae9bb9a4fad3ab47c67bdf386d7aec32a3d3
regression matrix SHA-256: b91fbb81d36e09750fc7321370477addb5c74ab5e32561a5248b1795856eb784
fixture snapshot SHA-256: c4c965974ccf2a5dc76a2376550cc415e3ce46e3b469e6ba8fbc6d5e63d8863f
```

Exact integrity replay:

```bash
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd "/mnt/e/网安/CyberSecurity-Innovation-Audit" && .venv-web/bin/python research/tests/a_null_01/verify_fixtures.py --check'
```

This replay validates fixture identity only. It does not execute detector regression
because the public implementation is gated.

## Regression acceptance after approval

The implementation is acceptable only when the matrix has an executable failure-to-pass
record:

1. Run the fixture package through `ohscanner.cpp.null_dereference`.
2. Require exactly one retained candidate for each `candidate_shape` and
   `candidate_with_unknown_obligations` case.
3. Require zero candidates for fixed, safe and unrelated controls while preserving their
   narrow negative limitations.
4. Require `failed`/`not_analyzed` cases to publish no absence or safety conclusion.
5. Require every candidate to bind source SHA-256 and all listed obligations.
6. Run the combined C/C++ detector suite and the project-wide unit suite.
7. Record exact argv, runtime versions, hashes, counts, limitations and source-bound
   evidence. Do not claim Precision/Recall from these authored controls.

## Limitations and deferred competition evidence

This package does not implement CFG, type inference, alias analysis, macro expansion,
template instantiation, exception/destructor modeling or product build analysis. It does
not establish a real OpenHarmony entry point, attacker control, trigger, affected version,
CIA impact, PoC, remediation or patch revalidation. Those competition deliverables remain
required after implementation and evidence-gate review.
