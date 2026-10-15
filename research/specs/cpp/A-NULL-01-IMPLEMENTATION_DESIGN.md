# A-NULL-01 implementation design: narrow C/C++ NULL dereference detector v1

## 1. Gate and change boundary

Repository evidence records A-CCR-04 as `proposed/awaiting_owner_approval`. Therefore this
document is an implementation design only. It does not add or modify:

- `src/ohscanner/**`;
- public Detector contracts or schema v2;
- runner/catalog registration;
- API, Worker, storage or frontend code;
- historical reports, candidate IDs or reviews.

When the approval is recorded, implementation must be a separate reviewed change. Public
contract changes, if any are still required, remain separate from detector behavior changes.

## 2. Proposed files after approval

```text
src/ohscanner/detectors/cpp/null_dereference_detector.py
tests/detectors/null_dereference_fixture_support.py
tests/detectors/test_cpp_null_dereference_detector.py
src/ohscanner/detectors/cpp/README.md                 # add a short v1 section
research/tests/a_null_01/                             # already prepared fixtures/matrix
```

The production implementation must use `src.ohscanner.contracts` only. It must not import
research code or call an external scanner. The fixture support may read
`research/tests/a_null_01/manifest.json` and validate every source hash before tests.

## 3. Internal records

Use immutable records equivalent to:

```python
@dataclass(frozen=True)
class NullSource:
    symbol: str
    kind: str                 # local, parameter, member, return_value
    position: int
    nullability: str          # explicit_null, may_be_null, unknown
    declaration_span: tuple[int, int]
    binding_id: str

@dataclass(frozen=True)
class DereferenceSink:
    symbol: str
    kind: str                 # unary, member, method, subscript, alias
    position: int
    function_span: tuple[int, int]

@dataclass(frozen=True)
class GuardShape:
    symbol: str
    condition: str            # null, non_null
    branch_spans: tuple[tuple[int, int], ...]
    returns_on_null_path: bool
    relation: str             # dominates, not_dominating, unknown

@dataclass(frozen=True)
class UnsupportedShape:
    kind: str                 # macro, template, exception, destructor, indirect_call, alias
    span: tuple[int, int]
    missing_fact: str
```

All records must carry the `SourceUnit.path` and `SourceUnit.sha256`; positions are offsets
into the exact unit text. Do not merge symbols across functions or units without a recorded
identity rule.

## 4. Bounded lexical analysis

1. Select `SourceUnit.language in ("c", "cpp")`.
2. Reject `parse_status="failed"` as `failed`; leave `partial` and `not_run` as `partial`
   with no safe result.
3. Mask comments and literal bodies while preserving byte offsets.
4. Identify function spans and simple nested brace regions. Any malformed brace, macro
   directive that controls the shape, template, `try`/`catch`/`throw`, destructor-sensitive
   ownership, `goto`, unresolved switch fallthrough or indirect call marks the region
   `partial`.
5. Build the source, sink, guard, return and unsupported records above.
6. Evaluate only same-function, same-binding-id source/sink pairs. A simple alias chain
   is allowed only for direct assignments with no call, address escape or conditional
   rebind.
7. Emit a candidate when the source is explicit null/may-be-null and a reachable lexical
   sink is not covered by a dominating guard or early return. Preserve a candidate with
   unknown obligations when the shape is visible but CFG/dominance, alias or context is
   incomplete.

### Guard rules

- Null guard: `p == nullptr`, `nullptr == p`, `!p`.
- Non-null guard: `p != nullptr`, `nullptr != p`, `p`.
- Early return: every terminal statement in the null branch is `return`; no fallthrough.
- Dominating positive guard: sink is inside the non-null branch and no rebind/escape occurs.
- Dominating early return: null branch returns before the sink on every modeled path.
- `guard_relation=unknown` whenever a path, alias or unsupported construct is not modeled.

### Source rules

- Local: `T *p = nullptr` or `T *p = NULL`.
- Parameter: `T *p` is `may_be_null` unless the function contract/build facts prove
  otherwise; proof is out of scope for v1.
- Member: an explicit constructor initializer or assignment to `nullptr` is a source;
  uninitialized members remain unknown, not automatically null.
- Return value: `T *p = Call(...)` is `unknown` nullability and requires a candidate/unknown
  result when a sink follows; it is never treated as proven null.

### Sink rules

Recognize `*p`, `p->member`, `p->method()`, `p[index]`, and the same forms through a simple
alias. A function pointer call or unresolved indirect call is an unknown boundary even if
its argument is a pointer.

## 5. ReadOnlyFactView and build context

The approved A-CCR-04 envelope is an optional semantic fact source, not a license to guess.
The adapter should request only bounded facts:

- `get_cfg_path` for source-to-sink paths;
- `get_guard_proof` for dominance;
- `get_dataflow` for source-to-sink identity;
- `get_build_context` for defines/includes/language mode;
- `get_coverage` for per-file closure.

If the envelope is absent, malformed, `unknown`, `failed`, budget-exhausted, or has
unverified proof for a `proven` claim, record the corresponding unknown reason and emit
candidate/unknown or partial coverage. Never use host defaults or a nearby fact as proof.
No public ReadOnlyFactView implementation is created here.

## 6. EvidenceObligation output

For each candidate, attach obligations with the exact kinds in
`research/tests/a_null_01/regression_matrix.json`. The finding itself remains
`evidence_type="syntax"` with `candidate_cwe="CWE-476"` and `source_sha256` bound.
Do not add `consequence_impact` unless a separate approved consequence contract and real
evidence are available.

## 7. Coverage and run state

Map each selected unit to exactly one `file_outcomes` value:

- `complete`: no unsupported shape in the bounded slice; a zero-finding result still gets
  limitations stating that it is not a safe verdict;
- `partial`: any macro/template/exception/destructor/alias/CFG/build uncertainty;
- `failed`: parse/integrity/analysis failure;
- `not_analyzed`: unsupported language or out-of-scope unit.

Run state is `completed` only when all selected in-scope C/C++ units are `complete`.
If any in-scope unit is partial or failed, use `blocked` or `failed` while retaining valid
candidates and obligations. Unsupported out-of-scope files may remain `not_analyzed`.
Unknown/partial/failed/unexecuted never becomes safe or miss.

## 8. Proposed detector README section

After approval, add this bounded section to `src/ohscanner/detectors/cpp/README.md`:

> `ohscanner.cpp.null_dereference` v0.1.0 recognizes a narrow same-function C/C++
> null-source and pointer-dereference shape. It records local, parameter, member and
> function-return pointer roles, bounded guard/error-path relations and source-bound
> candidate evidence. It is not a complete CFG, type, alias, macro, template, exception,
> destructor or build-context analysis. Candidate results require the A-NULL-01
> EvidenceObligation gate; zero findings are not a safe verdict.

Do not add the production README before the approval gate is recorded.

## 9. Verification plan

Use the fixture matrix as a failure-to-pass gate. After implementation, run exact commands
and record them in research evidence:

```bash
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd "/mnt/e/网安/CyberSecurity-Innovation-Audit" && .venv-web/bin/python research/tests/a_null_01/verify_fixtures.py --check'
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd "/mnt/e/网安/CyberSecurity-Innovation-Audit" && .venv-web/bin/python -m unittest tests.detectors.test_cpp_null_dereference_detector -v'
wsl.exe -d Ubuntu-22.04 -- bash -lc 'cd "/mnt/e/网安/CyberSecurity-Innovation-Audit" && .venv-web/bin/python -m unittest discover -s tests -q'
```

The first command is valid now. The latter two are intentionally deferred because no
public detector implementation is permitted by the current gate. Required controls are
vulnerable, fixed, safe, unrelated, macro, template, exception/destructor, indirect call,
cross-function alias, failed parse and unsupported-language cases. No Precision/Recall or
zero-FP/FN claim is permitted from synthetic controls.
