# C/C++ unique_ptr raw-alias lifetime method card v0.3

> Current contracts and status authority remain `docs/架构与公共协议.md` and
> `docs/项目现状与下一步.md`. This card describes the narrow detector method and
> its controlled PoC; it is not a whole-program lifetime proof.

## Identity

- Detector: `ohscanner.cpp.lifetime`, version `0.3.0`.
- Rule: `ohcpp-lifetime-unique-raw-alias-reset-001` (stable historical rule ID).
- Candidate CWE: CWE-416. Output remains syntax-level `candidate/unassessed`.

## Expanded invalidation model

For a same-function explicit `std::unique_ptr<T>` owner and a raw alias created
with `owner.get()`, the detector now records these owner lifetime changes:

- `owner.reset(...)`;
- owner assignment, including `owner = nullptr` and replacement by a new object;
- `std::move` transfer out of the owner.

Move semantics are scope-sensitive. A raw alias can remain valid while the
destination owner is alive. The detector requires the destination owner's
lexical scope to end before the later alias use; immediate use while the
destination remains alive is not promoted by this rule.

Unconditional straight-line `alias = owner.get()` rebinding remains a narrow
suppression. Conditional rebinding, CFG gaps, escapes, destructors, exceptions
and cross-function transfers remain unknown.

## Evidence gate

A finding does not prove UAF, attacker control, a real entry boundary, CIA
impact or exploitability. Promotion still requires reachable sensitive
operation, trigger conditions and concrete impact evidence.

## Failure-to-pass record

- Failure gate: `27` lifetime tests with `4` failures for version and missing
  null/replacement/move invalidation coverage.
- Expanded detector regression: `27/27` passed.
- PoC contract tests: `5/5` passed.

## Controlled PoC

`src/ohscanner/poc/cpp_lifetime_uaf.py` and
`src/ohscanner/poc/harnesses/cpp_lifetime_unique_ptr_alias/` execute a
hash-bound self-authored workload under AddressSanitizer.

Recorded run:
`research/evidence/cpp/lifetime_unique_ptr_alias/run-004/`; raw local build/runtime artifacts remain under `outputs/poc/` and are not committed.

| variant | detector boundary | ASan result |
|---|---|---|
| `reset_vulnerable` | `owner.reset()` | `3/3` triggered |
| `null_assignment_vulnerable` | `owner = nullptr` | `3/3` triggered |
| `replacement_vulnerable` | owner replacement | `3/3` triggered |
| `move_transfer_vulnerable` | move + destination scope end | `3/3` triggered |
| `fixed_rebind` | unconditional alias rebind | `3/3` clean |
| `safe_use_before_reset` | use precedes invalidation | `3/3` clean |

`validated_vulnerability=0`; this is controlled self-authored dynamic evidence,
not a real product vulnerability result.

## Remaining unknowns

- CFG dominance, early returns, exceptions and destructor timing.
- Cross-function alias escape/transfer and ownership graphs.
- Member aliases, pointer/reference aliasing and templates/macros.
- Real OpenHarmony entry/privilege boundaries and product builds.
- No Precision/Recall claim is made from these authored controls.