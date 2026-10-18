# GuardFact proposal for A/B shared facts

This is a research interface proposal, not a public schema change. The platform
owner must review and version any serialized addition.

## Purpose

Expose bounded guard facts so C/C++ detectors and IPC/Parcel rules do not each
reimplement condition parsing. The immediate motivating case is
`communication_wifi` `RemoteOnConfigChanged`, where the scanner missed:

```text
if (cfgLen <= 0) return;
if (cfgLen > MAX_LEN) return;
```

The fact consumer must see `cfgLen` as `[1, MAX_LEN]` before the later
allocation/copy.

## Proposed fields

- `file`, `function`, `line`, `column`, `source_sha256`
- `symbol`
- `condition`
- `guard_kind`: `lower_bound`, `upper_bound`, `zero_check`, `null_check`,
  `return_code`, `permission_predicate`, `unknown`
- `lower`, `upper`: optional integer bounds
- `dominance`: `dominating`, `not_dominating`, `unknown`
- `error_path`: `return`, `break`, `continue`, `goto`, `throw`, `unknown`
- `proof_ref`: stable reference to the parsed condition/CFG evidence

The A-line producer is implemented as
`src/ohscanner/detectors/cpp/memory_safety.build_guard_facts`; it returns
in-memory `GuardFact` objects and does not serialize or change the public
contract.

`if (x != 0) return;` currently produces `guard_kind=zero_check` with
`[0, 0]`; A line does not claim that `x` is a return code. Whether a
`zero_check` symbol is a return code, error status or an ordinary integer is a
consumer decision (B/platform) and stays outside the producer.

The C/C++ bounds detector deliberately does not consume `zero_check` as a range
constraint: `if (n != 0) return; dst[n - 1]` still underflows when `n == 0`, so
the index candidate must remain. Consumers may use the fact for control-flow
understanding, but must apply their own underflow rules.

## Ownership

- A line produces C/C++ interval and early-return guard facts.
- B line produces IPC entry, caller identity and permission predicates.
- Platform owner defines serialization and compatibility tests for any public
  `GuardFact` surface.
- `CheckGetSAPermission`, `CheckGetRemoteSAPermission`, PengLai and similar
  predicates remain B-line semantics; A line must not add a trusted-name
  allowlist.

## Boundary

A guard fact is a bounded syntax/CFG claim. It does not prove that the guarded
path is the only product path, that a permission predicate is correctly bound to
the actual caller, or that the operation has a security consequence.
