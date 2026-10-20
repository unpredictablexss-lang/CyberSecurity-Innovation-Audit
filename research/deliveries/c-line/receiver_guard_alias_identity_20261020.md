# Receiver guard alias identity slice

This bounded C-line slice improves receiver guard matching for simple local
`GateRef` value copies. Previously the rule only matched the same parameter
binding at guard and accessor, and it cleared the guard bit after any assignment
to that parameter. Those behaviors left a proven same-object alias unknown or
candidate after the parameter was restored from a stable alias.

The path analysis now tracks object identities for GateRef parameters and plain
identifier copies. A positive direct TypedArray guard records the current
object identity; assignment from another tracked identifier updates the
binding's current identity. The original guard therefore applies again when a
later assignment restores the same object through a stable alias.

| Case | Expected | Result |
|---|---|---|
| Guard and sink use values copied from the same parameter | `matched` | `matched` |
| Re-sample type through a same-origin alias and guard before sink | `matched` | `matched` |
| Guard, rebind receiver to another parameter, restore from stable alias, then sink | `matched` | `matched` |
| Guard one object, rebind alias to a different parameter, then sink alias | `candidate` | `candidate` |
| Conditional/complex assignment or writable reference alias | `unknown` | `unknown` |

Only direct `GateRef` identifier copies are modeled. Pointer/reference
declarators and non-identifier assignments invalidate tracked identities.
Compound predicates, unsupported generated control flow, unresolved source
bindings, parse gaps, and unknown paths remain unproved; this is not a product
safety or accuracy claim.

Validation: `python -m pytest tests/detectors/ark_runtime/test_receiver_guard.py
-q` passed **16 tests** with one explicit historical Git-store test skipped.
The full Ark runtime suite passed **158 tests**, with three explicit historical
Git-store tests skipped; `git diff --check` passed.
