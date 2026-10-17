# Cross A/B Parcel length case

This is the first controlled composition of A length facts and B Parcel semantics. It uses self-authored IPC fixtures under `tests/fixtures/ipc`, not a product build.

## Result matrix

| Case | A bounds | B IPC | Range fact | Interpretation |
|---|---|---|---|---|
| positive | 1 `ohcpp-memory-bounds-copy-candidate-001` | 1 `ipc.parcel.copy-range` | `n`: `[0, unknown]` bytes | Two independent candidate layers agree on the same unbounded copy shape |
| fixed | 0 | 0 | `n`: `[0, 64]` bytes | Explicit `n<0 || n>sizeof(dst)` guard suppresses both layers |

## Composition boundary

A supplies local destination-capacity/length evidence and v2 `RangeFact`; B supplies `MessageParcel`/`ReadInt32`/`ReadBuffer`/`memcpy` boundary semantics and `EvidenceObligation`. Neither layer proves attacker control, product reachability, permission bypass or CIA impact. The combined output is a review aid, not a vulnerability claim.

## Reproduction

```text
.venv-web/bin/python scripts/run_cross_ab_parcel_case.py --out research/evidence/cpp/cross_ab_parcel_case_20261017.json
.venv-web/bin/python -m unittest tests.test_cross_ab_parcel_case
```
