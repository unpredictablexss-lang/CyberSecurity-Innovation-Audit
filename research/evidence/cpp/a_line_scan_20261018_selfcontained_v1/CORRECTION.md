# Runner binding correction (2026-10-18)

## What was wrong

`a_line_scan_20261018_v1` through `v16` were produced with the shared mainline
runner `scripts/run_cpp_memory_safety_scan.py`. That script inserts
`Path(__file__).resolve().parents[1]` at `sys.path[0]`, so every run imported
the **mainline** detectors (`bounds 0.2.0`, `integer_bounds 0.2.0`,
`resource_lifetime 0.1.0`, `unsafe_memory_call 0.1.0`), not this A-line
worktree. Setting `PYTHONPATH=src` did not override that insert.

Consequences:

- The repeated "33 candidates / 22 groups, no change" results describe the
  mainline detectors, not the A-line detector changes.
- Those runs remain valid mainline baseline observations, but they must not be
  cited as A-line before/after evidence.
- The sandbox copy-range replay and all unit tests import the A-line modules
  directly and were not affected.

## Corrected run

`research/evidence/cpp/mvp_20261018/run_scan.py` is a self-contained copy of the
mainline runner with `PROJECT_ROOT = parents[4]` and a startup check that aborts
if any detector module resolves outside this worktree. The corrected full
five-component run is `a_line_scan_20261018_selfcontained_v1`:

| Detector | Version | Candidates |
|---|---|---:|
| `ohscanner.cpp.bounds` | `0.2.9` | 21 |
| `ohscanner.cpp.integer_bounds` | `0.2.2` | 25 |
| `ohscanner.cpp.resource_lifetime` | `0.1.3` | 7 |
| `ohscanner.cpp.unsafe_memory_call` | `0.1.2` | 7 |
| total | | 60 |

| Component | Mainline (`v16`) | A-line (`selfcontained_v1`) |
|---|---:|---:|
| `communication_dsoftbus` | 7 / 4 | 36 / 23 |
| `distributeddatamgr_kv_store` | 11 / 8 | 10 / 7 |
| `security_access_token` | 4 / 2 | 6 / 3 |
| `update_updateservice` | 7 / 6 | 6 / 5 |
| `window_window_manager` | 4 / 2 | 2 / 1 |
| total | 33 / 22 | 60 / 39 |

Per-rule comparison (mainline → A-line):

- `ohcpp-format-string-candidate-002`: 7 → 7
- `ohcpp-integer-bounds-arithmetic-candidate-001`: 16 → 25
- `ohcpp-memory-bounds-copy-candidate-001`: 0 → 21
- `ohcpp-resource-lifetime-double-free-candidate-001`: 2 → 3
- `ohcpp-resource-lifetime-use-after-free-candidate-002`: 8 → 4

The higher total is coverage from the A-line rules, not an accuracy gain; the
lower UAF count is a precision change. Neither is a vulnerability count, and
`validated_vulnerability` remains `0`.

## Precision follow-up (`selfcontained_v2`)

Two systemic false-positive shapes were fixed after the first corrected run:
capacity expressions are normalized for identity factors (`x + 1` vs
`x + 1 * 1`, `N` vs `sizeof(char) * N`), symbolic `length + constant`
capacities are recognized, and implicit `calloc`/`new[]` element products are
treated as allocator-checked instead of candidates. Further precision fixes
remove unconditional-exit/lambda fall-throughs and preprocessor macro bodies.
The final run is 30 candidates / 20 groups (bounds 9, integer 16, resource 2,
unsafe 3); `communication_dsoftbus` drops from 36/23 to 13/9.
`a_line_scan_20261018_selfcontained_v7` is the authoritative A-line scan.
