# Independent holdout freeze and single evaluation, 2026-10-17

## Freeze

The independent holdout was frozen before any post-freeze detector change. It contains 30 distinct official public fix commits, each represented by a vulnerable parent and fixed commit (60 source snapshots), across six C/C++ rule families. Every root cause has a unique stable patch ID over modified non-test C/C++ source scope.

- Manifest SHA-256: `485b8729df41afa10a2fb3b78cd215e75fbe04681766363ba8f4fb027f8031e8`
- Canonical content digest: `53e97de6b84498aa4a24bf9c8914f73ea99ccd251e4fdf9e77b3ba7616ddc264`
- Truth authority: official public vulnerable-parent/fixed-commit source pairs
- Product exploitability and CIA impact: unknown; the truth is code-defect detection only
- Detector tuning after freeze: none

The selection excludes CVE-2025-23420, CVE-2025-0587 and the previously used c_utils shared_ptr / dsoftbus null tuning samples.

## Evaluation

The frozen detector set was evaluated on all 60 samples. An earlier result-serialization preflight reached `run_all` for one sample but retained no output and was not used for metrics; it did not tune any rule. The complete evaluation is the single retained run under `run_20261017_single`.

Known-scored sample confusion counts:

| TP | FP | FN | TN | unable-to-analyze | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 10 | 10 | 38 | 0.5 | 0.0909 | 0.1538 |

The metrics denominator is explicitly limited to 22 known scored samples. Unknown/partial/blocked/failed samples are not converted to misses.

Root-cause axes:

- vulnerable root causes: 1 TP, 10 FN, 19 unable-to-analyze
- fixed root causes: 1 FP, 10 TN, 19 unable-to-analyze

No family-level Precision/Recall/F1 is published. All six families have incomplete paired coverage, so family metrics are fail-closed. Observed family counts remain available in `metrics.json`.

## Interpretation

These results measure bounded lexical detector behavior against independent developer-acknowledged source defects. They do not establish vulnerability counts, zero false positives/negatives, attacker reachability, privilege bypass, confidentiality/integrity/availability impact or product deployment.

## Reproduction

Freeze generation requires local pinned source repositories and explicit exact-blob acquisition. Evaluation reads only local Git objects with `GIT_NO_LAZY_FETCH=1`; the exact commands and repository mappings are recorded in `run_manifest.json` and the scripts under `scripts/freeze_independent_holdout.py` and `scripts/run_independent_holdout.py`.
