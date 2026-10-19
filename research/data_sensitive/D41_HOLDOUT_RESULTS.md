# D41 cross-component sensitive-data holdout replay

Date: 2026-10-19. State: **replayed; independent labels pending**.

## Frozen scope and execution

Before scanning, the study froze six non-development OpenHarmony source snapshots, the detector baseline (`main` commit `efb79ee2397396f38bb0df5d4703f55d7977f138`), detector 0.17.0, and an engine bundle SHA-256 `9d0f2763a97f3fcaaa1841355a89cf8fdd93a422042db2f9dc5a0664dfb0ea9e`. The exact repository commits, trees, scope counts, and file identities are in `D41_HOLDOUT_MANIFEST.json` and `D41_HOLDOUT_PREREGISTRATION.md`. Every component was scanned twice from pinned Git objects; all six repeat signatures were stable. Source worktrees were not modified.

| Component | Files | Candidates | Partial | Not analyzed | Time (two-round replay) | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| security_huks | 537 | 14 | 150 | 387 | 7.29 s | 86,264 KiB |
| security_certificate_manager | 304 | 148 | 240 | 64 | 5.08 s | 59,660 KiB |
| inputmethod_imf | 402 | 10 | 330 | 72 | 5.88 s | 74,128 KiB |
| window_window_manager | 1,079 | 3 | 811 | 268 | 37.96 s | 316,868 KiB |
| telephony_call_manager | 393 | 22 | 324 | 69 | 7.47 s | 78,100 KiB |
| multimedia_camera_framework | 1,105 | 4 | 932 | 173 | 20.86 s | 174,348 KiB |
| **Total** | **3,820** | **201** | **2,787** | **1,033** | **84.54 s summed** | **316,868 KiB max** |

All 201 observations use `data.sensitive.unresolved-escape`, CWE `none`. No direct `data.log.sensitive-value` finding was produced. All six detector runs were `blocked`, had zero complete files, and completed with limitations. The large certificate-manager candidate count (148/304 files) is a review workload signal, not a false-positive count.

## Independent review packet and limits

`D41_BLIND_REVIEW_PACKET.json` contains 99 cases: up to eight candidate observations and ten no-hit control files per component. Case metadata binds the exact component commit/tree, path, anchor, and source SHA-256 while omitting the scanner prediction. The review key is stored outside the repository and must remain hidden until labels are frozen. The packet was sampled after the scans, so it supports case review and possible miss discovery; it is not a preregistered random holdout and cannot estimate population precision or recall.

No independent labels have been recorded: `supported_risk=0`, `protected_safe=0`, `unrelated=0`, `unknown=0`. TP/FP/FN/TN, precision, and recall are therefore not estimable. The scan did not establish that any output reaches a public log sink, is visible to an unauthorized reader, or is included in a product build. Every finding remains a candidate, and `validated_vulnerability=0`.

## Reproduce and verify

The preregistration and collection scripts are `d41_freeze_holdout.py` and `d41_collect_holdout.py`. Per-component first/replay JSON reports are under `D41_HOLDOUT/<component>/`; the aggregate machine result is `D41_HOLDOUT_RESULTS.json`. Collection rechecks the frozen engine bundle, repository trees, and repeat signatures before creating the blind packet. Do not tune detector/model/source filters on this set before independent labels are frozen; if it is used for tuning, it becomes development data and a new holdout is required.

The source-line review can proceed in the following order: verify each source file hash against the manifest; inspect the listed source and call path in the frozen commit; record both supporting and contradicting evidence; use `unknown` when sink semantics, caller identity, control flow, or runtime visibility cannot be bound. A local scanner observation alone is not a label.