# D48 distributed_screen frozen-source replay

Date: 2026-10-19. Classification: **blocked, zero candidates; not a safety result and not an accuracy measurement**.

## Frozen input and scanner

- Repository: OpenHarmony distributed_screen from the G-drive campaign-100 source mirror.
- Commit: 373e2b5241c0e5dcb923642059ae83e4e9a1a64e.
- Tree: 431a2a0be0c140846b6ff1cefb0e7adfa19d2088.
- Snapshot SHA-256: 5b7a5b1da878b6c00b38e781d416bd5b921bed17023dc6551128bdc1d7a2c617.
- Scope: 97 tracked C/C++ source/header files under the preregistered D19 path filter; scope path SHA-256 ed0b65517d5b9de40e180a8924b1885d110179675f4497a64c116ee9498db489.
- Detector: ohscanner.data.sensitive_exposure 0.21.0; source model 0.4.0; sink model 0.8.0. Frozen detector and replay-script hashes are recorded in D48_HOLDOUT_PREREGISTRATION.md.

The scan ran twice against the exact Git tree and produced matching candidate signatures and coverage. Both runs returned zero candidates. All 97 eligible files were only partially inspected; zero were reported as fully analyzed. Detector status was blocked and task status completed_with_limitations. Two-run wall time was 1.1613 seconds and peak RSS 36,732 KiB. Raw reports and hashes are in this directory's summary.json, first.json, and replay.json.

## Interpretation

This sample was not previously named in D research records, and the campaign README says its C/D scan gate had not run. It is a convenience sample from a stratified A/B campaign, not a population-random sample. The source set has no independent line-bound labels. Therefore the zero-candidate result gives no FN count and cannot estimate recall or precision. Given partial coverage of every file, it cannot be called clean or safe.

The D detector and models were not changed after preregistration. Do not use D48 to tune the current implementation and then continue calling it a holdout. A future accuracy result requires a separately frozen sample and an independent reviewer blinded to detector predictions. Product inclusion, runtime behavior, caller reachability, log-reader authorization, CIA impact, affected product versions, product PoC, and fixed-product retest remain unknown; product vulnerability count remains zero.

## Reproduction

From the D branch repository root, with the project web Python environment available:

    PYTHONPATH=. .venv-web/bin/python research/data_sensitive/d19_unreviewed_replay.py --repo-dir /path/to/read-only-distributed_screen-commit-373e2b5 --repository openharmony/distributed_screen --commit 373e2b5241c0e5dcb923642059ae83e4e9a1a64e --output-dir /tmp/d48-distributed-screen

The replay tool reads pinned Git objects and writes only to its output directory.