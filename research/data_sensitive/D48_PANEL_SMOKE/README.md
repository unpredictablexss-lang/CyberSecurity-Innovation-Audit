# D48 current-version panel positive-control smoke

Date: 2026-10-19. This is a synthetic integration control, not an independent holdout or product scan.

## Fixed run

- D branch: feat/d-commercial-next-20261019, code commit ca3b87f3493652f42241d916eabae125e6f9e93e.
- Detector: ohscanner.data.sensitive_exposure 0.21.0, explicitly selected in the repository scan page; default checkbox was observed off before selection.
- Isolated API + Worker: 127.0.0.1:18767, data directory /tmp/ohscanner-d48-panel-data. The user's 8765 service was unreachable; the separate 18765 service displayed detector 0.18.0 and was not used for this test.
- Synthetic repository: local/d48-d43-positive-control, commit 052f5c0acf5654204b3512d470ee5f4f278d5b69, tree b439c20314be3f8cd3a0d2c0eaa2fbfa42feef6e, snapshot SHA-256 ceeded7747ef8d7bb5e7f6e306ab0b4168376c1e35bbb6d0b6e9ffc994e4cbe2.
- Task: 3ee8b5e9e94a4f5cba4368c85bffcb84, completed_with_limitations in 0.33 s.

The browser selected the D sensitive-data rule, previewed the plan, created a fixed-commit scan, and showed one candidate at fixture.cpp:1 (`data.log.sensitive-value`, CWE-532, analysis partial, human review pending). DetectorRun was blocked; all six obligations were unknown and zero findings were confirmed. The evidence drawer bound the source to SHA-256 d266af23568ac2e6341d9f4b5ebeead4c014f9e611223f68fb91dc3dcf0d9304. The report page exposed manifest.json, report.json, report.md, review.json, and review.md; report.json SHA-256 is 95ac1f1547d6de78d187dda0db6bc222a7e519f52bad1bf273e102d3fb09477f and snapshot SHA-256 matched the registered source.

This fixture was used in the earlier D44 browser acceptance, so the result only confirms current 0.21.0 page → API → Worker → candidate evidence → persisted report integration. The source contains synthetic heuristic evidence; it does not demonstrate a real secret, exploit, product vulnerability, or independent accuracy. The separate D48 97-file distributed_screen zero-candidate replay remains blocked/partial and is documented in D48_HOLDOUT.

## Pinned report artifacts

- [Manifest](manifest.json), SHA-256 af3d8d0de2a0f0e943dba8ca4c09ad0a32d888e980d6d2ae684cd2960e1b9b99
- [JSON report](report.json), SHA-256 95ac1f1547d6de78d187dda0db6bc222a7e519f52bad1bf273e102d3fb09477f
- [Markdown report](report.md), SHA-256 b602e475e3eda177b308bdaef3fb719b56b70048ceb18d699a60f90b3700c7e5