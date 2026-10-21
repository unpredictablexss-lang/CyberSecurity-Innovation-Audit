# DATA-06 local mainline demo (2026-10-21)

## Mainline and B-closeout comparison

After a successful `git fetch origin main codex/b-ipc-closeout-20261020`,
`origin/main` is `b957894ca0229d7a6b0557b87d35e1c2ac877b07` (tree
`a8e1ca39deb827e253b6fe9f86679a1dc1ede2a5`) and the actual current tip of
`origin/codex/b-ipc-closeout-20261020` is
`96cfc453c15263ec3ec83ce87aa75d08d221b445` (tree
`e413abe82124654ffdd93b5bba82db407280ea9f`). They diverge after
`4b0e16576a45a111b4fad7e8f82819a47ed472f5`: mainline is 7 commits ahead and
B is 6 commits ahead. The DATA-06 detector, rule helper, family entry, and
model blobs match exactly. B adds the source-semantic PoC and evidence package.
The direct ref comparison also shows eight shared-code files changed on B:
`contracts.py`, `known_cves.py`, `runner.py`, `operations_api.py`, `service.py`,
`test_known_disclosed_cves.py`, `test_workbench.py`, and `JobDetail.tsx`.
Together those changes remove known-CVE evidence fields and existing risk detail
presentation from current mainline versions. This delivery keeps the mainline
API, panel, and known-CVE fields and adds DATA-06 traceability. Exact detector
blobs are recorded in `data06_runtime_poc_20261021/source_bindings.json`.

## Reproducible scan-to-detail path

The new workbench integration test scans the exact source bytes from official
`communication_ipc` commits in its own temporary target repository and
temporary workbench data directory. The vulnerable scan reports one
`ipc.parcel.array-allocation-width` candidate at
`interfaces/innerkits/cj/src/message_sequence_impl.cpp:1188`. The finding-detail
API returns that source hash, line, risk assessment, source location, PoC
metadata, and the same report hash used by the report endpoint. The test then
scans the official fixed-source bytes and observes zero DATA-06 findings.

Saved outputs are under
`data06_runtime_poc_20261021/artifacts/workbench_api_replay/`:

- `vulnerable_report.json` and `vulnerable_report.md` contain the immutable
  candidate report.
- `finding_detail.json` is the finding-detail API response consumed by the
  panel.
- `finding_evidence.md` is the readable report companion linking the source
  location and CVE mapping basis to the semantic PoC, upstream fix, retest,
  hashes, and evidence limits.
- `fixed_report.json` and `fixed_report.md` preserve the fixed-source replay.
- `summary.json` binds both source byte hashes, the local scan commits, the
  report hashes, the detail hash, and the fixed result.
- `SHA256SUMS` verifies all saved outputs and replay logs.

The source candidates are bound separately to official commit/tree/blob and
SHA-256 identities in `source_bindings.json`. The test's temporary Git commits
are transport wrappers for the official source bytes, not OpenHarmony release
identifiers.

## Risk and evidence limits

The T74 regression manifest associates the function root with
`CVE-2025-26474`; NVD is linked as the mapping source. The disclosure does not
identify this allocation-width primitive as the CVE root cause. The report and
detail explicitly label this as provenance only. The detector finding remains
`candidate/unknown`, with severity and product applicability unassessed.

The ASan harness is an isolated source-semantic model. It reports a heap
buffer overflow for the vulnerable allocation, returns cleanly for the fixed
allocation, and rejects zero and insufficient-byte controls. The lossless raw
stderr is retained as base64; decoded stderr SHA-256 is
`b27931bbf0ae57391ae40046f5a8c0899a8f49f357a5caeecd9e35630fd6747b` (3,609
bytes). This does not compile the OpenHarmony component, establish
Binder/DBinder reachability, or prove product impact.

## Verification

- Focused DATA-06/T74 suite: 44 passed, 576 subtests passed.
- IPC regression set: 423 passed, 1 skipped, 712 subtests passed.
- Isolated workbench candidate/detail/fixed replay: 1 passed.
- Web tests: 68 passed; TypeScript check and production build passed.
- Harness replay: vulnerable positive, fixed positive control, zero-count
  negative, and insufficient-Parcel-byte negative all matched expectations.

The isolated API replay and its saved report/detail hashes were refreshed after
this verification. See `data06_runtime_poc_20261021/artifacts/workbench_api_replay/summary.json`
and both adjacent `SHA256SUMS` manifests for the current run identities.
