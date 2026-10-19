# T59 — Independent Pasteboard permission-guard acceptance

Date: 2026-10-23 (Asia/Shanghai)

## Baseline recorded; patch review pending

T59 prepared an independent acceptance worktree at the D51 frozen scanner commit `c8f83b82291e82b3272c73b943623336a3c836c3` (detector blob `94113fdd45b2273e6ea9dd02c7eeac886b853329`, rule version 0.19.3). The D52 pinned source was fetched as raw bytes from the Git object database, not read from a line-ending-normalized checkout:

- Source commit/tree: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- Stub path/blob: `services/zidl/src/pasteboard_service_stub.cpp` / `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`.
- Raw blob: 6,288 bytes; SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- Exact-unit replay: `blocked`, with D52 candidate `ohknowncve-pasteboard-cve-2025-27247` at line 41, column 1; identity quality is partial and source parse status is partial.

The structured source-local expected matrix is in the companion JSON. It was independently replayed in memory against the frozen detector using a local signature fixture as input; no test suite was run, and no detector, fixture, or expected-output file was changed.

| Probe | Frozen 0.19.3 observed | Required after D59 | Meaning |
|---|---|---|---|
| No permission token in mapped/routed read-and-return path | Candidate | Candidate | Retain positive candidate |
| Bare permission-like call before read, result ignored | Suppressed | Candidate | Reject token-only suppression |
| Visible denial branch after `GetPasteData` | Suppressed | Candidate | Check must precede read |
| Visible denial branch after parcel write | Suppressed | Candidate | A post-disclosure check cannot suppress |
| Valid-looking denial branch nested under `if (false)` before read | Suppressed | Candidate | Dead branch cannot suppress |
| Visible denial branch and early return before read | Suppressed | Suppressed | Syntactic negative control only |

The fixture also emits the separate D51 observer candidate `CVE-2025-25212` for every matrix case. Post-patch review must verify that its rule behavior and other CVE IDs do not regress; the raw pinned-source replay must retain the D52 candidate when no local guard is present.

## Acceptance dimensions

- **fix-correctness:** pending D59's frozen commit. Required: the five matrix expectations above, including the valid early denial branch as the only suppressing shape.
- **candidate-retention:** baseline verified on the exact pinned blob; post-patch replay pending.
- **coverage:** the exact source-unit run is `blocked` and parser state is `partial`; component or framework coverage remains unproven unless separately replayed.
- **scope:** pending D59 diff audit. T59 will not edit detector logic, fixtures, or expected outputs.

These are syntactic candidate expectations. They do not prove permission helper semantics, control-flow dominance in general, framework authorization, CVE causality, product inclusion, or runtime vulnerability. D52 remains a pinned-source candidate with full framework/product/CVE conclusions unknown.

## Reproduction

Baseline source identity and replay were checked from the independent T59 worktree with:

```powershell
git show -s --format="%H %T %s" c8f83b82291e82b3272c73b943623336a3c836c3
git rev-parse c8f83b82291e82b3272c73b943623336a3c836c3:src/ohscanner/detectors/known_cves.py
git --git-dir=D:/openHarmonyScanner/tmp/d51-source-objects ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/zidl/src/pasteboard_service_stub.cpp
```

The raw blob's length, Git blob SHA-1, and SHA-256 were computed in Python via `git cat-file blob`. The detector was invoked directly with `SourceUnit(parse_status="partial")` for the pinned source, and with six in-memory guard variants for the acceptance matrix.
