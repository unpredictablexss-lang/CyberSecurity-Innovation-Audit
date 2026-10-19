# T59 — Independent Pasteboard permission-guard acceptance

Date: 2026-10-23 (Asia/Shanghai)

## Frozen patch reviewed; one precision failure sent for follow-up

T59 prepared an independent acceptance worktree at the D51 frozen scanner commit `c8f83b82291e82b3272c73b943623336a3c836c3` (detector blob `94113fdd45b2273e6ea9dd02c7eeac886b853329`, rule version 0.19.3). The D52 pinned source was fetched as raw bytes from the Git object database, not read from a line-ending-normalized checkout:

- Source commit/tree: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- Stub path/blob: `services/zidl/src/pasteboard_service_stub.cpp` / `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`.
- Raw blob: 6,288 bytes; SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- Exact-unit replay: `blocked`, with D52 candidate `ohknowncve-pasteboard-cve-2025-27247` at line 41, column 1; identity quality is partial and source parse status is partial.

The structured source-local expected matrix is in the companion JSON. It was independently replayed in memory against both the frozen baseline and D59 in a detached test worktree. T59 changed no detector, fixture, or expected-output file.

| Probe | Frozen 0.19.3 observed | Required after D59 | Meaning |
|---|---|---|---|
| No permission token in mapped/routed read-and-return path | Candidate | Candidate | Retain positive candidate |
| Bare permission-like call before read, result ignored | Suppressed | Candidate | Reject token-only suppression |
| Visible denial branch after `GetPasteData` | Suppressed | Candidate | Check must precede read |
| Visible denial branch after parcel write | Suppressed | Candidate | A post-disclosure check cannot suppress |
| Valid-looking denial branch nested under `if (false)` before read | Suppressed | Candidate | Dead branch cannot suppress |
| Visible denial branch and early return before read | Suppressed | Suppressed | Syntactic negative control only |
| Visible denial branch and immediate throw before read | Suppressed | Suppressed | Syntactic exit control; catch/unwind behavior is not modeled |

The fixture also emits the separate D51 observer candidate `CVE-2025-25212` for every matrix case. It remained present in every probe. Exact pinned-source replay retained the D52 candidate with its original ID, line 41:1 anchor, and source hash.

## Independent verification

- Frozen D59 commit: `7182aaf7c2334a3cf91dcf9a1016116b4709fccd`, based on c8 detector commit `c8f83b82291e82b3272c73b943623336a3c836c3`; D59 version is 0.19.4.
- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — **PASS, 32/32**.
- Replayed all 67 C/C++ source units from the D50 saved-parser packet, using raw source Git blobs, against c8 and D59. Both runs are `blocked`, with identical findings: D51 `CVE-2025-25212` at `services/core/src/pasteboard_service.cpp:241:5` and D52 `CVE-2025-27247` at `services/zidl/src/pasteboard_service_stub.cpp:41:1`. Both retain their original per-file SHA-256 values. Parser states remain 57 complete / 10 partial.
- `git diff --check c8..D59` — **PASS**. The diff has 8 files (237 insertions / 12 deletions): the known-CVE detector, focused regression and corpus checks, two D52 fixture controls with corresponding manifest hash/byte updates, and the D59 evidence packet. No unrelated detector implementation changed.
- Full test discovery was not independently rerun. D59's report records 3 failures and 17 errors in that wider run with environment/baseline causes; this acceptance does not claim a full-suite pass.

### Supplemental non-dominating-guard failure

An additional in-memory probe placed a valid-looking denial branch under `if (is_privileged)` and then performed `GetPasteData()` after the outer conditional. Both c8 and frozen D59 suppress the candidate. The false outer branch bypasses the denial exit, so this is an actionable non-dominating-guard false suppression for candidate retention. T59 sent the exact shape to root and D59 for correction. This case is distinct from the explicitly handled literal `if (false)` adversary.

## Acceptance dimensions

- **fix-correctness:** **FAIL pending follow-up**. The required D58/T58 matrix passes, including immediate `return`/`throw` exits as syntactic controls, but the supplemental conditional outer branch still suppresses although it can bypass the denial exit. Exception/catch behavior is also not modeled.
- **candidate-retention:** **PASS on the exact pinned source**: the historical D52 candidate remains, and the separate D51 sibling candidate remains. This does not offset the supplemental synthetic false suppression described above.
- **coverage:** **PARTIAL**. The exact source-unit and full 67-unit replay remain blocked; the D50 parser packet has 57 complete and 10 partial units. Product/framework coverage is not established.
- **scope:** **PASS for frozen commit `7182aaf7`**. The frozen patch changes the D52 matcher, focused controls/corpus, and the two corresponding fixture bindings. T59's evidence files are separate; T59 made no detector or fixture edits. A follow-up patch is pending.

These are syntactic candidate expectations. They do not prove permission helper semantics, control-flow dominance in general, framework authorization, CVE causality, product inclusion, or runtime vulnerability. D52 remains a pinned-source candidate with full framework/product/CVE conclusions unknown.

## Reproduction

Baseline source identity and replay were checked from the independent T59 worktree with:

```powershell
git show -s --format="%H %T %s" c8f83b82291e82b3272c73b943623336a3c836c3
git rev-parse c8f83b82291e82b3272c73b943623336a3c836c3:src/ohscanner/detectors/known_cves.py
git --git-dir=D:/openHarmonyScanner/tmp/d51-source-objects ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/zidl/src/pasteboard_service_stub.cpp
```

The raw blob's length, Git blob SHA-1, and SHA-256 were computed in Python via `git cat-file blob`. The detector was invoked directly with `SourceUnit(parse_status="partial")` for the pinned source and with in-memory guard variants for the baseline and patched matrix. The full-component comparison used the 67 paths and parser states listed in the D50 report.
