# T59 — Independent Pasteboard permission-guard acceptance

Date: 2026-10-23 (Asia/Shanghai)

## Independent review of D59 follow-up; new permission-identity failure

T59 prepared an independent acceptance worktree at the D51 frozen scanner commit `c8f83b82291e82b3272c73b943623336a3c836c3` (detector blob `94113fdd45b2273e6ea9dd02c7eeac886b853329`, rule version 0.19.3). The D52 pinned source was fetched as raw bytes from the Git object database, not read from a line-ending-normalized checkout:

- Source commit/tree: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` / `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- Stub path/blob: `services/zidl/src/pasteboard_service_stub.cpp` / `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`.
- Raw blob: 6,288 bytes; SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- Exact-unit replay: `blocked`, with D52 candidate `ohknowncve-pasteboard-cve-2025-27247` at line 41, column 1; identity quality is partial and source parse status is partial.

The structured source-local expected matrix is in the companion JSON. It was independently replayed in memory against frozen baseline c8 and final D59 commit `da0195610f2203ce97af1f43385f0091f040504e` (0.19.5) in a detached test worktree. T59 changed no detector, fixture, or expected-output file.

| Probe | Frozen 0.19.3 observed | D59 0.19.5 observed | Meaning |
|---|---|---|---|
| No permission token in mapped/routed read-and-return path | Candidate | Candidate | Retain positive candidate |
| Bare permission-like call before read, result ignored | Suppressed | Candidate | Reject token-only suppression |
| Visible denial branch after `GetPasteData` | Suppressed | Candidate | Check must precede read |
| Visible denial branch after parcel write | Suppressed | Candidate | A post-disclosure check cannot suppress |
| Valid-looking denial branch nested under `if (false)` before read | Suppressed | Candidate | Dead branch cannot suppress |
| Visible denial branch and early return before read | Suppressed | Suppressed | Syntactic negative control only |
| Visible denial branch and immediate throw before read | Suppressed | Suppressed | Syntactic exit control; catch/unwind behavior is not modeled |
| Denial guard nested under `if (is_privileged)` before read | Suppressed | Candidate | Outer branch can bypass the denial exit |

The fixture also emits the separate D51 observer candidate `CVE-2025-25212` for every matrix case. It remained present in every probe. Exact pinned-source replay retained the D52 candidate with its original ID, line 41:1 anchor, and source hash.

## Independent verification

- Final D59 commit: `da0195610f2203ce97af1f43385f0091f040504e`, based on c8 detector commit `c8f83b82291e82b3272c73b943623336a3c836c3`; D59 version is 0.19.5. The prior 0.19.4 commit `7182aaf7c2334a3cf91dcf9a1016116b4709fccd` failed the non-dominating conditional-guard probe; the follow-up added a top-level guard restriction and regression control.
- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — **PASS, 32/32**.
- Replayed all 67 C/C++ source units from the D50 saved-parser packet, using raw source Git blobs, against c8 and D59. Both runs are `blocked`, with identical findings: D51 `CVE-2025-25212` at `services/core/src/pasteboard_service.cpp:241:5` and D52 `CVE-2025-27247` at `services/zidl/src/pasteboard_service_stub.cpp:41:1`. Both retain their original per-file SHA-256 values. Parser states remain 57 complete / 10 partial.
- `git diff --check c8..da019561` — **PASS**. The final diff has 8 files (243 insertions / 12 deletions): the known-CVE detector, focused regression and corpus checks, two D52 fixture controls with corresponding manifest hash/byte updates, and the D59 evidence packet. The follow-up delta is limited to top-level guard checking, its regression, and report caveats. No unrelated detector implementation changed.
- Full test discovery was not independently rerun. D59's report records 3 failures and 17 errors in that wider run with environment/baseline causes; this acceptance does not claim a full-suite pass.

### Supplemental non-dominating-guard follow-up

An additional in-memory probe placed a valid-looking denial branch under `if (is_privileged)` and then performed `GetPasteData()` after the outer conditional. Baseline c8 and D59 0.19.4 suppressed the candidate, even though the outer false branch bypasses the denial exit. T59 reported this to root and D59. D59 0.19.5 requires the guard to be top-level in the checked method; the exact probe now retains the candidate and is included in D59 regression tests.

### Unrelated-permission false suppressions

An independent D59 0.19.5 in-memory probe inserted each of these exact top-level guards before `GetPasteData(); reply.WriteParcelable(data);`:

```cpp
if (!CheckBluetoothPermission()) return ERR_NO_PERMISSION;
GetPasteData(); reply.WriteParcelable(data);
```

```cpp
if (!CheckPermission(PERMISSION_NETWORK)) return ERR_NO_PERMISSION;
GetPasteData(); reply.WriteParcelable(data);
```

```cpp
if (!VerifyCallingPermission(PERMISSION_NETWORK)) return ERR_NO_PERMISSION;
GetPasteData(); reply.WriteParcelable(data);
```

All three runs completed with only the separate D51 `CVE-2025-25212` finding; D52 `CVE-2025-27247` was suppressed. The generic permission-name matcher does not bind the permission or resource to Pasteboard read access. This is an actionable candidate-retention precision failure for D60/D61, not evidence about runtime helper semantics.

## Acceptance dimensions

- **fix-correctness:** **PARTIAL**. The specified matrix and conditional-outer-branch adversary pass on D59 0.19.5, but unrelated Bluetooth/Network permission guards still suppress D52. Immediate `return`/`throw` are syntactic exits only; exception/catch behavior is not modeled.
- **candidate-retention:** **PASS on the exact pinned source** and 67-unit replay, but **FAIL** on the three unrelated-permission controls above. The historical D52 and separate D51 candidate remain on the pinned source.
- **coverage:** **PARTIAL**. The exact source-unit and full 67-unit replay remain blocked; the D50 parser packet has 57 complete and 10 partial units. Product/framework coverage is not established.
- **scope:** **PASS for final commit `da019561`**. The final patch changes the D52 matcher, focused controls/corpus, and the two corresponding fixture bindings. T59's evidence files are separate; T59 made no detector or fixture edits. Assign permission identity binding/conservative ambiguity behavior to D60/D61.

These are syntactic candidate expectations. They do not prove permission helper semantics, control-flow dominance in general, framework authorization, CVE causality, product inclusion, or runtime vulnerability. D52 remains a pinned-source candidate with full framework/product/CVE conclusions unknown.

## Reproduction

Baseline source identity and replay were checked from the independent T59 worktree with:

```powershell
git show -s --format="%H %T %s" c8f83b82291e82b3272c73b943623336a3c836c3
git rev-parse c8f83b82291e82b3272c73b943623336a3c836c3:src/ohscanner/detectors/known_cves.py
git --git-dir=D:/openHarmonyScanner/tmp/d51-source-objects ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/zidl/src/pasteboard_service_stub.cpp
```

The raw blob's length, Git blob SHA-1, and SHA-256 were computed in Python via `git cat-file blob`. The detector was invoked directly with `SourceUnit(parse_status="partial")` for the pinned source and with in-memory guard variants for the baseline and patched matrix. The full-component comparison used the 67 paths and parser states listed in the D50 report.
