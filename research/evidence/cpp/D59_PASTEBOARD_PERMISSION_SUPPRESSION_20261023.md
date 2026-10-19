# D59 — CVE-2025-27247 permission suppression correction

Date: 2026-10-23 (Asia/Shanghai)

## Scope and frozen identities

D59 starts from frozen D51 detector baseline `c8f83b82291e82b3272c73b943623336a3c836c3` (`ohscanner.known_disclosed_cves` 0.19.3) in an isolated worktree. D58 replay commit `8eb43e33a10e88cc02341df3e9bb91f93d1dc862` and independent T58 commit `1a4252b6925369b04f7efe9462d9670848aff327` recorded that a bare ignored permission result, a post-read check, a post-serialization check, and a valid denial guard nested under `if (false)` all suppressed the CVE-2025-27247 candidate.

D59 changes only the local permission-suppression matcher and its focused tests/corpus controls. It recognizes a suppression shape only when a permission predicate is the complete `if` condition (`!Check...Permission(...)`, `... != PERMISSION_GRANTED`, or `... == PERMISSION_DENIED`), the `if` body begins with `return` or `throw`, and the entire `if` statement ends before the handler's `GetPasteData` call or before the request dispatch's `it->second` route. It excludes a nested candidate guard when its enclosing `if` condition is exactly the literal `false` (case-insensitive). It does not treat a permission-like token alone as a guard.

## Focused results

The unchanged positive shape remains one candidate with rule ID `ohknowncve-pasteboard-cve-2025-27247`, symbol `CVE-2025-27247`, and the existing `OnRemoteRequest` anchor. The following controls were exercised in focused tests:

| Input shape | Result |
|---|---|
| No permission check | candidate retained |
| Bare/ignored `VerifyPermission(...)` before the read | candidate retained |
| Mixed condition `!VerifyPermission(...) && caller_is_special` | candidate retained |
| Permission denial condition with immediate return before read | suppressed as a syntactic control |
| Permission status `!= PERMISSION_GRANTED` with return before read | suppressed as a syntactic control |
| Denial check after `GetPasteData` | candidate retained |
| Denial check after `WriteParcelable` | candidate retained |
| Valid denial guard nested inside `if (false)` before the read | candidate retained |

The pre-existing corpus `fixed.cpp` and `safe.cpp` controls used ignored permission results, so they were corrected to use explicit pre-read denial exits; their fixture SHA-256, Git blob, and byte-count records were updated. No candidate identity for another CVE was intentionally changed. Detector version is advanced from 0.19.3 to 0.19.4.

## Verification

- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — PASS, 32 tests.
- Full `python -m unittest discover -s tests` — 1,110 tests ran, 63 skipped, with 3 failures and 17 errors unrelated to these focused tests. Reported environment/baseline problems include missing `fastapi` and `fcntl`, Windows symlink privilege errors, an unusable configured clang executable (`WinError 193`), snapshot path/hash mismatches, and existing D2 replay output missing. This is not a full-suite pass.

## Limits

This is syntax-shape suppression only; it is not a control-flow graph, dominance, alias, macro-expansion, caller, permission-contract, or framework authorization proof. It does not inspect authorization outside `OnRemoteRequest` and `OnGetPasteData`, and only recognizes the exact constant-false wrapper. `throw` counts as a syntactic exit, but catch/unwind semantics are not modeled; a surrounding local catch could affect whether the path truly exits. Other dead or conditionally unreachable constructs, loops, `goto`, indirect/helper-based permission checks, and ambiguous permission return domains can evade or confuse this local shape. A suppressed candidate therefore does not prove safety. The retained finding remains a source-only candidate; CVE causality, affected/fixed product status, device applicability, exploitability, and runtime authorization are all UNKNOWN.
