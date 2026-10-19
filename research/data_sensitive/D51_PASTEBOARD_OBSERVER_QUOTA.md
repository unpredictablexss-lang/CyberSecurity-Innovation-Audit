# D51 — Pasteboard observer quota candidate

Date: 2026-10-20 (Asia/Shanghai)

## Result

D51 refined `ohscanner.known_disclosed_cves` from 0.18.0 to 0.19.0. The fixed vulnerable-source replay now reports the candidate on the repeated set insertion itself (`observers->insert(observer)`, line 241, column 5), instead of the method opening at line 222. The detector requires the named observer registry map and insertion of the observer into a set-like collection, and it suppresses a finding when a direct count bound or a same-file helper body exposes a hard observer limit. It no longer treats the mere presence of a caller identity accessor as evidence of a quota.

The exact vulnerable snapshot shows `observerMap_` keyed by the account `userId` returned from `GetUserId()` / `IPCSkeleton::GetCallingUid()`. Its map value is a `std::set` ordered by the remote observer object's pointer. Re-registering the identical Binder observer deduplicates, but this is not a bound on distinct observer objects. The file contains single-observer removal and remove-all-for-user methods; no automatic cleanup for observer death was found in the inspected source. The ZIDL handler maps `ADD_OBSERVER`, reads and casts a remote object, then calls the registration method directly. Service ACLs and product caller reachability remain unknown.

The official OpenHarmony 5.0.3 branch has a strong fixed-mechanism control in merged PR !1539 (`836cf699...`): observer entries are keyed by `(userId, callingPid)` and the implementation enforces `MAX_OBSERVER_COUNT = 10` before insertion. That revision refactors the API to `AddObserver`, so its zero-hit under the old function signature is not treated as proof that the lexical rule detects the fix. A same-shape unit control confirms direct hard quotas and same-file quota helpers suppress the candidate.

The official CVE record describes a local denial of service by improper input on OpenHarmony v5.0.3 and prior. It does not identify this exact source line. The source/fix pair supports a component-source candidate for second-layer review, not confirmed CVE causality or product impact.

## Source identity and replay

Vulnerable source: official Gitee `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, path `services/core/src/pasteboard_service.cpp`, blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`. D50's full component snapshot SHA-256 is `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`.

Fixed-mechanism source: official Gitee `openharmony/distributeddatamgr_pasteboard`, `OpenHarmony-5.0.3-Release`, merged PR [!1539](https://gitee.com/openharmony/distributeddatamgr_pasteboard/pulls/1539), commit `836cf6990579451d6521e9177d749660b07ad34e`, tree `8db5ac5a62c018c80818c85482e4914a836a4765`, same relative source path, blob `af95e87bed596cc9f159bbf020536ea361835977`, SHA-256 `e8202191adf1d660a7a6c3149481013747e1a40b6bb166aa5947fb28b67ad3d4`.

D50's historical 0.16.0 output and a frozen 0.18.0 replay both place the candidate at line 222. D51's 0.19.0 single-source replay binds the same source hash and places one candidate at line 241. The isolated replay is one source unit only and explicitly supplies `parse_status=partial` as a conservative source-only input (not a new parser result). The D50 component scan stays partial/blocked, and no post-change full component scan is claimed. The fixed source one-file replay has zero findings but is marked partial and is non-diagnostic for rule sensitivity because its API/function name changed.

## Controls and coverage

- Exact vulnerable source: one candidate at the repeated set insertion.
- Exact fixed source: source contains the per-process aggregate count and limit of 10; method was refactored, so the old signature does not match.
- Same-shape hard quota: no candidate.
- Same-file helper with a visible hard quota: no candidate.
- Set deduplication: retained as an informative positive; deduplicating identical object references does not cap distinct references.
- Removal/lifecycle: explicit remove and remove-all exist; no complete or automatic caller-death cleanup proof was established.
- Unrelated map growth: no candidate.
- Partial parse: candidate is retained and the run remains blocked.

The CVE record at [NVD](https://nvd.nist.gov/vuln/detail/cve-2025-25212) cites the official [OpenHarmony July 2025 disclosure](https://gitee.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-07.md). Findings remain candidates with `product_vulnerability_confirmed=false`.

## Reproducible commands

```powershell
$mirror = 'D:/openHarmonyScanner/tmp/d51-source-objects'
git init --bare $mirror
git --git-dir=$mirror fetch --no-tags https://gitee.com/openharmony/miscservices_pasteboard.git dd22c7cb5e5f207a6c38c50f45b7369ee8575840
git --git-dir=$mirror cat-file -p dd22c7cb5e5f207a6c38c50f45b7369ee8575840
git --git-dir=$mirror ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/core/src/pasteboard_service.cpp
cmd /c "git --git-dir=D:/openHarmonyScanner/tmp/d51-source-objects cat-file blob c380ac266a85edd818caa811f11b99722d351788 > D:/openHarmonyScanner/tmp/d51-pasteboard-service.cpp"
Get-FileHash D:/openHarmonyScanner/tmp/d51-pasteboard-service.cpp -Algorithm SHA256

$fixedMirror = 'D:/openHarmonyScanner/tmp/d51-fixed-source-objects'
git init --bare $fixedMirror
git --git-dir=$fixedMirror fetch --no-tags https://gitee.com/openharmony/distributeddatamgr_pasteboard.git 836cf6990579451d6521e9177d749660b07ad34e
git --git-dir=$fixedMirror cat-file -p 836cf6990579451d6521e9177d749660b07ad34e
git --git-dir=$fixedMirror ls-tree 836cf6990579451d6521e9177d749660b07ad34e services/core/src/pasteboard_service.cpp
cmd /c "git --git-dir=D:/openHarmonyScanner/tmp/d51-fixed-source-objects cat-file blob af95e87bed596cc9f159bbf020536ea361835977 > D:/openHarmonyScanner/tmp/d51-fixed-pasteboard-service.cpp"
Get-FileHash D:/openHarmonyScanner/tmp/d51-fixed-pasteboard-service.cpp -Algorithm SHA256
python -m pytest tests/detectors/test_known_disclosed_cves.py tests/detectors/test_known_case_corpus.py -q
git diff --check
```

## Verification

- `python -m pytest tests/detectors/test_known_disclosed_cves.py tests/detectors/test_known_case_corpus.py -q` — 31 passed.
- `git diff --check` — passed.
- Scope verifier: N/A because frozen `ownership.json` has no D lane. Changed paths were manually checked against the task-authorized D51 surfaces; no ownership policy or checker changes were made.

Machine-readable source identities, candidate packet, controls, limits, and commands are in [D51_PASTEBOARD_OBSERVER_QUOTA.json](D51_PASTEBOARD_OBSERVER_QUOTA.json).
