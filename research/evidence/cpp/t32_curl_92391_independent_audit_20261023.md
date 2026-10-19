# T32 independent curl CVE-2026-92391 static regression audit

Date: 2026-10-23 (Asia/Shanghai)
Acceptance checkout: `385e0266301793a45d9df84f7a18a3f1a3b07efc`
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`
Rule: `ohcpp-resource-lifetime-recursive-cleanup-candidate-003`

## Source-bound replay

T32 used the pinned local curl Git object store `D:/openHarmonyScanner/tmp/curl-upstream-pins-20261019.git` and the production CLI, each with `--include lib/mime.c` and exactly one selected detector. Both source objects were verified independently by commit, tree, file blob OID, and SHA-256; both target files parsed completely and received complete detector coverage.

| Variant | Commit / tree | `lib/mime.c` blob / SHA-256 | Result |
|---|---|---|---|
| Vulnerable | `01346829096c61b372692f6dc43ffa778c6caccd` / `6ae23d9333713707a02588b44ed238a50e8b3bde` | `600437576581be08f9026881c39178857a1c5939` / `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` | 1 same-rule candidate, `lib/mime.c:1118`, `curl_mime_free` |
| Fixed | `d7546809d5bd548b69ec49fca26565c8f6f0d344` / `52a8416729366487cdd3b6012071f5f8370e769f` | `3522679a16e2fa560c581413bf946d38e332bea4` / `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` | 0 same-rule candidates |

Both production CLI reports identify the current rule version `0.4.2` and identical `light-ast`, `lib/mime.c` scope. Snapshot hashes match the already recorded exact snapshots: vulnerable `c0ca047682dce16d7aec8a1607b06f7a0420602a6a0ae13b8195f6629a1ac730`, fixed `cbc4bf484c7dacefd8869f7917b00983569e8d012470e88f278fc6104744c2f6`. Raw outputs are [vulnerable CLI JSON](t32_curl_vulnerable_cli_20261023.json) and [fixed CLI JSON](t32_curl_fixed_cli_20261023.json).

## Rule regression and disposition

`python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v` passed all 8 tests on this independent checkout. The hash-bound fixture manifest covers positive, fixed, safe, unrelated, and unknown/partial controls. The focused tests include the recursive-cleanup positive, detached-callback fixed control, unrelated recursive-cleanup control, and partial-input behavior; they also rerun the resource-lifetime detector's additional safe/unrelated controls. This is **PASS for the current rule's focused mechanism regression**.

The exact vulnerable/fixed source differential is **PASS for static candidate regression** (1/0 with equal detector version and complete parse/coverage). It is not a product/CVE verdict. The report's candidate still has `identity_quality=partial` and unknown callback binding/semantic obligations; no current OpenHarmony product build, call path, attacker-reachable nested MIME depth, runtime exhaustion, or impact was established. Record product/CVE status as **PARTIAL/BLOCK** pending those independent facts. No A0 ID or status was changed.

Reproduction commands:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit 01346829096c61b372692f6dc43ffa778c6caccd --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/t32_curl_vulnerable_cli_20261023.json
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit d7546809d5bd548b69ec49fca26565c8f6f0d344 --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/t32_curl_fixed_cli_20261023.json
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v
python research/evidence/cpp/verify_t32_curl_92391_audit.py --source-git-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 385e0266301793a45d9df84f7a18a3f1a3b07efc --lane cpp
git diff --check
```

## Scope

This is an evidence-only T32 acceptance change. No detector, tests, fixtures, catalog, API, or A0 ledger contents were modified. See the machine record and verifier for exact assertions.
