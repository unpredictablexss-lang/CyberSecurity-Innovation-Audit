# D32 — curl CVE-2026-92391 current production replay

Date: 2026-10-22 (Asia/Shanghai)  
Scanner checkout: `385e0266301793a45d9df84f7a18a3f1a3b07efc` (`codex/a-d32-curl92391-20261022`)  
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`  
Rule: `ohcpp-resource-lifetime-recursive-cleanup-candidate-003` (`0.4.2`)

## Exact-source replay

Both inputs were read from the already-present local bare object store `D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git`; this run performed no fetch. `git ls-tree`/`cat-file` and the production CLI reports bind the inputs to upstream commit, tree, blob, and file SHA-256:

| Input | Upstream commit | Tree | `lib/mime.c` blob | File SHA-256 | Parse / coverage | Result | Detector elapsed |
|---|---|---|---|---|---|---|---:|
| Vulnerable 8.22.0 | `01346829096c61b372692f6dc43ffa778c6caccd` | `6ae23d9333713707a02588b44ed238a50e8b3bde` | `600437576581be08f9026881c39178857a1c5939` | `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` | complete; 1/1 selected file | 1 CWE-674 candidate at `lib/mime.c:1118`, `curl_mime_free` | 0.0817073 s |
| Exact fix | `d7546809d5bd548b69ec49fca26565c8f6f0d344` | `52a8416729366487cdd3b6012071f5f8370e769f` | `3522679a16e2fa560c581413bf946d38e332bea4` | `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` | complete; 1/1 selected file | 0 same-rule candidates | 0.0775187 s |

Commands (run from this checkout, with Python 3.13.9 and the current source tree):

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit 01346829096c61b372692f6dc43ffa778c6caccd --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/d32_curl92391_vulnerable_20261022.json --md-out research/evidence/cpp/d32_curl92391_vulnerable_20261022.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit d7546809d5bd548b69ec49fca26565c8f6f0d344 --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/d32_curl92391_fixed_20261022.json --md-out research/evidence/cpp/d32_curl92391_fixed_20261022.md
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v
```

Raw CLI JSON and Markdown reports are adjacent. The finding is unassessed syntax evidence; it does not prove a product build, product reachability, attacker control, or impact. Current source parser coverage is complete for this one file, so the vulnerable/fix delta is not explained by a partial parse.

## Existing D3 regression controls

The current HEAD's resource-lifetime module passed all 8 tests (`Ran 8 tests ... OK`), including the existing recursive-cleanup candidate and `test_fixed_unrelated_and_unknown_controls`, deterministic output/budget, hash-bound fixture manifest, cross-rule resource exhaustion separation, and partial-status controls. These are the existing D3 family regressions exercised by the module. The exact real-source fixed commit is also quiet under the same current detector, scope, and parser.

No current regression was observed, and this replay did not justify a detector code change. D3's older 0.3.0 report is retained as history; this current replay is 0.4.2. Source manifest, A0 queue, and statuses were not edited. Missing source-level safe/unrelated real-world controls remain a limitation; synthetic fixture controls are not promoted to independent real-world labels.

## Status

Static root-cause candidate regression: **PASS** for this exact vulnerable/fixed source pair and complete target-file parse. Product vulnerability confirmation: **not assessed**. No API or diagnostic schema changes. See `d32_curl92391_current_replay_20261022.json` and `verify_d32_curl92391_replay.py`.
