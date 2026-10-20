# T4 source-bound rescan: curl and legacy pasteboard CVEs

Date: 2026-10-20 (Asia/Shanghai)  
Checkout: `codex/t4-d51-d52-acceptance-20261020` at `0a8e87dbf3d184f9e536c1116a80f6498b87cb50`  
Role: independent testing/provenance follow-up; detector, tests, fixtures, and A0 queue unchanged.

## Matrix reconciliation

The frozen 13-row A-line matrix in T12 contains curl CVE-2026-92391 but does **not** contain the two old pasteboard CVEs. T2 explicitly says it carried the 13-row matrix forward and did not freshly replay every historical row. Curl was subsequently replayed in D32/T32 at the current `resource_lifetime` 0.4.2 rule on exact vulnerable/fixed upstream commits. This T4 replay independently reproduces that result; curl is not currently a missing static replay row. Its matrix PASS remains limited to the exact source-level regression and says nothing about product reachability or impact.

At the time of T2/T12, six of the 13 historical rows had not been freshly rerun in either acceptance package: libtiff CVE-2025-9900, curl CVE-2026-92391, OpenHarmony CVE-2025-0587, OpenHarmony CVE-2025-23420, and the two N/A exclusions CVE-2025-20042/CVE-2025-21098. Subsequent independent work has now refreshed curl (this package), 0587/23420 (the matrix history package), and libtiff (the webview/libtiff matrix follow-up). The two N/A rows remain excluded rather than being relabeled as tested. The exact OpenHarmony/web_webview row still lacks a complete current full-source CLI replay; the available Chromium-derived bounded fragments and previous partial full-file runs are not exact-row completion. The two pasteboard CVEs are an adjacent disclosed-CVE evidence pair, not two additional rows silently inserted into the 13-row matrix.
The pasteboard pair was rerun here because its source-bound evidence is relevant to the A-line disclosed-vulnerability scanner goal.

## Fresh CLI results

All four commands below were run from this checkout with `python -m src.cli ohscan-run`. The current detector versions were `ohscanner.cpp.resource_lifetime` 0.4.2 and `ohscanner.known_disclosed_cves` 0.16.0.

| Case/input | Exact source identity | Parse/coverage | Candidate result |
|---|---|---|---|
| curl vulnerable | upstream commit `01346829096c61b372692f6dc43ffa778c6caccd`; tree `6ae23d9333713707a02588b44ed238a50e8b3bde`; `lib/mime.c` blob `600437576581be08f9026881c39178857a1c5939`; SHA-256 `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` | 1/1 complete | `CVE-2026-92391`, line 1118, `ohcpp-resource-lifetime-recursive-cleanup-candidate-003` |
| curl exact fix | upstream commit `d7546809d5bd548b69ec49fca26565c8f6f0d344`; tree `52a8416729366487cdd3b6012071f5f8370e769f`; `lib/mime.c` blob `3522679a16e2fa560c581413bf946d38e332bea4`; SHA-256 `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` | 1/1 complete | 0 same-rule candidates |
| pasteboard legacy snapshot | commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`; tree `e374a0d61c9ec664ddd29fc17002797828c480ee`; `pasteboard_service.cpp` blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`; `pasteboard_service_stub.cpp` blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` | 2/2 complete | CVE-2025-25212 at line 222 and CVE-2025-27247 at line 41; rules `ohknowncve-pasteboard-cve-2025-25212` and `ohknowncve-pasteboard-cve-2025-27247` |
| later pasteboard snapshot, exploratory comparison only | commit `e73747b227104e6743e957ce31040edf58507221`; tree `4128cdf9ad11d393c30f2839f43419e97a5a466d`; `pasteboard_service.cpp` blob `fa6a08cdbaa18f34dcb6632babc70f22a700c860`; SHA-256 `2f18a183e6eaa75f996d221fac735703a534d00cf294d122cbc6637bb28fa78a` | selected core file partial; the old stub path is absent | 0 findings; no fixed/safe inference |

The pasteboard old snapshot is a candidate-positive source, not proof of a product vulnerability. No verified official fix commit or exact fixed counterpart for these two CVEs was present in the bound evidence. The later snapshot is not promoted to a fixed control: its core parse is partial, the stub source is absent, and this rescan does not establish the exact fix lineage. The existing synthetic guarded fixture test is a mechanism control only; it is not a source-bound real-world fixed pair.

## Reproduction commands

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit 01346829096c61b372692f6dc43ffa778c6caccd --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/t4_historical_rescan_20261020/curl_vulnerable.json --md-out research/evidence/cpp/t4_historical_rescan_20261020/curl_vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit d7546809d5bd548b69ec49fca26565c8f6f0d344 --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/t4_historical_rescan_20261020/curl_fixed.json --md-out research/evidence/cpp/t4_historical_rescan_20261020/curl_fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d56-pasteboard-lineage\miscservices_pasteboard.git --repository openharmony/miscservices_pasteboard --commit dd22c7cb5e5f207a6c38c50f45b7369ee8575840 --include services/core/src/pasteboard_service.cpp --include services/zidl/src/pasteboard_service_stub.cpp --detector ohscanner.known_disclosed_cves --json-out research/evidence/cpp/t4_historical_rescan_20261020/pasteboard_legacy.json --md-out research/evidence/cpp/t4_historical_rescan_20261020/pasteboard_legacy.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d68-pasteboard-source-20261023 --repository openharmony/miscservices_pasteboard --commit e73747b227104e6743e957ce31040edf58507221 --include services/core/src/pasteboard_service.cpp --include services/zidl/src/pasteboard_service_stub.cpp --detector ohscanner.known_disclosed_cves --json-out research/evidence/cpp/t4_historical_rescan_20261020/pasteboard_later_snapshot.json --md-out research/evidence/cpp/t4_historical_rescan_20261020/pasteboard_later_snapshot.md
python research/evidence/cpp/t4_historical_rescan_20261020/verify.py
python -m unittest tests.detectors.test_known_disclosed_cves.KnownDisclosedCveTests.test_pasteboard_disclosed_cves_and_guarded_controls -v
```

The targeted synthetic-control test passed (1/1). `verify.py` checks the committed CLI artifacts' exact commits, detector versions, source hashes, finding locations, and coverage classifications. No A0 status or matrix label is changed. Pasteboard product status remains PARTIAL/BLOCK; no source-level fixed differential is claimed.
