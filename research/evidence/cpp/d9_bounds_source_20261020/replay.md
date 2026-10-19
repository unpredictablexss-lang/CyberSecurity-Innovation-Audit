# D9 bounds source replay and unblock record

Date: 2026-10-20 (Asia/Shanghai)
Base: `7e8083314f854780a0f606ecc6382208e8a02e8a`
Worktree: `D:\openHarmonyScanner\worktrees\a-d9-bounds-source-20261020`
Branch: `codex/a-d9-bounds-source-20261020`

## Decision

No detector edit is justified by the current exact-source replays. The libtiff root expression is already covered by D7's bounded rule and a complete synthetic source positive; the pinned full translation units are partial, so the real-source run never reaches detector analysis. The web_webview vulnerable commit/blob is unavailable in the replay object's repository, and the available fixed translation unit is partial. These are parser/provenance blocks, not reproducible detector misses. No safe conclusion is made from either zero-finding replay.

## libtiff CVE-2025-9900

Exact Git identities were independently rechecked with `git rev-parse` and file bytes:

| Version | Commit | Tree | `tif_getimage.c` blob | SHA-256 |
|---|---|---|---|---|
| Vulnerable | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `6c7b5031a1937bb48cc79808a59618d8a4f6237e` | `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` |
| Fixed | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `77361ef7262189e16a2010b5c333f6b275d17f09` | `2774caa0eef24bce2a619d2686a23d59fb5ef9db` | `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |

Replayed current CLI with `ohscanner.cpp.bounds` v0.2.0, `light-ast`, and the same two-file scope (`libtiff/tif_getimage.c`, `libtiff/tiffio.h`). Both runs completed with limitations, parsing `partial: 2`, detector `blocked`, `not_analyzed: 2`, and 0 findings. Measured command wall times were 0.83 s vulnerable and 0.51 s fixed. This confirms the analysis is blocked before bounds inspection; it does not contradict the rule-level positive.

The existing D7 rule `ohcpp-memory-bounds-pointer-offset-candidate-004` v0.1.0 targets unsigned dimension subtraction used in a scaled pointer offset. Its controls cover:

- positive: unguarded unsigned dimension difference in pointer displacement;
- guarded/fixed-shape: ordered dimension guard;
- safe: signed subtraction;
- unrelated: unsigned subtraction not used in pointer displacement;
- partial: fail closed with no finding.

The full C++ memory-safety detector module passed 19/19 tests on this base. The real vulnerable/fixed source pair remains `PARTIAL`; the rule-level fixture result is not promoted to a full-source regression pass.

Replay commands:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out D:\openHarmonyScanner\tmp\d9-libtiff-replay-20261020\vulnerable.json --md-out D:\openHarmonyScanner\tmp\d9-libtiff-replay-20261020\vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out D:\openHarmonyScanner\tmp\d9-libtiff-replay-20261020\fixed.json --md-out D:\openHarmonyScanner\tmp\d9-libtiff-replay-20261020\fixed.md
```

## web_webview CVE-2026-27648

The available replay repository `D:\openHarmonyScanner\tmp\d2-webview-fixed-current-cli-20261019` contains fixed-only commit `7038439a38336e0f74de9e8cdd72bf7b7ce8371f`, tree `9873e4146e4a521b80f05a61c24d9c6047f696a7`, target blob `27e93e338ced03aeed6e7d892e29d4d0740f3653`, and target file SHA-256 `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483`.

The exact vulnerable CVE commit `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a` and cited vulnerable target blob `78e83fea67a2db3297cc59f07566a0c0b6153e7a` are absent from this local replay object database. Replaying the fixed-only commit with `ohscanner.cpp.bounds` v0.2.0 took 0.48 s wall time; it returned `partial: 1`, detector `blocked`, and 0 findings. This remains `BLOCK`, not a fixed-control pass.

Minimum unblock input: a retrievable Git object store or archive that resolves the exact vulnerable commit and target blob, plus parser coverage sufficient for the affected function on both vulnerable and fixed revisions. Until then no detector-gap judgment is supportable.

Replay command:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d2-webview-fixed-current-cli-20261019 --repository openharmony/web_webview --commit 7038439a38336e0f74de9e8cdd72bf7b7ce8371f --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out D:\openHarmonyScanner\tmp\d9-webview-replay-20261020\fixed.json --md-out D:\openHarmonyScanner\tmp\d9-webview-replay-20261020\fixed.md
```

## Validation and scope

- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: 19/19 passed.
- `python -m scripts.check_change_scope --base 7e8083314f854780a0f606ecc6382208e8a02e8a --lane cpp`: no violations.
- `git diff --check`: clean.
- No detector rule, parser, Catalog, API, docs, or source-sync changes.
- Case states: libtiff `PARTIAL` (full translation units not analyzed); web_webview `BLOCK` (vulnerable object missing; available fixed-only source partial).
