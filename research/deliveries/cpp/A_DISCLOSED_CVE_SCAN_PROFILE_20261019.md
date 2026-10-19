# A-line disclosed-CVE scan profile and coverage gate — 2026-10-19

Input: `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\cpp\源漏洞审查记录_20261018_A线整合版.md` and its `coverage_ledger_20261019.json`. This is the exact review file identified by the A-line lead; the older task-tree draft referenced a separate C-line G-drive review and is not the case inventory for this matrix. Baseline: latest fetched `origin/main` `db77164fdc2af0da02e4d3efc056d84694fd68e8`; execution from `D:\openHarmonyScanner\worktrees\a-memory-d2-20261019`.

## What is available in the scanner

| Case in the integrated review | A-line mechanism / rule | Ordinary default scan | Current evidence and disposition |
|---|---|---:|---|
| CVE-2025-9900 libtiff | `ohscanner.cpp.integer_bounds` 0.2.1, unsigned subtraction into scaled pointer offset | yes | Exact upstream vulnerable/fix M2 replay: 1 candidate / 0 same-rule findings; both full source scopes remain partial/blocked. OpenHarmony source pin also produces the candidate. Component guard-page reproduction exists; product caller uses matched dimensions in inspected paths, product build remains unknown. |
| CVE-2026-46675 libpng | `ohscanner.known_disclosed_cves` 0.16.0, affected version marker and `png_read_info`→`png_read_end` sequence | no; explicit selection required | New production M2 CLI replay on a source-shaped vulnerable/fix pair reports one candidate / zero findings. Exact upstream source baseline remains partial/blocked with no resource-lifetime root-cause candidate. This closes CLI wiring only; it does not close parser or source-state coverage. |
| CVE-2026-33416 libpng | `ohscanner.cpp.resource_lifetime` 0.3.0, cross-struct member alias/release/read | yes | Exact 1.6.55/1.6.56 source replay: 2 candidates / 0 same-rule findings; both scopes 4/4 partial/blocked. |
| CVE-2026-92391 curl | `ohscanner.cpp.resource_lifetime` 0.3.0, callback-mediated recursive cleanup | yes | Exact affected 8.22.0/fix M2 replay: 1 candidate / 0 same-rule findings with complete parse. The audited OpenHarmony component version 8.8.0 falls within the advisory range 7.56.0–8.22.0; product caller reachability, attacker-controlled nesting depth and impact remain unknown. |
| CVE-2026-67216 cJSON | `ohscanner.known_disclosed_cves` 0.16.0, recursive object compare with repeated linear key lookup | no; explicit selection required | Production M2 CLI source-shaped vulnerable/fix pair: 1 candidate / 0 findings. Exact local `cJSON.c` scan remains partial/blocked with no diagnostic; that result remains unknown, not a miss or safe result. No verified fixed-source control exists. |
| CVE-2026-67215 cJSON | `ohscanner.known_disclosed_cves` 0.16.0, JSON Patch deep-copy and recursive delete without visible depth bound | no; explicit selection required | Production M2 CLI source-shaped vulnerable/fix pair: 1 candidate / 0 findings. Exact local source scan has one complete and one partial file and remains blocked; no valid upstream fixed source is known. |
| CVE-2026-27648 web_webview | `ohscanner.known_disclosed_cves` 0.16.0, Flowbuffer offset/length and destination-index signatures | no; explicit selection required | The fetched scanner has this CVE-specific source rule. Exact vulnerable/fixed function-fragment differential is recorded in the integrated review; whole translation units remain partial/blocked. |
| CVE-2025-26690 DSoftBus | `ohscanner.cpp.null_dereference` (0.2.0 historical report) | no; explicit selection required | Historical delivery reports 5 candidates / 0 fixed, but raw original replay artifacts are absent and current head was not replayed. Do not count as current verified coverage. |
| CVE-2025-0587 Ark runtime | `ohscanner.cpp.integer_bounds` | yes | Current CLI replay with pinned vulnerable/fix commits returns 1/0; safe/unrelated are quiet, truncated source is partial/blocked. Normalized evidence is in `research/evidence/cpp/ark_runtime_replay_20261019/` in the integration PR. |
| CVE-2025-23420 Ark runtime | `ohscanner.cpp.bounds` | yes | Current CLI replay with pinned vulnerable/fix commits returns 5/0; safe/unrelated are quiet, truncated source is partial/blocked. The historical patch SHA conflicts with a fresh diff-byte digest; both are retained in the replay status report. |
| CVE-2025-20042 / CVE-2025-21098 kernel_liteos_a | no applicable rule in the historic A-line inventory | no | Explicitly marked not applicable/not scanned by the prior A-line report; do not recast as a scanner miss. |

## Reproducible explicit profile

`ohscanner.known_disclosed_cves` is approved and registered in the fetched scanner source, but catalog metadata sets `default_enabled: false`. It is runnable through the production CLI when explicitly selected. The tested core A-line profile selects the general memory/lifetime families plus the CVE rule pack:

```powershell
python -m src.cli ohscan-run `
  --repo-dir <local-git-repository> `
  --repository <owner/name> `
  --commit <full-40-character-commit> `
  --detector ohscanner.cpp.bounds `
  --detector ohscanner.cpp.integer_bounds `
  --detector ohscanner.cpp.resource_lifetime `
  --detector ohscanner.known_disclosed_cves `
  --json-out <report.json> `
  --md-out <report.md>
```

The 2026-10-19 production CLI regression ran the core profile on three source-shaped inputs covering CVE-2026-46675, CVE-2026-67216 and CVE-2026-67215: 3 candidates on the vulnerable snapshot, 0 on the safe/fixed-shape control. The vulnerable scan is `blocked` because one C file parses partial; it retains all three candidates. The fixed control parses completely and returns 0 diagnostics. Full reports and tiny Git source bundles are in `research/evidence/cpp/disclosed_cve_m2_cli_replay_20261019/`. This proves the registered CLI route and candidate behavior for those shapes; it is not a source-identity match to a product build or a product-vulnerability verdict.

For an A-line invocation that selects the core profile consistently, use `research/deliveries/cpp/run_a_disclosed_cve_scan.ps1`. It pins the four detector IDs above, requires a full commit SHA, and accepts an optional `-Include` scope. I exercised this wrapper against the preserved vulnerable/fixed source bundles: vulnerable commit `aaa265e33b497a26a638a2d79a68b3b8e0663e12` returned `diagnostic_count=3`, `validated_vulnerability=0`, `completed_with_limitations`; fixed commit `fb1309f75f13affdf8ca5c93ab88ba87704e4e49` returned `diagnostic_count=0`, `validated_vulnerability=0`, `completed`. Reports are `script-vulnerable.{json,md}` and `script-fixed.{json,md}` in the evidence directory. These remain source-shaped CLI wiring controls, not upstream component or product source proof.

The historical DSoftBus CVE-2025-26690 uses the separately disabled `ohscanner.cpp.null_dereference` detector. It can be added explicitly for a targeted replay, but a full-profile control run on these unrelated pointer-heavy fixtures emitted generic null-dereference candidates. Keep it out of the core profile until a source-bound DSoftBus vulnerable/fixed replay and unrelated controls establish an acceptable scope. The extra five-detector experiment is retained as `profile-vulnerable.*` / `profile-fixed.*` and shows the noise; the four-detector core profile is `a-profile-vulnerable.*` / `a-profile-fixed.*`.

## Admission follow-up

The feature is available through explicit detector selection today. It is not part of ordinary default scans because the shared Catalog owner currently gates it on the lack of an independent holdout and unverified product reachability. A-line's concrete handoff is to have the shared owner define an A-line named profile (or approve default selection) after independent source holdout review. This task does not edit shared Catalog/Runner/contract files. The request should name the four core detector IDs above, separately scope the null-dereference detector, preserve candidate-only obligations, include the three historical replay gaps, and gate profile acceptance on exact source vulnerable/fixed/safe/unrelated/partial results.

## Checks

- `python -m unittest tests.detectors.test_known_disclosed_cves -v`: 21/21 pass.
- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector tests.detectors.test_cpp_cross_member_alias_regression tests.detectors.test_cpp_recursive_cleanup_regression tests.detectors.test_cpp_pointer_offset_underflow tests.detectors.test_known_disclosed_cves -q`: 39/39 pass.
- `python -m compileall -q src/ohscanner/detectors/cpp ...`: passed.
- No shared Catalog/Runner/API edit. Candidate outcomes are not promoted to confirmed vulnerabilities.
