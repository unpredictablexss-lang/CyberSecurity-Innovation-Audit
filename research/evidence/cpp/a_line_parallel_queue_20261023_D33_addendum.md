# D33 addendum — cJSON current production CLI replay

Date: 2026-10-23 (Asia/Shanghai)
Base: `6f24b0ccae22446d76b4a993312ef37228ffd05e`
Evidence commit: see this worktree's final commit.

D33 replayed the exact two-file `openharmony/third_party_cjson@0c2c9dff82cc85539c8362132d7a5f6bf7d1e748` scope through production M2 CLI / `ohscanner.cpp.resource_lifetime` 0.4.2. The CLI reports candidates for CVE-2026-67215 at `cJSON_Utils.c:932` and `:950`, and CVE-2026-67216 at `cJSON.c:3161`. Runner is `completed_with_limitations`; detector is `blocked`; parsing is 1/2 complete and `cJSON.c` is partial. There is no demonstrated candidate miss, and no detector change was made.

The exact source identity, command, candidate IDs, elapsed time, parser limitations, and distinction from D18/D19 mechanism controls are recorded in [D33 report](d33_cjson_current_cli_20261023_report.md), the raw [CLI Markdown](d33_cjson_current_cli_20261023.md), and [CLI JSON](d33_cjson_current_cli_20261023.json). No trusted root-matched fixed source is bound for either case; both remain PARTIAL/BLOCK and fixed-source comparison remains BLOCK. The historical matrix and A0 queue were not edited.

Verifier: `python research/evidence/cpp/verify_d33_cjson_current_cli.py --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\third_party_cJSON.git --queue research\deliveries\cpp\a0_triage_20261019\queue.csv --cli-json research\evidence\cpp\d33_cjson_current_cli_20261023.json`.
