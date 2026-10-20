# D37 — Preferences get-fuzzer candidates CR-0066–CR-0090

## Source-bound current CLI replay

All 25 A0 rows bind to `openharmony/distributeddatamgr_preferences` commit `bff9efd79afc0d7d1ed22a63ff355f1600404596`, tree `7761d9e273ae7007046ae115797f255e554523ae`. The source `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp` is blob `7a5c8a263fa4142579a3f4c6161c7d28b3350f50`, SHA-256 `3e72c80d962f8dc9df6573328198c37072f4dddcd88dbc004ed2f72128d176b9`. Its `BUILD.gn` binding is recorded in the per-ID JSON report.

The current `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI scanned only this file. Parsing completed (1/1, 197 LOC); 25 syntax candidates reproduce all CR-0066–CR-0090 lines. The exact target is `ohos_fuzztest("DBPreferencesGetFuzzTest")` in the `fuzztest` group marked `testonly = true`.

The harness obtains one `Preferences` instance and invokes Get/Put methods sequentially in `LLVMFuzzerTestOneInput`, then clears and removes the cached instance. These calls establish that the fuzz harness exercises production APIs. They do not establish concurrent overlapping accesses, product inclusion, external reachability, or impact. There is no demonstrated production-source root miss in this replay, so no detector change is justified; findings remain syntax candidates rather than confirmed vulnerabilities or confirmed false positives.

All A0 rows remain `not_testable / paused_pending_evidence` and PARTIAL. Run `python research/evidence/cpp/verify_d37_preferences_get_fuzzer_20261024.py` to validate source bindings, CLI line mapping, report, and unchanged 345-row queue counts. Raw CLI output is `d37_preferences_get_fuzzer_20261024.json`; per-ID source and finding identities are in `d37_preferences_get_fuzzer_replay_20261024.json`.

## Structured vibe-coding prompt

- **角色：** A 线 Preferences `shared_ptr_race` 开发负责人。
- **持续目标：** 区分测试 harness 语法候选与生产可达、确有并发交错的同对象根因；保持源码绑定和 A0 队列状态不变。
- **输入：** D37 精确 source/build 身份、当前 CLI 原始输出及 CR-0066–CR-0090 对应行。
- **步骤：**
  1. 单独追踪 production BUILD inclusion、调用链和可达性，不以 fuzz target 依赖推断产品发布。
  2. 核验 shared_ptr 同对象读写、线程/任务创建与重叠、锁/原子或 join 的同步关系。
  3. 仅在具体产品源码漏检已复现时改 `shared_ptr_race`；同时提供 positive、fixed、safe、unrelated、renamed 和 partial controls。
  4. 每次复跑记录 commit/tree/blob/SHA、规则版本、scope、解析覆盖和命令。
- **完成门：** 独立复验精确对象和发现；产品构建/可达性及重叠未同步同对象访问均有证据后才能确认产品根因，否则保留 PARTIAL/BLOCK 并列明缺失项。
- **边界：** 不按 CVE、仓库、函数名或哈希硬编码；不把测试 harness 候选提升为产品漏洞；不改 A0 状态、共享 API 或 Catalog。
