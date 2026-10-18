# D5 main readiness

| Gate | Status | Current evidence / remaining condition |
|---|---|---|
| M0: default-off isolated module | **Not met** | D data suite 55/55; full Python suite 889 (884 passed, 5 skipped); D13 verified both historical Git commits, trees, and all 44 D4 source-manifest rows offline. D5 exact 10-file replay reproduces 1 old / 0 post-hardening candidates, but both runs are blocked with 4 complete / 6 partial. D14 retains private/default-private sensitive flows as conditional candidates. Public Runner was not used for historical replay; latest PR-head CI and dependency/license review remain unverified. The D branch stays unregistered. |
| M1: explicit experimental registration | **Not met** | Shared partial-AST admission, report/UI integration, and an explicit experiment switch remain owner work. Public Runner still withholds partial D files. |
| M2: default one-click scan | **Not met** | The model remains limited to reviewed DSoftBus sources and exact historical profiles. There is no second independent real source/API family, no independent labeled holdout, no TP/FP/FN/unknown evaluation, and no end-to-end runtime/RSS benchmark. |
| M3: confirmed product vulnerability | **Not met** | Component stubs and historical source replay do not prove a product build, actual product log output, unauthorized reader, validated remediation build, affected release, or product impact. validated_vulnerability=0. |

Recommendation: continue D as research-only. D14 moves the static layer toward high recall by preserving privacy-masked flows for review; it does not relax public Runner partial admission. Next detector work must broaden independently reviewed source families and then evaluate against a frozen real-source holdout. No Catalog registration, default enablement, PR Ready, or merge is approved by these results.

## Historical status correction (2026-10-19)

The table above is the D5-era snapshot and is not current after PR #17. D 0.13.0 is now merged to main at `4593a7c9b6977eb81172d01b46cc59daf46f5d45`, explicitly selectable and default-off. A real panel task carried one partial candidate through API/Worker/report while preserving `blocked` coverage and `validated_vulnerability=0`; this meets the narrow M0/M1 integration gates only. M2 and M3 remain unmet. The D19 high-recall fallback is a separate 0.14.0 branch experiment; an API -> Worker -> report regression now verifies candidate preservation on a synthetic unknown-source fixture, but a real 8765 UI task with this version has not been run and the fallback has no independent labeled holdout. See `D19_HIGH_RECALL_FALLBACK.md` for its fixed-source replay and limitations.

## 2026-10-19 current D lane snapshot (D25)

The D5-era matrix above is historical. The current branch feat/d-commercial-expansion-20261018 is the D commercial-expansion line based on main commit 4593a7c9b6977eb81172d01b46cc59daf46f5d45. Existing D work in Draft PR #19 registers the known-disclosed-CVE detector in the first-party Catalog and Runner; D22 previously verified the libpng candidate through the panel API -> Worker -> report -> source-view path. D25 adds CVE-2025-57052 to that same detector (version 0.6.0), so it inherits the existing page/scan integration. The D25 exact upstream parent/fix pair was validated through the detector and a rootless component replay. This does not by itself rerun the browser UI or establish product impact.

- **M0: isolated research behavior — met for the current narrow integration.** The detector is explicitly selectable through the Catalog/Runner; its findings remain candidates and its evidence obligations keep component identity, product build, attacker control, and impact open. Default enablement is a separate policy decision and is not claimed here.
- **M1: panel/API/Worker/report path — met for the existing detector integration, with scope.** D22 passed a real fixed-source API -> Worker -> report -> source-view replay for CVE-2026-46675, with stable candidate identity and completed_with_limitations. D25 adds another rule family to this integrated detector. A D25 Workbench integration regression now follows the pinned synthetic fixture through scan creation, Worker, report, and source viewer; browser click automation was not repeated because no frontend code changed.
- **M2: independent scanner quality gate — not met.** The 9 CVE signatures are seeded from disclosed cases and their regression samples are tuning data, not independent holdout. No frozen blind true-source set or complete TP/FP/FN/unknown and performance evaluation exists. Existing real-source replays establish detector behavior on named inputs, not general recall.
- **M3: confirmed OpenHarmony product vulnerability — not met.** D25 demonstrates an upstream cJSON component API behavior and its upstream fix with synthetic input. Product inclusion, an attacker-reachable product caller, protected impact, affected OpenHarmony release, and product-fixed-build retest remain unknown. validated_vulnerability=0; do not present this component PoC as a product exploit.

Historical pre-merge snapshot (2026-10-19, before PR #19 merge): D25 targeted detector tests passed 12/12; the Workbench API -> Worker -> report -> source-view test passed 1/1; the full Python suite passed 912 tests with 5 skipped (917 total). Production Web bundle build remains unavailable in the current WSL/Windows Node setup because the installed esbuild binary targets Linux while only Windows Node is usable. Latest known CI success was on the previous PR head a489a0fc7089cbc67534f37338c2a3750f51d4c5; D25 GitHub Actions run 39153123959 passed both Python unit tests and Workbench TypeScript/production-build jobs on head e768c2445886c2a5f9fc4f8695c9b5e1459ad9cd. PR #19 remains Draft until fresh remote status is verified. No merge or Ready transition was authorized at that snapshot.


## Post-merge and D26 follow-up (2026-10-19)

PR #19 was merged into main at 56a5d2689a5abf21e13d35397d87c9b035954197 after the owner explicitly requested merge on successful tests. Its D known-CVE rule remains a candidate-only source-signature detector; the merge did not complete M2 or M3. On the merged main snapshot the rule was default-eligible, while the follow-up branch feat/d-independent-eval-20261019 makes it opt-in until an independent holdout and applicability review exist.

D26 scanned pinned G-drive third_party_cJSON@0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 twice through the first-party Runner. Both runs retained the same CVE-2026-67215/67216 candidates and did not match CVE-2025-57052 because cJSON_Utils.c exactly matches the known upstream fixed Git blob/SHA. All 99 files remain partial and the detector run blocked. This is a real-source regression replay, not the independent blind holdout required by M2, and not a product safety or vulnerability verdict. See D26_G_CJSON_REPLAY.md and D26_G_CJSON/.


## D27 IoT Connect source-to-log replay (2026-10-19)

An exact-revision source model now recognizes PBKDF2 output -> UtilsHexify -> IOTC_LOGI for the pinned communication_iot_connect source. The repeated Workbench API/Worker/report/source-view replay retains one candidate at line 602 with stable source binding; scan remains blocked/partial and validated_vulnerability=0. The pinned G-drive working file is dirty, so only the Git object at d8c0aef305601770c912dbdedc58a3f1e6efd30c was read. The audit's separate authCode source, product inclusion, INFO logging, reader access, and impact remain unknown. Component-source relation is confirmed; product vulnerability is not. See D27_IOTC_KEY_LOG_REPLAY.md and D27_IOTC_PANEL_REPLAY.json.


## D30：libpng CVE-2026-46675 ASan 组件对照（2026-10-19）

在固定 G 镜像构建输入 libpng 1.6.55 归档上新增并运行了真实 C PoC。归档 SHA-256 `71a2c5b1…002782a6` 与 G repo HEAD `e57b1079564a02a50321ec528aa6e41884979d32` 内 Git blob `975cee2aca0eda6bfa3e9b7a1336c956fcf1b094` 一致。3 轮 ASan 重放稳定复现 `png_zlib_inflate` heap-use-after-free；修复对照是在同一归档副本应用上游 `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` 提交，3 轮无 UAF。读图像行再调用 `png_read_end` 与短 tEXt 无重新分配控制各 3 轮无 UAF。此为组件构建证据；不是完整 1.6.59 发布树，也未证明产品应用使用罕见调用顺序。报告为“组件根因 confirmed；产品适用性/入口/影响 unknown”，`validated_vulnerability=0`。

复现入口：`.venv-web/bin/python research/data_sensitive/d30_libpng_cve_2026_46675_replay.py --source-tar <pinned-libpng-1.6.55.tar.gz>`。脚本校验哈希，将归档解压到临时目录，在独立副本中构建 ASan vulnerable/fix 两端，不联网、不改输入归档。静态规则此前已通过 D22 的真实归档 Runner/面板路径在 `png.h:277` 产生候选；D30 将该候选与可执行组件证据对应起来，但不升级产品结论。

当前 D 功能面：known-CVE 规则仍默认关闭、页面显式选用；D29 提交 `2dcc06062d0c9dce95b7a2d4330caf7843815d3f` 的 GitHub CI run `39159928045` 已通过 Python 与 Web 构建两项。D30 本轮本地完整 Python 为 923 项、918 passed/5 skipped；审计请求 UI 测试 12/12；三轮 ASan 组件重放稳定。M0/M1 仅按已有 opt-in 模块窄范围评估；主线兼容、安全审查和负责人签署仍需逐项完成。M2 因无独立冻结标签、TP/FP/FN/unknown 和完整性能/RSS 基准仍未达到；M3 产品构建、可达入口、影响与产品修复复验仍未达到。PR #20 保持 Draft，未经下一轮完整准入复核不作 Ready/merge 结论。

## D31：libtiff CVE-2025-9900 组件 PoC（2026-10-19）

固定 G 镜像 Git 对象扫描器两次稳定产生 CVE-2025-9900 candidate；通过 ASan 在旧版 libtiff 4.7.0 组件中 3/3 复现 `put8bitcmaptile` 越界写访问，上游 MR !732 修复对照和正确 raster 尺寸控制均为 0/3 ASan 报告。脚本只用固定 commit 的 `git archive`，不读入 G 盘 dirty 文件、不联网、不写回源仓库。复现入口与限制见 `D31_LIBTIFF_CVE_2025_9900_REPORT.md`；scanner 仍报 candidate，产品状态 unknown，`validated_vulnerability=0`。

D30 的 GitHub CI run `39161430278` 的 Workbench TypeScript/production build 与 Python unit tests 均通过。D31 新增脚本、夹具和报告仍须在本提交本地回归及推送后 CI 验证。页面集成仍为显式 default-off 研究规则；M2 独立 holdout 与 M3 产品构建/入口/影响/修复后复验仍未满足，不据此宣称商业就绪或产品漏洞 confirmed。
D31 提交前本地完整回归：`.venv-web/bin/python -m unittest discover -s tests -q` 为 923 项，918 passed、5 skipped；D31 脚本已完成三轮旧版/修复版/安全控制 ASan 验证并写出 JSON，`py_compile` 和 `git diff --check` 通过。D30 GitHub CI `39161430278` 的 UI/build 与 Python jobs 均 success；D31 GitHub Actions run `39162408024` 的 Workbench TypeScript/production build 与 Python unit tests 均通过。