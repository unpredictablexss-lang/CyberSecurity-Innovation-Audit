# A 线 T3 独立验收预审（非最终验收）

日期：2026-10-19  
审阅基线：`db77164fdc2af0da02e4d3efc056d84694fd68e8` (`origin/main`)  
审阅入口：`D:\openHarmonyScanner\worktrees\a-triage-t2-20261019`  
状态：**预审完成；最终 T3 未完成，等待 I1 shared Catalog/Runner 准入和 profile 回放。**  
结论边界：所有扫描结果均为 source-bound candidate/evidence；没有确认 OpenHarmony 产品漏洞。

## 1. 范围、输入和可复核记录

按任务指令从 T2 worktree 核对 A 线任务树、D1/D2/T1/T2 交付及其隔离 worktree。D1、D2 实现分别位于 `D:\openHarmonyScanner\worktrees\a-path-d1-20261019`、`D:\openHarmonyScanner\worktrees\a-memory-d2-20261019`；T1 在 `D:\openHarmonyScanner\worktrees\a-contacts-t1-20261019`。本预审仅在本目录新增报告和测试 stdout，不改 detector、A0 原报告或 shared Catalog/Runner。

重跑输出：

- `d1-focused-tests.txt`：`python -m unittest tests.detectors.test_cpp_path_safety_detector -v`，10/10 通过。
- `d2-focused-tests.txt`：`python -m unittest tests.detectors.test_cpp_resource_lifetime_detector tests.detectors.test_cpp_recursive_cleanup_regression tests.detectors.test_cpp_cross_member_alias_regression tests.detectors.test_cpp_pointer_offset_underflow -v`，18/18 通过。
- `source-rehash.txt`：从三组源 Git object 独立导出选中文件字节并重新计算 SHA-256；libtiff vuln/fix 2/2 + 2/2、curl vuln/fix 1/1 + 1/1、libpng vuln/fix 4/4 + 4/4 均匹配 M2 JSON。
- `profile-recheck.txt`：六个 default-enabled replay JSON 的报告文件 SHA-256 和 source snapshot SHA-256 均与 manifest 相符；列出两个目标 detector 的诊断数/状态。
- 当前 T2 worktree 在写报告/日志前仅有其自身 triage 交付 untracked；D1/D2/T1 源码和证据均在各自 worktree。审阅期间没有改这些交付。

## 2. 结论摘要

| 项 | 预审判定 | 证据 / 限制 |
|---|---|---|
| D1 path detector 核心路径和 partial finding Runner 归一化 | **通过（模块级）** | partial run 将实际检查的路径列入 `analyzed_files`，同时 `file_outcomes=partial`；单测直接调用 `_normalized`，确认诊断保留且 normalized parsing 仍为 partial。当前没有 Catalog/生产 profile 接线。 |
| D2 三组 exact disclosed CVE vulnerable/fix 配对 | **有条件通过；两组覆盖证据不足** | 三组目标规则都观察到 vulnerable candidate、fixed same-rule 0；curl 1/1 完整解析。libtiff 2/2、libpng 4/4 两侧 partial，Runner/detector blocked；这些 fixed 0 不是安全结论。 |
| 三组 safe controls | **通过（控制样本）** | 同一 M2 CLI/Runner 路径、对应 detector 版本、完整 parse、0 目标规则 diagnostics；控制样本是小型 first-party fixture，不代表产品安全。 |
| default-enabled detector-set CLI replay | **通过（选择集路径）** | manifest 枚举 `catalog.default_detector_ids()` 的 8 个 IDs，并用 `ohscan-run` 显式传入；6 个 JSON 的实际 SHA-256 与 manifest 相符，source snapshot SHA 与 JSON 相符。CLI 需要显式 `--detector`；opt-in `known_disclosed_cves` 和 D1 新 detector 不在这 8 个中。 |
| CVE-specific/known-path 硬编码 | **未见 D1/D2 通用规则硬编码** | 对 D1、D2 两个新增/扩展通用 detector 实现做文本检索：未见 CVE ID、CVE 名称或 `libtiff/libpng/curl` 路径/组件名分支。resource_lifetime.py:374 仅有注释称 fixed curl shape；其执行逻辑按 callback 字段、嵌套 pointer、dispatch cycle、release 和 depth bound 等通用形状分析。既有 `known_disclosed_cves` 则明确定义为 CVE 专项 detector，保持 opt-in，未作为这三组 exact-pair 结果计算。 |
| T1/T2 任务树依赖 | **交付存在，状态边界明确** | T1 report 将 Contacts 维持 partial：产品版本/入口、真实文件权限域和官方修复仍 unknown。T2 队列为 345 行，CSV 346 行含 header；T2 仅分诊，不改变 A0 原结论。二者可供最终 T3 使用，但不关闭 I1。 |

## 3. D1 独立核验

原始实现与交付：

- detector: `D:\openHarmonyScanner\worktrees\a-path-d1-20261019\src\ohscanner\detectors\cpp\path_safety_detector.py`
- tests: `D:\openHarmonyScanner\worktrees\a-path-d1-20261019\tests\detectors\test_cpp_path_safety_detector.py`
- handoff/evidence: `D:\openHarmonyScanner\worktrees\a-path-d1-20261019\research\deliveries\cpp\20261019-d1-path-source-sink.md`

独立执行的 10 个 focused tests 全部通过。partial test 验证一条 source→sink candidate 不因 parse partial 丢失；`DetectorRun.analyzed_files=("src/sample.cpp",)`、`file_outcomes=(("src/sample.cpp","partial"),)`，Runner `_normalized(...)` 输出一条诊断且 parsing `analysis_status="partial"`。这验证了 D1 曾暴露的 finding provenance/Runner contract 回归。

规则采用有限 API source 名称模型、局部赋值/串接与已列文件 sink；这些是 API 名称模型，不按仓库路径、漏洞编号或 CVE 名匹配。canonical containment、basename allowlist 和 partial controls 覆盖在 focused tests 中。限制是 lexical same-TU may-flow；没有 CFG、真实文件系统语义、跨 TU/宏或产品入口建模。Contacts source replay 是 module-level partial replay，不是 production CLI/Runner replay；D1 未接入 shared Catalog。

**D1 判定：** 模块和 partial normalization regression 通过；生产 profile 准入、exact CLI/Runner Contacts replay、fixed/safe/unrelated/partial controls 待 I1 后重跑。

## 4. D2 三组 CVE 配对核验

D2 主记录：`D:\openHarmonyScanner\worktrees\a-memory-d2-20261019\research\evidence\cpp\d2-disclosed-vulnerability-regression.md`。以下 hash 是各 M2 JSON 中的实际 selected source SHA-256；我从 source Git object 独立导出相同 commit:path 文件后重新计算，所有选中文件均与 JSON hash 匹配（完整 stdout 见 `source-rehash.txt`）。漏洞和修复源是不同对象身份，报告亦固定 commit/tree/snapshot。源身份与官方记录符合：

| 披露与机制 | vulnerable → fixed source identity / scanned source hash | 同规则结果 | safe control | 预审 |
|---|---|---|---|---|
| CVE-2025-9900, libtiff `TIFFReadRGBAImageOriented` unsigned row-height difference → scaled pointer offset；rule `ohscanner.cpp.integer_bounds` 0.2.1 | OSGeo vulnerable commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, `tif_getimage.c` SHA `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` → fix commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, `tif_getimage.c` SHA `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` | vulnerable: 1 candidate at line 621; fixed: 0; same detector. Both 2/2 partial, Runner `completed_with_limitations`, detector `blocked`. | `libtiff-safe/control.c`, SHA `4a8284444e8a1d9870651a3fdabf6f37c5a1eec2cc8b9bd0a4d960968f463aa6`, complete, 0. | candidate preserved; fixed comparison is parser-limited. |
| CVE-2026-92391, curl `curl_mime_free` unbounded recursive cleanup; rule `ohscanner.cpp.resource_lifetime` 0.3.0 | vulnerable curl commit `01346829096c61b372692f6dc43ffa778c6caccd`, `lib/mime.c` SHA `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` → exact fix `d7546809d5bd548b69ec49fca26565c8f6f0d344`, `lib/mime.c` SHA `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` | vulnerable: 1 candidate at line 1509; fixed: 0; same detector. Both 1/1 complete, detector `completed`. | `curl-safe/control.c`, SHA `91bccea194473eadcbfcfc540bfb4edd1161b2587f0095cba975eae691fb5209`, complete, 0. | strongest pair in this pre-review; still does not prove product use/attacker-controlled nesting. |
| CVE-2026-33416, libpng `png_set_tRNS` / `png_set_PLTE` cross-struct shared allocation alias/release/read; rule `ohscanner.cpp.resource_lifetime` 0.3.0 | official 1.6.55 archive SHA `d925722864837ad5ae2a82070d4b2e0603dc72af44bd457c3962298258b8e82d`, represented by transport snapshot commit `afad740f043acd9bee412677d0a5ff1e046aaa24`; scanned `pngrtran.c` SHA `4df05c2e5db00911817d7f125c862524205895f34a65106e016d351f7e6edb53` and `pngset.c` SHA `9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0` → official 1.6.56 archive SHA `f7d8bf1601b7804f583a254ab343a6549ca6cf27d255c302c47af2d9d36a6f18`, represented by transport snapshot `dcd78000a2e39558bd0b9340633d7acff796d37b`; scanned `pngrtran.c` SHA `6b724ff0047cced71884176296aac10a6fc1d2592477034bbd622222ded3373f`, `pngset.c` SHA `d3a203e40b6a6000a7cb78a61e0fd9664b0c39a65d82260efedb0f0184a8bc19` | vulnerable: 2 candidates at `pngrtran.c:1187,1228`; fixed: 0; same detector. Both 4/4 partial, Runner `completed_with_limitations`, detector `blocked`. | 3 independent-copy files, hashes in source D2 report, 3/3 complete, 0. | mechanism candidate preserved; fixed comparison remains parser-limited. Synthetic transport commits are clearly labeled and not confused with official commits. |

Official-source cross-checks:

- libtiff: [CVE-2025-9900 Debian tracker](https://security-tracker.debian.org/tracker/CVE-2025-9900) links issue #704 and exact fix commit; [libtiff 4.7.1 release notes](https://libtiff.gitlab.io/libtiff/releases/v4.7.1.html) record fixing the buffer-underflow crash for issue #704.
- curl: [official CVE-2026-92391 advisory](https://curl.se/docs/CVE-2026-92391.html) names unbounded recursion in `curl_mime_free`, affected through 8.22.0, and links fix commit `d7546809…`; [upstream commit](https://github.com/curl/curl/commit/d7546809d5bd548b69ec49fca26565c8f6f0d344) changes cleanup to non-recursive traversal.
- libpng: [official GHSA-m4pc-p4q3-4c7j](https://github.com/pnggroup/libpng/security/advisories/GHSA-m4pc-p4q3-4c7j) names CVE-2026-33416, affected `<=1.6.55`, fixed 1.6.56/1.8.0 and the cross-struct ownership bug; upstream fixes are [tRNS](https://github.com/pnggroup/libpng/commit/23019269764e35ed8458e517f1897bd3c54820eb) and [palette](https://github.com/pnggroup/libpng/commit/7ea9eea884a2328cc7fdcb3c0c00246a50d90667).

For all three pairs, `validated_vulnerability=0` remains in reports. CVE/source pairing verifies a component-level regression target, not an OpenHarmony dependency/build or product exploit.

## 5. M2/default-enabled CLI and source/hash integrity

D2's report set includes exact production M2 `ohscan-run` vulnerable/fixed/safe-control JSON and Markdown for all three pairs. JSON records commit, tree, snapshot SHA, selected file SHA-256, detector ID/version, Runner status, detector status, diagnostic set and parse status. Vulnerable and fixed were run with the same selected detector, source file scope and production CLI route. D2 keeps the initial libtiff Runner-normalization failure JSON/trace and later corrected blocked result, rather than discarding the failure.

The separately labeled default-enabled set replay is in `research/evidence/cpp/a-default-profile-replay-20261019/`. Its manifest lists all eight default detector IDs at the pinned base. I recomputed SHA-256 for all six vulnerable/fixed reports and matched each manifest value; each JSON's `snapshot_sha256` also matches its manifest `source_snapshot_sha256` (summary in `profile-recheck.txt`). The targeted rules report: libtiff 1/0, curl 1/0, libpng 2/0. All target results match the specific detector M2 outcomes above. This replay tests CLI selection/Runner execution of the pre-existing default-enabled set; it does not include the opt-in CVE-specific pack or new D1 path detector.

Potential scope concern: `resource_lifetime_detector.py:374` contains an explanatory comment naming “the fixed curl shape”; the logic around it is generic callback-field and call-graph modeling, and no CVE/path/component identifiers appear in executable matching conditions. Treat this as harmless test-history wording, not a special-case code path. The separate `known_disclosed_cves` implementation is intentionally CVE-specific and is explicitly excluded from the default-enabled set; source-shaped tests there must not be reported as exact upstream-source coverage.

## 6. Task tree dependencies: T1/T2

The 2026-10-19 A-line task tree in `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-development-plan-20261019.md` sets final T3 dependencies as D1, D2, T1, T2 and I1.

- **T1 dependency exists but remains partial:** `D:\openHarmonyScanner\worktrees\a-contacts-t1-20261019\research\deliveries\a-line-sample30\20261019\T1_contacts_source_and_isolated_replay_20261019.md` states source path/permission boundary and supplemental mechanism replay; product build/HAP mapping, runtime file permissions/SELinux and official product fix remain unknown. This supports preserving a candidate-only line in final T3.
- **T2 dependency exists:** `D:\openHarmonyScanner\worktrees\a-triage-t2-20261019\research\deliveries\a-line-triage\20261019\candidate_triage_queue.json` contains 345 candidates and CSV has 345 records plus header (346 lines). The README preserves original statuses and assigns evidence/action/owner; it is a validation queue, not a new vulnerability classification.
- **I1 remains open:** the D1 and D2 integration handoffs require shared owner Catalog/profile admission and true CLI replay. Until then, D1 is not in ordinary scan selection and D2's optional `known_disclosed_cves` remains absent from default IDs.

## 7. Final T3 gates after I1

Final T3 should not close until these are independently rerun against the owner-admitted profile and exact current source hashes:

1. Confirm Catalog/planner/CLI selection and recorded rule IDs/versions for D1 path source/sink, D2 integer bounds and resource lifetime, and any explicitly approved opt-in CVE rule pack.
2. Run production CLI/Runner on D1 Contacts pinned source plus fixed/safe/unrelated and partial controls; preserve output hashes and verify partial findings survive with `blocked/partial` status.
3. Rerun D2 three exact vulnerable/fix pairs and all safe/unrelated controls through the admitted profile. Require matching source hashes, rule versions, source-binding records and per-file parse outcomes. For libtiff and libpng, do not treat fixed zero as passing safety until parser coverage is complete or an owner-reviewed narrow coverage contract is evidenced.
4. Independently exercise CVE-2026-46675 and CVE-2026-67215/67216 source-shaped rules against exact upstream vulnerable and exact fix sources. Existing synthetic/source-shaped outputs show candidate behavior and a quiet synthetic control only; they are not exact upstream fix coverage. Keep CVE-2026-46675 exact-source 0-candidate partial replay as an explicit unknown/coverage gap.
5. Preserve `validated_vulnerability=0` for component/fixture evidence and do not infer product applicability from dependency name alone. Keep source identity, build/version, entry/control, permissions and impact as explicit proof obligations.
6. Recompute all result hashes; retain failures and parser-blocked runs; review all scope diffs and run the owner-prescribed catalog/planner/Runner checks.

**Pre-review disposition:** D1 module and normalization contract: pass; D2 generic detector differential on three recent CVE families: component-level pass, with material parse-coverage limitation for two; CLI/default-set wiring evidence: pass at the pinned base. **Final T3: pending I1 and gates above.**
