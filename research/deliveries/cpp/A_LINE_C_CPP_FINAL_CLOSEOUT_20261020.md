# A 线 C/C++ 最终收尾验收（2026-10-20）

## 快照与范围

- 最终代码快照：`3ec1139e5990b9a706975e876d9b53a1a6f1c14d`（基于当前可用 `origin/main` `0f53af62283dbd0f249280805e8286a04b2d43b9`）；后续提交仅补入本验收表与重放/保全报告。
- 分支：`codex/a-line-final-closeout-20261020`。初始交付提交 `fb6e31a397c34f5ebb768c834f62fb0a5111c0dd` 及其状态修正提交 `27377ddd3877f3636334dc451b52afc4a06653fe` 已推送；当前继续复核的新增材料在后续提交中。尚未创建/合入 PR。
- A 分支比较基线：`f193636e7b1384f0ca2e360b4ec3b0b0348d9340`。只选入有测试/来源支撑的 bounds 规则、resource lifetime 精化和 unsafe memory call 的 partial 文件状态修复。`integer_bounds` 与 main 无有效代码差异；`memory_safety.py` 无有效差异。
- 实际 Catalog：bounds 0.3.0、integer_bounds 0.2.1、resource_lifetime 0.4.2、unsafe_memory_call 0.5.0 默认启用；null_dereference 0.6.0 与 path_traversal 0.3.0 默认关闭，显式选择才运行。没有依赖升级。
- 初次最终验收保留的静态历史口径为 2 PASS / 9 PARTIAL / 2 N/A。随后对 CVE-2025-0587 的精确 vulnerable/fixed 源码补做根因差分复核，当前静态口径调整为 3 PASS / 8 PARTIAL / 2 N/A；产品级仍为 0 PASS / 11 PARTIAL-BLOCK / 2 N/A。四项最终快照真实源 CLI 回放，其他案例仍按表内标记。

## 13 案验收表

“有界静态回归”是截至此前整合验收的 disposition；“最终快照”列准确标记是否在本代码提交上重放。PASS 只表示源版本候选差分成立，不表示产品级漏洞确认。

| # | 案例 | 有界静态回归 | 最终快照真实源回放 | 产品级证据 |
|---:|---|---|---|---|
| 1 | libtiff CVE-2025-9900 | PARTIAL | not_run；历史配对两侧解析均 partial/blocked | PARTIAL-BLOCK |
| 2 | libpng CVE-2026-46675 | PARTIAL | not_run；历史完整文件解析有错误 | PARTIAL-BLOCK |
| 3 | libpng CVE-2026-33416 | PARTIAL | not_run；历史多文件解析 partial | PARTIAL-BLOCK |
| 4 | curl CVE-2026-92391 | PASS | vulnerable 1、fixed 0；两侧 parse/coverage complete | PARTIAL-BLOCK |
| 5 | cJSON CVE-2026-67216 compare cost | PARTIAL | not_run；历史仅 bounded-shape candidate，缺可信修复源 | PARTIAL-BLOCK |
| 6 | cJSON CVE-2026-67215 tree amplification | PARTIAL | not_run；历史目标完整但语义聚合 partial，缺根因匹配修复对照 | PARTIAL-BLOCK |
| 7 | web_webview CVE-2026-27648 | PARTIAL | not_run；历史全文件解析 partial，fragment 结果不能替代全源 | PARTIAL-BLOCK |
| 8 | dSoftBus CVE-2025-26690 | PARTIAL | not_run；历史 5/0 摘要没有当前源绑定复放，语义控制不完整 | PARTIAL-BLOCK |
| 9 | Ark runtime CVE-2025-0587 | PASS | vulnerable 1、fixed 0；两侧 parse/coverage complete；精确补丁差分命中候选所在函数 | PARTIAL-BLOCK |
| 10 | Ark runtime CVE-2025-23420 | PASS | vulnerable 5、fixed 0；另有同源 comparator snapshot safe control 0；均 complete | PARTIAL-BLOCK |
| 11 | kernel_liteos_a CVE-2025-20042 | N/A | not_applicable；无本轮适用规则 | N/A |
| 12 | kernel_liteos_a CVE-2025-21098 | N/A | not_applicable；无本轮适用规则 | N/A |
| 13 | Contacts PortraitFileName path traversal | PARTIAL | 3 candidates；parse/规则覆盖 complete；无可信修复版 | PARTIAL-BLOCK |

## 真实源回放细节

证据 JSON/Markdown 均在本目录。所有扫描通过生产 CLI `python -m src.cli ohscan-run` 生成，并绑定仓库、commit、Git tree/blob、源 SHA、profile、detector 版本和输出诊断。解析、规则语义覆盖、候选、运行影响分开判断：

- CVE-2025-0587：`atomic_helper.cpp` vulnerable `cae11f121c030a90ba41d8e4d866f91292f25892` 1 个 integer_bounds 候选；fixed `5aa9c035` 前缀版本 0；完整解析和规则覆盖。缺该根因的同源真实安全/负例控制；运行影响 not_run。
- CVE-2025-23420：`js_array.cpp` vulnerable `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` 为 5 个 bounds 候选；fixed `1b235315` 前缀版本 0。额外在 vulnerable commit 的 `array_helper.cpp` comparator snapshot 控制为 0。解析/规则覆盖 complete；候选尚未逐条证明等于 CVE 公告根因；运行影响 not_run。
- Curl CVE-2026-92391：`lib/mime.c` vulnerable `01346829096c61b372692f6dc43ffa778c6caccd` 1 个 resource_lifetime 候选，fixed `d7546809d5bd548b69ec49fca26565c8f6f0d344` 为 0；完整解析/规则覆盖；运行影响 not_run。
- Contacts：`contacts_data_ability.cpp` `b02aadfc2d801ee30573fcb2d13490298e146fea` 3 个 path traversal 候选；完整解析/规则覆盖。尝试查找官方 6.1 LTS 对应修复源，公开 refs/可用 6.0 clone 均未提供匹配修复对象；产品调用链和归一化行为未验证，因此安全对照、运行影响与产品结论 unknown/not_run。

### CVE-2025-0587 source-root-cause review

The exact vulnerable/fixed Git objects were diffed after the initial closeout. In `AtomicHelper::ValidateAtomicAccess`, the vulnerable source converts `GetArrayLength()` to signed `int32_t` and narrows the `ToIndex` result through `DoubleInRangeInt32` before its bounds check; the detector candidate is at the corresponding `index` conversion (vulnerable source blob `7fd67717571c6d8fe7b10bf294998e952dc61e36`, SHA-256 `f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541`). The fixed blob `80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c` keeps length unsigned, converts the index to `uint64_t`, checks it against length before offset arithmetic, and performs the offset multiplication in the wide type. This exact function-level patch relation, together with complete vulnerable/fixed CLI parse and 1/0 candidate delta, supports **bounded static PASS**. It does not establish attacker reachability, a successful out-of-bounds access, execution impact, or applicability to a shipped product build; those remain unknown/not_run. The March 2025 OpenHarmony bulletin independently lists CVE-2025-0587 as an integer-overflow issue in `arkcompiler_ets_runtime` affecting OpenHarmony 4.1 and 5.0.2 lines ([official security mailing-list bulletin](https://lists.openatom.io/hyperkitty/list/security@openharmony.io/thread/435GCMWA4TBKSDHCKDUQKITICCLLBCBI/)).

### Representative case and dynamic attempt (2026-10-21)

CVE-2025-0587 is retained as the representative exact-source case because the A-line source objects have full vulnerable/fixed commit, tree, blob and SHA-256 bindings; detector/rule `ohscanner.cpp.integer_bounds` 0.2.0 / `ohcpp-integer-bounds-narrow-index-candidate-003` 0.2.0 reports 1/0 at `AtomicHelper::ValidateAtomicAccess` line 71, and the exact function patch matches the candidate. The detailed source binding, scan commands and current reproduction limit are in [the representative case packet](../../evidence/cpp/a_final_closeout_20261020/representative_ark_0587/A_LINE_REPRESENTATIVE_CASE_20261021.md).

An isolated WSL component build was attempted on 2026-10-21 and exited 127 because the available Ark Runtime component checkout has no `./build.sh` product driver. The full attempt log is preserved alongside the packet. Component runtime/PoC result remains **not_run**; this does not change the source-level PASS or `validated_vulnerability=0`. The Contacts file-deletion PoC is documented separately and uses a PoC-only fixed guard, not a trusted upstream fixed source.

## 代码、回归和记录保全

- A0 原始候选包保存在 `research/deliveries/cpp/a0_original_20261018/`。便携 verifier `verify_a0_preservation.py` 校验了 97 个 SHA 清单文件（4,364,747 字节）、345 个唯一 ID、来源关联和历史状态；结果通过。345 条历史状态为 336 `not_testable`、9 `not_reproduced`；队列状态为 331 `paused_pending_evidence`、5 `queued_first_batch`、9 `queued_not_reproduced`。原始报告 Markdown/PDF、README、triage CSV/JSON、检查 NDJSON 已保留；未纳入 Git 的约 720 MB 未清单 POC 运行产物仍在未改动原工作树。
- 最终快照回归：73 tests passed，覆盖 bounds/integer bounds、resource lifetime、unsafe memory calls、path traversal、NULL dereference 与信号控制中的正例、修复/安全、无关、partial/unknown、绑定和预算行为。
- `tests.detectors.test_cpp_path_traversal_catalog` 在 Windows 因 `fcntl` 缺失而无法导入；WSL 环境的 `tree_sitter` 缺失。替代核验：生产 Catalog 直接构建断言通过，实际 CLI path traversal 源回放成功。
- 四个相关 detector 通过真实源 CLI；其他 9 个可适用案例本轮未冒充重放。没有完整产品镜像/build profile/运行时复现；所有产品结果维持历史 0 PASS / 11 PARTIAL-BLOCK / 2 N/A。
- `git diff --check` 对实现/测试/方法文档通过。原始保全材料的历史尾随空格保留，未为格式清理改写证据字节。

## 剩余事项与最小复验条件

| 负责方 | 缺失输入/事项 | 解除后复验 |
|---|---|---|
| A 线 + libtiff/libpng/web_webview 组件维护方 | 精确目标构建宏、完整可解析源码和匹配安全/修复版本；libtiff 还缺根因同源安全控制 | 同一 CLI 对固定源 SHA 跑 vulnerable/fixed/safe/unrelated/partial，记录逐文件解析和规则覆盖 |
| A 线 + cJSON 组件维护方 | CVE-2026-67216/67215 的可信修复 commit 或可信安全对照，确认 compare/tree 语义 | 用精确源 commit 跑同一 CLI 两侧及负例，评估 partial 语义，不以合成样例代替 |
| A 线 + dSoftBus 组件维护方 | 精确 CVE-2025-26690 vulnerable/fixed OID、控制流 guard 证据 | 当前 NULL detector 显式选择的生产 CLI 双侧回放和安全/无关控制 |
| Contacts 源码维护方 | `OpenHarmony-6.1-LTS` 对应 fixed/safe 源对象；修复行为及 caller/path normalization 证据 | 同 detector/CLI 对 vulnerable、fixed、安全、无关和 partial 源回放；再核调用者/产品 build |
| 产品集成方 | 11 个适用案例的产品源码 pin、构建宏/配置、调用入口和可复现运行证据 | 将源扫描结果与实际产品构建、入口可达性、触发条件和影响关联；之前不提升产品判定 |

本轮未增加漏洞家族或扩展候选扫描。没有可靠标签时不报 Precision/Recall；历史 unknown/candidate 不升级。`not_run` 表示未执行。
