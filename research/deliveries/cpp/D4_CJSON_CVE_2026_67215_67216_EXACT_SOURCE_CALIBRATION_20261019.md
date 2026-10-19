# D4：cJSON CVE-2026-67215 / CVE-2026-67216 精确源码校准

日期：2026-10-19  
基线：`db77164fdc2af0da02e4d3efc056d84694fd68e8` (`origin/main`)  
隔离分支：`codex/a-cjson-d4-20261019`  
范围：核对真实组件源码、复跑最小生产 CLI、区分签名候选与机制覆盖；不改 Catalog、Runner、contracts 或已推送 PR 分支。

## 结论

当前 A 线没有独立的通用 algorithmic-complexity detector。现有原型是 opt-in `ohscanner.known_disclosed_cves@0.16.0` 中两条窄 source-shape 签名，加上 `tests/detectors/test_known_disclosed_cves.py` 的 synthetic 正/负 fixture。实际目标源 CLI 已确认两条签名都能命中 pinned 的真实 cJSON 代码；这证明规则对已知漏洞形状有响应，**不证明通用复杂度根因分析、修复侧不报、完整文件扫描通过或产品漏洞成立**。

D4 状态为 **BLOCKED：无法构造权威固定版/安全对照，因而不能完成 vulnerable/fixed/safe 精确源差分准入**。官方咨询材料截至 2026-08-28 均称未有上游修复；本地可复核的 1.7.17 与 1.7.19 源都属于披露影响范围。不得把自行修改的 counterfactual、synthetic fixture、test 文件无命中或另一个受影响版本冒充 fixed/safe 控制。

## 真实源码绑定与 CLI 结果

执行脚本：`research/evidence/cpp/a_cjson_d4_20261019/run_exact_source_cli.py`。它校验输入文件 SHA-256 后，把这些**原始字节、不改源码**复制到临时 Git snapshot，以调用生产入口 `python -m src.cli ohscan-run`；snapshot commit 只是 CLI 所需的包装身份，不冒充上游 Git commit。完整 stdout、临时 commit/tree、覆盖与诊断见 `research/evidence/cpp/a_cjson_d4_20261019/exact_source_cli_replay.json` 及其逐次 CLI JSON/Markdown。

| 来源/版本 | 文件与 SHA-256 | 目标源码 CLI | 解析/覆盖 | 对照 |
|---|---|---|---|---|
| D49 pinned `openharmony/third_party_cJSON@0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`；D49 tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`；v1.7.19 | `cJSON.c` `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`；`cJSON_Utils.c` `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9` | `cJSON.c:3067` 命中 CVE-2026-67216；`cJSON_Utils.c:808` 命中 CVE-2026-67215；detector `blocked` | 2/2 partial，0 complete；仍未知 | `tests/compare_tests.c` + `tests/json_patch_tests.c` 0 候选；2/2 partial，blocked，属于同组件的无关文件控制，不是修复版/安全控制 |
| OpenHarmony 5.0.2 本地 cJSON v1.7.17 源快照（其 `.git` 元数据不可用，本次按实际源码 hash 绑定） | `cJSON.c` `5518fa1468362e7b357ee4239aeddcdae081c001467a6073ddc6a25930b83fc7`；`cJSON_Utils.c` `9cdd62376a8e46de94fc63bc899d928c56ed6e08a5109be5d64ebe9a6a4add4d` | `cJSON.c:3310` 命中 CVE-2026-67216；`cJSON_Utils.c:825` 命中 CVE-2026-67215；还命中同文件既有 CVE-2025-57052 签名；detector `blocked` | 2/2 partial，0 complete；仍未知 | 同版本两份 test source 0 候选；2/2 partial，blocked。不是修复侧或安全文件 |

D49 的整组件生产路径此前扫描 99 个 C/C++ 源文件、61 complete / 38 partial，但因至少含 partial 覆盖而 blocked；其两条 cJSON 候选的文件 hash 与本轮目标源 hash 完全一致。D4 本轮 CLI 进一步把最小 scope 收到两份根因文件，并在同一引擎上另跑无关 test-source scope，未用 synthetic 代码替代漏洞目标源。

## 对 prototype 的机制审视

- **CVE-2026-67216 / CWE-407**：真实 `cJSON_Compare()` 对 object 两侧各迭代一次，每个子项做线性 key lookup，且对匹配值递归比较；源码还注释 object lookup 为 O(n²)。该组合可在相同深度对象中放大递归成本。当前 signature 仅检查同函数中至少两个递归调用、`get_object_item` 与 `cJSON_ArrayForEach`。它没有构建递归调用图或数量级模型，不能从候选单独证明指数增长，也没有完整处理 base-case、对象形状或真正的安全负例。
- **CVE-2026-67215 / CWE-674**：真实 `apply_patch()` 深复制 JSON 值，`cJSONUtils_ApplyPatches*()` 循环应用 patch；cleanup / remove 路径进入递归 `cJSON_Delete()`。`cJSON_Duplicate()` 的 circular limit（10000）高于 parse nesting limit（1000），仍可能使复制后树的删除深度超过线程栈承受能力。当前 signature 搜索 duplicate/deep-copy、delete、batch apply 和无可见深度上限的局部形状；它没有证明外部输入可达、树深确实增长，或析构是否会在特定 patch 路径执行。
- **固定/安全判别尚未验证**：synthetic 单测证明的是人为字符串片段让签名命中/不命中。D4 找不到可绑定的官方固定提交；官方 advisory 当前记录也没有 patched version。源码测试文件为 unrelated negative control，解析还 partial，不能当 fixed/safe control。
- **默认扫描覆盖**：`known_disclosed_cves` catalog 明确 `default_enabled=false`。`integer_bounds` 与 `resource_lifetime` 当前也不建模上述复杂度/深度放大根因；默认跑 generic detector 不等于会扫描出这两个漏洞。

## 可复核出处

- D49 机器报告：`research/data_sensitive/D49_KNOWN_CVE_REPLAY/cjson.json`；报告称 latest 1.7.19 source tree 对两个 CVE 各保留一个 hash-bound candidate，99 文件有 38 partial，整体 blocked，`validated_vulnerability=0`。
- 当前原型和 synthetic controls：`src/ohscanner/detectors/known_cves.py`、`tests/detectors/test_known_disclosed_cves.py`。版本 0.16.0；default catalog 明确关闭：`src/ohscanner/detectors/catalog.py`。
- 上游/公告：CVE-2026-67216 [GitHub Advisory](https://github.com/advisories/ghsa-ff2v-f99f-wm3f)；CVE-2026-67215 [Red Hat CVE record](https://access.redhat.com/security/cve/cve-2026-67215) 与 [Ubuntu CVE status](https://ubuntu.com/security/CVE-2026-67215)；上游维护公告 [DaveGamble/cJSON issue #1080](https://github.com/DaveGamble/cJSON/issues/1080)。审阅的 advisories 标示暂无上游 fixed version/commit；无固定源码对用于本轮 CLI 校准。
- 真实源 CLI 和控制记录：`research/evidence/cpp/a_cjson_d4_20261019/`。

## Blocked finding 与缺口

| Finding | 证据 | 未闭合项 |
|---|---|---|
| 真实已披露源能产生签名 candidate | v1.7.19 与 OH v1.7.17 SHA-256 均固定；生产 `ohscan-run` 在真实根因文件上分别报 67216/67215 | 来源版 Git commit 对 v1.7.17 不可用；两组完整覆盖都 blocked/partial |
| unrelated controls 不报 CVE | 两版本 test source scope 都为 0 finding | controls 本身 partial，且无关样本不能证明受影响实现已修复或安全 |
| 固定/安全样本判别 | 无 | 上游 advisory 未给修复提交/版本；需官方修复或独立安全审查并冻结的修复源码后，才能做 fixed/safe CLI 正负对照 |
| prototype 对真实复杂度根因的归因质量 | 函数结构与 advisory 描述一致，candidate 位置绑定真实文件 hash | 当前只作 lexical shape match；缺 complexity model、对抗性安全/无关场景、真实运行时成本或完整代码路径证据 |
| 产品适用性 | 原型 obligation 明确缺 product build、attacker path、impact | 需要确认 OH 产品 profile 是否构建 `cJSON_Utils.c`、真实 caller 是否接受不可信 Compare/JSON Patch 输入以及产品影响 |

## 结构化下一步 Vibe Coding 提示词

```text
角色：A 线 C/C++ 静态分析与漏洞回放工程师。

目标：为 CVE-2026-67216（递归 JSON 对象比较复杂度）与 CVE-2026-67215（JSON Patch add/copy 放大深度后递归删除）建立可审查的机制级检测验证。以本交付的精确源码 hash、D49 机器回放、官方 advisory 和 upstream 状态为起点；不要重新把 CVE ID/文件路径/函数名硬编码成通用 detector 结论。

边界：只在独立 A 线 worktree 中工作；不得改 Catalog、Runner、contracts 或已推送 PR 分支。不得用 synthetic 片段替代真实漏洞源。没有权威 fixed source 时不得构造 synthetic fixed 结果，也不得把 unrelated test files 说成安全样本。保持候选与产品漏洞确认分离。

工作步骤：
1. 固定官方漏洞源完整 Git commit/tree/blob 与 SHA-256；追踪官方 advisory/upstream issue/PR，确认是否出现可审计修复提交。对旧的 OH v1.7.17 snapshot 明示 source commit 不可用。
2. 若有 authoritative fix，冻结同一依赖/配置的 vuln、fixed、safe、unrelated 四类真实源码；如果无 fix，登记 blocked 并停在真实 vuln 与 unrelated calibration。
3. 先审视已有 `known_disclosed_cves` shape rule 和 generic A detectors；提出机制级模型：67216 应分析对象两侧匹配与递归展开造成的增长；67215 应连接 copy/add 对树深的放大与递归 delete 的栈成本。不得只凭 function name/CVE/path/hash 发 candidate。
4. 使用生产 `python -m src.cli ohscan-run` 对每个固定的真实源码对象做最小 exact-source CLI 回放；记录 commit/tree/blob/SHA、include scope、完整命令、parser状态、detector status、诊断位置/规则、报告hash。partial/blocked 必须保留 unknown。
5. 对 67216 与 67215 各自报告 vuln→fixed 差分；验证安全边界、相近但无风险实现、unrelated functions 的负控，检查固定侧是否 residual。若完整解析或源码身份不可得，写明确 blocker 而非声称 0 finding 安全。
6. 只有在 source-level evidence 闭环后，另行追产品 build graph/profile、API caller、攻击者控制和影响；不要在此阶段声称产品漏洞。

交付：dated Markdown finding/matrix、可重复 exact-source replay script 与 machine JSON、checksums、下一目标状态。跨函数complexity模型/数据flow如需新增，先单独登记设计与所有者评审；当前任务不得改共享接口。

完成标准：每个 CVE 都有真实固定漏洞源 CLI candidate，并有真实修复版/安全/无关/partial controls 的结论；修复侧无 root-specific residual，关键源解析可完成，盲测材料另行冻结。若 upstream 尚无 fix source，目标保持 BLOCKED，明确缺口并持续等待/追踪修复对象，绝不将 synthetic 对照升格。
```

## 持续目标

持续推进到两个 CVE 都具备可复核的真实漏洞/固定源码对、source-bound exact CLI replay、机制相关安全与无关控制、完整解析和固定侧无 root-specific 残留。上游尚无固定对象时维持 `BLOCKED`，以后每次新增证据先核验 source identity，再继续回放；在闭环前不宣称修复版识别能力、完整覆盖、Recall 或产品漏洞。
