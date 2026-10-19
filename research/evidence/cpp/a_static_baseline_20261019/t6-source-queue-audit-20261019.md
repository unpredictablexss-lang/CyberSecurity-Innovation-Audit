# T6 independent source and follow-up queue audit

- Date: 2026-10-19 (Asia/Shanghai)
- Checkout: `D:/openHarmonyScanner/worktrees/a-t6-source-queue-20261019`
- Base: `50b2806a7df38cd1ad07f257873617fe9d6b8337` (T3 integrated acceptance)
- Role: independent test/source-provenance audit; detector, tests, fixtures and development code were not edited.
- Source review read-only copy: `D:/openHarmonyScanner/CyberSecurity-Innovation-Audit/research/deliveries/cpp/源漏洞审查记录_20261018_A线整合版.md`, SHA-256 `0e331b9da1845eeb0c72edf226bf93a7e0de93d42f1de1e2ad2122b9fcd3ba4a`. Coverage ledger SHA-256: `e991abd2c020e5157278779374ed2f029ac6aacfddef4887adbcd160b58f8812`.

## Current disposition

The T1 matrix remains the immutable PR #30 before baseline at `8ec5f56a12e90bba56953b39eb17faa20e154da9` (13 rows). T6 reconciles later independent T3/T5 acceptance without rewriting that baseline. Current A-line case disposition: **3 PASS** for static regression only, **7 PARTIAL**, **1 BLOCK**, **2 N/A**. `PASS` says only the stated source-level regression gates passed; it does not assert product vulnerability or safety.

| Case | T6 status | Source/analysis state | Minimum next evidence | Owner lane |
|---|---|---|---|---|
| libtiff CVE-2025-9900 | **PARTIAL** | 基于固定函数形态的 unsigned dimension subtraction 与 scaled pointer offset 候选已回归；近期证据为 vulnerable 1 / fixed 0。目标二文件仍 parser partial/blocked，产品构建 profile、完整 preprocessing 和攻击者可控调用条件未知。 | 获得产品所选 GN/profile 和生成配置头文件的 source-bound preprocessing 输入；用同一两文件 scope 对 vulnerable/fixed 完成足够目标分析，并绑定 safe/unrelated source controls。若无法获得 profile，保留 PARTIAL。 | 开发线 + 测试线 |
| libpng CVE-2026-46675 | **PARTIAL** | 资源生命周期规则已有该 stale zstream/UAF 形状研究，但 exact-source production CLI runs remain 0 findings and blocked; vulnerable/fixed target files are partial. Do not claim detector success from ASan or byte identity. | 提供 parser 可见的 zstream owner/release/use state and caller sequence across required files; rerun original byte-bound snapshots under a complete source scope. Obtain exact upstream tree IDs for fix parent and fixed commit, and source-bound saf | 开发线 + 测试线 |
| libpng CVE-2026-33416 | **PARTIAL** | resource_lifetime 0.3.0/D4 and later component evidence do not close the detector case; four scoped files parse partial. A D3-era 0.1.9 replay recorded 2/0 candidates at pngrtran.c:1187 and :1228 but all four files remained partia | Obtain parser/type context that exposes cross-file owner/release/use sequence for pngrtran.c and its three dependencies; rerun vulnerable v1.6.55 and fixed v1.6.56 using one frozen detector version, then bind safe/unrelated controls. Record | 开发线 + 测试线 |
| curl CVE-2026-92391 | **PASS** | D3 rule 0.3.0 produces one root candidate on exact vulnerable lib/mime.c and zero on exact fix; both complete. | No blocking static regression item. For product assurance, bind OH product build/caller and prove whether untrusted input can create deep nested MIME; otherwise retain product impact unknown. | 测试线静态回归维护 |
| cJSON CVE-2026-67216 | **PARTIAL** | Distinct compare-cost candidate is observed at cJSON.c:3161 on OH source under 0.3.0; cJSON.c parser/detector coverage remains partial/blocked. No trusted fixed source identified. | Find a vendor/upstream fix that bounds compare work for this exact exponential root cause, bind its full source identity, and complete analysis of cJSON.c at the target operation; rerun vuln/fix plus safe/unrelated. If no real fix exists, f | 开发线 + 测试线 |
| cJSON CVE-2026-67215 | **PARTIAL** | Distinct JSON Patch add/copy tree amplification followed by recursive-delete candidate is observed at cJSON_Utils.c:861; related cJSON.c remains partial and detector analysis blocked. | Obtain real fix matching add/copy amplification then recursive delete, or explicitly retain fixed comparison as BLOCK; complete parse/model context for cross-file cJSON/cJSON_Utils flow; add/verify a safe guarded tree control and unrelated  | 开发线 + 测试线 |
| web_webview CVE-2026-27648 | **BLOCK** | Current independent acceptance is blocked. Source ledger contains exact 6.0/5.1/5.0.3 vulnerable/fixed commit-tree-blob-SHA pairs, but T3 acceptance describes a fixed-only frozen replay while T1 matrix stores vulnerable/fixed repl | Against the official source objects, re-extract vulnerable and fixed full TU bytes for each scoped release pair, verify blob/SHA, run one frozen bounds detector with explicit scope, compare parser diagnostics and candidate location, then is | 开发线 + 测试线 |
| dsoftbus CVE-2025-26690 | **PARTIAL** | Null dereference rule reports 5 vulnerable / 0 fixed candidates from exact official fetched file bytes, but model coverage is partial and run blocked; upstream commit trees remain unbound. | Recover authoritative upstream commit/tree objects (or obtain verified tree IDs from an official immutable endpoint) for both exact commits; rerun frozen current detector on those commit objects/full caller scope; confirm all candidate line | 开发线 + 测试线 |
| Ark Runtime CVE-2025-0587 | **PASS** | Exact pinned vulnerable/fixed pair 1/0, complete parse, plus independently source-bound synthetic safe/unrelated controls 0/0. | No blocker for static regression acceptance. Product version/build/caller and attacker-controlled index path are not confirmed; preserve that product-level gap if in scope. | 测试线静态回归维护 |
| Ark Runtime CVE-2025-23420 | **PASS** | Exact pinned vulnerable/fixed pair 5/0, complete parse, plus independently source-bound synthetic safe/unrelated controls 0/0. | No blocker for static regression acceptance. Product release branch, build/caller reachability, and impact remain unknown if advancing to product claim. | 测试线静态回归维护 |
| CVE-2025-20042 | **N/A** | 历史台账明确在当前 lexical-bounds 规则范围外。 | No action unless A-line scope/rule applicability changes; then reopen with explicit criteria. | 测试线维护排除理由 |
| CVE-2025-21098 | **N/A** | 历史台账明确在当前 A 规则范围外。 | No action unless A-line scope/rule applicability changes; then reopen with explicit criteria. | 测试线维护排除理由 |
| Contacts PortraitFileName | **PARTIAL** | D6 path-traversal v0.3.0 reproduces exact A0 file candidates at lines 789/790/794; D6 regression and guard-order controls pass. Line 790 has separate bucket-ID semantics; finding identity remains partial. | Obtain and source-bind a trusted fixed implementation for the A0 root cause or keep fixed comparison BLOCK; resolve field/permission semantics for PortraitFileName and bucket ID; obtain owner admission for Catalog then rerun production CLI. | 开发线 + 测试线 |


## 来源链与待证项

完整结构化来源链、文件身份、开发/测试下一步和状态理由见 [`t6-source-queue-audit-20261019.json`](t6-source-queue-audit-20261019.json)。当前重点：

- **历史案例精确绑定**：CVE-2025-0587 和 CVE-2025-23420 的 vulnerable/fixed commit、tree、blob、SHA-256 与完整解析重放在 T1/T3 原始记录中一致，T3 另有独立 source-bound safe/unrelated 合成控件；静态回归 PASS。CVE-2025-26690 的漏洞/修复文件 blob 与 SHA-256 已由官方文件获取并复验，5/0 差异可复现，但上游完整 commit/tree 对象不可得、detector coverage partial，因此 PARTIAL。
- **web_webview 来源冲突**：T1 `matrix.json` 保留 vulnerable 与 fixed 两条带文件 SHA 的 replay，均有 23 个 parse issues、0 findings、blocked；T3 首波总结又写 vulnerable full TU unavailable / fixed-only。T6 不覆盖任一方，按 BLOCK 记录；下一步先从所列 release commit 重抽精确 blob，核对 raw JSON 后再冻结一次当前 CLI 结果。
- **libpng**：1.6.55/1.6.56 的四文件范围及上游 tree 对 CVE-2026-33416 已绑定；各文件均 partial。CVE-2026-46675 的 vulnerable/fix-parent/fixed 源文件 OID/SHA 与 synthetic snapshot 核对一致，但官方 fixed/full source tree 未取得。不同 detector 版本的 0/0 与 2/0 不合并。
- **Contacts**：A0 源 commit/tree/blob/SHA 确认；2026-10-19 只读 `git ls-remote` 看到 `OpenHarmony-6.1-LTS` 指向 A0 commit，`master` 与 `weekly_20261019` 同指 `341cc3…`，目标文件 blob 与 A0 不同。该观测不证明任一历史版本都没有修复；当前固定对照仍 BLOCK。
- **libtiff**：漏洞与修复 commit/tree/blob/SHA 都记录完整；规则已有 1/0 根因候选，但 parser partial 和产品 preprocessing/profile 缺失，保持 PARTIAL。
- **cJSON**：OpenHarmony 组件 commit/tree 及两个目标文件 SHA/blob 已绑定；候选各自对应指数比较成本、JSON Patch 扩树后递归删除两个根因。没有可信 fixed source，`cJSON.c` 分析 partial，修复对照 BLOCK。

## 远端 ref 只读观察

2026-10-19 使用 `git ls-remote --heads/--tags` 记录 Contacts `OpenHarmony-6.1-LTS`/`master`/`weekly_20261019`，curl `curl-8_22_0`/`curl-8_23_0` 标签，libpng `v1.6.55`/`v1.6.56`/`v1.6.59` 标签。返回的 refs 和 hash 写在 JSON 中。该方法没有 checkout 或 fetch；branch/tag tip 只用来佐证可定位的来源，不用来推断目标文件已修复或产品包含状态。libpng v1.6.59 的 annotated tag object `a543b51f2de2904f3436830394b1013782f7f9e6` 和 peeled commit `cd952f49f95bb27154ae77dbb103032d95f6e580` 均由只读 refs 输出观察到。

## 345 候选队列

既有 A0 队列仍为 345 个唯一 ID：原始 `not_reproduced=9`、`not_testable=336`；排序状态为 9 `queued_not_reproduced`、5 `queued_first_batch`、331 `paused_pending_evidence`。来源清单 97 个文件（4,364,747 bytes）和 JSON/CSV/source key reconciliation 已通过；345 条 family leakage 标记均保留为未知待分诊。T6 只核对队列哈希与既有 reconciliation，未重写任何 ID/state，也不提供无标签支持的 precision/recall。

## 后续并行队列

### 开发线

1. libtiff：先取得与目标产品一致的配置头文件/preprocessing 输入，随后在相同 scope 验证 1/0 差分与 controls；parser partial 期间不升 PASS。
2. libpng 46675/33416：单独解决 stale zstream 与 33416 生命周期链的 parser/context 问题；统一冻结 detector 版本后复跑 vuln/fix、safe/unrelated。
3. cJSON 67215/67216：各自独立根因和 rule identity；需要目标完整分析、safe/unrelated 控件，真实修复源缺失项继续 BLOCK。
4. web_webview：先交付 source/replay discrepancy reconciliation，再决定 `bounds` 是否存在可复现漏检。
5. dsoftbus：完整 commit/tree 绑定后校准 null dereference 语义覆盖和候选位置。
6. Contacts：保留 D6 guard-order 修复与正负回归，等待 owner Catalog admission 后做 production CLI 回放。

### 测试线

1. 用冻结开发 commit 在独立 checkout 逐项重跑 exact vulnerable/fixed source；核对 commit/tree/blob/SHA、scope、profile、rule version、parse/detector coverage、finding location。
2. 将 web_webview 的两份冲突性历史表述用原始源码和 raw JSON 对账后更新附加记录，保留旧 baseline。
3. 对 26690、46675 和 Contacts 的未完整上游对象继续寻找官方可验证 tree；缺失对象保持 PARTIAL/BLOCK。
4. 只接纳来源绑定的 safe/unrelated 控件；合成控件标签与真实工程样本分开。
5. 按原 A0 ID 继续分诊 345 队列，先处理 9 个 `not_reproduced` 和 5 个首批 `not_testable`，未知家族逐项绑定责任线和最低补证。
6. 另行记录产品构建、组件链接、调用路径、权限与攻击者可控输入；这些材料不能替代静态回归覆盖。

## 可复跑校验

- Queue/source integrity: `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`
- Scope: `python -m scripts.check_change_scope --base 50b2806a7df38cd1ad07f257873617fe9d6b8337 --lane cpp`
- Patch formatting: `git diff --check`
- JSON syntax and embedded count/source hashes are validated as part of the T6 evidence check.
