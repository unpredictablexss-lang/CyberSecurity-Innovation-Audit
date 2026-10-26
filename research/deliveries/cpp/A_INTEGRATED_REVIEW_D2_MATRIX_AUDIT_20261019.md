# A 线整合漏洞清单与 D2 扫描矩阵核对

- 日期：2026-10-19
- 输入清单：`D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\cpp\源漏洞审查记录_20261018_A线整合版.md`
- 输入清单声称的 12 项：7 项当前 M2 扫描/复放案例、3 项仅有历史扫描摘要、2 项明确 N/A。
- 扫描器基线：`origin/main` / `HEAD` = `db77164fdc2af0da02e4d3efc056d84694fd68e8`；D2 检查工作树 `a-memory-d2-20261019`。
- 工作树状态：D2 工作树原本含 A detector 的未提交更改及其他研究产物；本文按当前工作树 detector 代码（integer_bounds 0.2.1、resource_lifetime 0.3.0）与 HEAD 上未修改的 Catalog/Runner 核对，不把这些工作树代码版本误称为 HEAD 中的实现。
- 对照资料：`research/deliveries/cpp/A_DISCLOSED_CVE_SCAN_PROFILE_20261019.md`、`research/evidence/cpp/d2-disclosed-vulnerability-regression.md`、`research/evidence/cpp/a-default-profile-replay-20261019/README.md`。
- 本文仅新增核对记录；未改输入报告、旧状态、Registry、Runner 或 detector 源码。

## 核对结论

当前 Catalog 注册 8 个普通默认 detector；`ohscanner.known_disclosed_cves` 已注册，但 `default_enabled: false`，须显式选择。`ohscanner.cpp.null_dereference` 也默认关闭。因而 A 线当前不存在“默认扫描 12 项披露案例”的 profile：默认集合覆盖一部分已泛化机制；known-CVE 规则包及 DSoftBus null-deref 家族不在普通默认集合内。D2 的 `run_a_disclosed_cve_scan.ps1` 是四个 detector 的显式 CLI 包装，不是 Catalog 中的具名 profile，也不改变 ordinary default。

当前 D2 默认 detector 全量 CLI 回放只为 libtiff 9900、curl 92391、libpng 33416 三组提供目标规则正/修复结果；libtiff 与 libpng 的完整源范围仍 partial/blocked，curl pair 完整解析。对 46675、67216、67215 的另一次生产 CLI 试验使用 source-shaped 控制代码，证明已注册的显式规则可运行，不证明实际上游源码根因已覆盖。27648 的整合报告所记 detector 身份与当前 Catalog 不匹配，不能纳入当前 scanner 的已验证覆盖数。

在当前 Catalog 里没有发现一个已实现 detector 完全不可注册/不可执行；可达性缺口主要是显式关闭：known-CVE pack 和 null-dereference 不会被普通默认 profile 选中。另有机制在当前 default detectors 中没有足够通用模型，即便有同名/CVE 专用签名，也不能据此称根因 detector 已覆盖。

现有 D2 研究文档还把 curl 8.8.0 写成“不在 92391 影响范围”。该结论错误：公告所述影响范围为 7.56.0–8.22.0，8.8.0 落在范围内；这只说明组件版本适用性，不证明产品调用路径或漏洞可达性。

## 12 项逐条分类

分类中的“默认可达”仅表示 detector 在普通默认选择集中、并有目标机制的 CLI 证据；不代表 complete coverage 或产品漏洞确认。“显式可达”表示 Catalog 注册且手动选择可执行。静态 finding 都是 candidate，partial/blocked 的 0 finding 不算安全结论。

| 输入清单项 | 当前 Registry/默认可达性 | D2 或历史矩阵中的结果 | 核对分类与下一步 |
|---|---|---|---|
| CVE-2025-9900 / libtiff | `ohscanner.cpp.integer_bounds` 默认选中；当前代码版本 0.2.1，泛化规则 `ohcpp-integer-bounds-pointer-offset-underflow-candidate-004`（`integer_bounds_detector.py:34–35,332–384`）。 | D2 vulnerable 1 candidate、fixed 0，但两侧同 scope 均 2/2 partial/blocked；safe control complete/quiet。OpenHarmony pin 也命中候选。 | **默认可达，候选级机制差分成立，完整源码覆盖仍 unknown。** 整合清单写 detector v0.2.6，与当前代码/D2 矩阵 v0.2.1 不一致；核清报告使用的 build/commit，再把版本字段统一。保留 safe/equal-dimension 和 lower-bound guard 控制；产品入口状态依原报告保持 unknown。 |
| CVE-2026-46675 / libpng | `ohscanner.known_disclosed_cves` v0.16.0 显式可达、默认关闭；当前规则检查受影响版本与同函数 `png_read_info`→`png_read_end` 顺序（`known_cves.py:339–395`）。普通默认集的 `resource_lifetime` 未在精确 `pngrutil.c` 源范围命中。 | source-shaped explicit CLI 正例 1 / fixed-shape 0；精确 pinned 上游源及 OH 生成源码 0 finding，`pngrutil.c` 1/1 partial/blocked，D2 记录为未知/parser gap。整合报告称 M2 机制规则未实现。 | **显式 signature 可达，但披露根因 detector 未覆盖。** API 调用顺序/版本签名不等同于内部 zstream 对已释放输入的跨函数生命周期根因。需要通用跨函数缓冲区生命周期/解压输入消费规则，并在解析可用的精确源上复放；现有 blocked 0 不算 miss 或 safe。 |
| CVE-2026-33416 / libpng cross-struct alias UAF | `ohscanner.cpp.resource_lifetime` 默认选中；当前版本 0.3.0，通用同名成员 alias→owner release→alias read 规则（`resource_lifetime_detector.py:31–32,209–285,587–628`）。 | 官方 1.6.55/1.6.56 固定源差分 2 candidates / 0；两侧 4/4 partial/blocked；三文件 independent-copy safe control complete/quiet。 | **默认可达，跨成员 alias 机制有候选差分；整文件结论仍 partial。** 整合清单写 v0.1.9，当前 D2 代码和 matrix 为 v0.3.0；统一证据绑定中的实际 detector version。继续保留 independent-copy、无关成员和 fixed controls；产品 build/link unknown。 |
| CVE-2026-92391 / curl MIME recursive cleanup | `ohscanner.cpp.resource_lifetime` v0.3.0 默认选中；callback-mediated recursive cleanup 为泛化规则，非 CVE/function-name hardcode（`resource_lifetime_detector.py:30,299–454,587–628`）。 | 官方受影响 8.22.0 / fix / safe 的目标规则结果 1 / 0 / 0，1/1 complete；默认 8-detector CLI 也触发 1 / 0。 | **默认可达，当前最佳完整静态差分。** 整合清单写 v0.1.9，与当前版本不符。A profile 文件及 D2 回归文档错误称 OH curl 8.8.0 不在影响范围；8.8.0 实际在 7.56.0–8.22.0 范围内。修正该状态，仍将产品 caller、嵌套深度可控与影响保留 unknown。 |
| CVE-2026-67216 / cJSON_Compare CPU 复杂度 | 仅 `ohscanner.known_disclosed_cves` 中有递归调用+重复 key lookup 签名（`known_cves.py:267–272`）；Catalog opt-in，普通默认扫描不执行。 | source-shaped production CLI 1 candidate / 0 fixed-shape；本地真实 `cJSON.c` parse partial/blocked，无 diagnostic；未有 verified upstream fixed source。 | **显式 signature 可达；generic algorithmic-complexity detector 缺失，实际源码覆盖 unknown。** 当前签名是函数/操作形态，不证明指数级复杂度或 attacker path。新增独立于 CVE 标签的泛化检测：递归结构与重复线性查找/匹配组合，并保留成本/安全控制和宿主调用方义务。整合报告的“没有规则”应更新为“无通用规则；当前有 opt-in source signature”。 |
| CVE-2026-67215 / cJSON JSON Patch recursion | 仅 known-CVE opt-in 规则检查 `apply_patch`、deep copy/delete 和外层 patch 循环（`known_cves.py:407–419`）。 | source-shaped CLI 1 candidate / 0 fixed-shape；本地 cJSON 范围有一文件 complete、一文件 partial，整体 blocked；缺经验证 upstream fixed source。 | **显式 signature 可达；generic recursion/resource-exhaustion detector 缺失，组件构建/入口 unknown。** 增加不绑定 cJSON/CVE 函数名的 untrusted recursive copy/tree growth/cleanup depth 分析；检验显式限深、迭代实现、循环但不递归等负例。整合报告“未实现”需区分旧扫描时点与当前已有 opt-in signature。 |
| CVE-2026-27648 / web_webview Flowbuffer 越界 | 当前代码有 known-CVE 函数名/变量形态规则（`known_cves.py:436–472`），显式可达、默认关闭；普通 `ohscanner.cpp.bounds` v0.2.0 默认选中，但现有规则面向固定数组和特定稳定数组 guard（`bounds_detector.py:252–294`），没有 shared-memory byte-range + dynamic vector length 联合追踪。 | 整合报告记 `memory-bounds v0.3.6` 对函数片段 root-loop candidate 6→0；但当前 `catalog.py` 没有 `memory-bounds` detector ID 或 v0.3.6 注册项。D2 profile matrix 则将当前覆盖归在 opt-in known-CVE signature，且称整翻译单元 partial/blocked。 | **Registry/矩阵映射冲突；generic detector 缺失。** `memory-bounds v0.3.6` 的报告来源、CLI build 和 detector ID 未绑定到本次当前 Catalog，不能当作当前 D2 default 或注册 detector 的证据。保留 known-CVE signature 为显式候选；新增通用 attacker-controlled shared-memory offset/length bounds 与动态容器索引规则，并以真实修复前后代码、变量改名/不同容器控制验收。核验该旧 M2 报告究竟来自哪个 worktree/版本。 |
| CVE-2025-26690 / communication_dsoftbus | `ohscanner.cpp.null_dereference` v0.2.0 已注册但默认关闭。 | 历史交付声称 5 candidates / fixed 0；原始 replay artifacts 不在当前 checkout，当前 CLI 未复放；整合报告明确 5 条不等于根因命中。宽选 null detector 曾在无关 fixed controls 产生噪声。 | **历史摘要，不是当前验证覆盖；显式 detector 有噪声风险。** 先恢复原始证据/精确两端 OID，使用当前 CLI 做漏洞版、修复版、安全/无关与 partial controls；在证明范围前维持 opt-in，不加入核心 profile。 |
| CVE-2025-0587 / Ark Runtime `atomic_helper.cpp` | `ohscanner.cpp.integer_bounds` 默认选中；当前代码 v0.2.1。 | 当前 CLI exact vulnerable/fixed 配对 1/0；safe/unrelated 0，partial blocked；17 项 memory-safety controls 通过。 | **generic static candidate verified；根因级命中与产品归属仍待人工复核。** 旧摘要已由当前 normalized reports 取代；保留产品发布分支 unknown。 |
| CVE-2025-23420 / Ark Runtime `JSArray::SortElementsByObject` | `ohscanner.cpp.bounds` 默认选中，当前 registry version 0.2.0。 | 当前 CLI exact vulnerable/fixed 配对 5/0；safe/unrelated 0，partial blocked；17 项 memory-safety controls 通过。旧 patch SHA 与 raw diff digest 不同。 | **generic candidates verified；根因映射不完整。** 逐条审查五个 finding 是否对应公告 OOBW，而非旧 Harness 所述 UAF；继续保留 digest discrepancy 与产品 unknown。 |
| CVE-2025-20042 / kernel_liteos_a | 输入报告明确 N/A；没有为其主张当前 A detector。 | 历史清单写 `not applicable to lexical bounds`，vulnerable/fixed=N/A。 | **N/A，非漏报或安全结论。** 当前登记为“无适用规则/未扫描”正确；除非扩充 kernel 专用机制检测，否则不纳入 A default CVE coverage 分母。 |
| CVE-2025-21098 / kernel_liteos_a | 输入报告明确 N/A；没有为其主张当前 A detector。 | 历史清单写 `not applicable to current A rules`，vulnerable/fixed=N/A。 | **N/A，非漏报或安全结论。** 与 20042 分开保留 N/A 记录；不要把无适用 lexical rule 记为 default negative。 |

## 发现的矩阵错列、漏列与可达性差异

### 错列或版本身份待纠正

1. **CVE-2026-92391 的 OH 8.8.0 范围判断写反。** `A_DISCLOSED_CVE_SCAN_PROFILE_20261019.md` 与 D2 regression matrix 都声称 8.8.0 “outside affected range”；官方范围为 7.56.0–8.22.0，8.8.0 在其中。源报告及同文件其他事实应保持产品调用链 unknown，但版本标记应为 affected-version candidate。依据：该 profile `:12`、D2 regression `:10`、来源整合报告 curl 条目 `:53–55`。
2. **当前 detector 版本号混用。** 输入整合报告列 9900 `integer-bounds v0.2.6`、33416/92391 `resource-lifetime v0.1.9`（输入 `:237,239–240`）；当前 D2 源码实际 `integer_bounds` v0.2.1、`resource_lifetime` v0.3.0（`integer_bounds_detector.py:34–35`、`resource_lifetime_detector.py:30–32`），D2 replay matrix 同样使用 0.2.1/0.3.0。生成报告必须以实际 execution metadata 的 detector version 为准，追溯 v0.2.6/v0.1.9 属于哪个旧 build。
3. **CVE-2026-27648 的 detector 身份冲突。** 输入报告列 `memory-bounds v0.3.6`（`源漏洞审查记录...md:243`），当前 Registry 只有 `ohscanner.cpp.bounds` v0.2.0、`ohscanner.known_disclosed_cves` v0.16.0 等，没有这个 detector ID/version（`catalog.py:20–89`，`bounds_detector.py:40–44,303`）。没有源绑定前，不能将 6→0 片段差分归给当前 D2 default/Registry。
4. **整合报告对 cJSON 的“没有规则/未实现”是旧扫描快照结论，不是当前源码注册状态。** 报告 `:241–242` 的真实上游 M2 结果仍是 parse-limited 0 finding；当前 D2 代码另有 known-CVE signatures 和 source-shaped CLI 正例。需改成两层：通用根因规则未建立；opt-in CVE-specific syntax signatures 已注册；实际组件源码证据仍 blocked/unknown。不能用后者覆盖前者，也不能将历史 0 finding 说成当前注册状态。

### default 与显式选择

当前 `default_detector_ids()` 在 catalog 第 90–99 行收录未标 `default_enabled:false` 的所有非 example detector。实际默认八项见 `a-default-profile-replay-20261019/README.md:16–20`；其中含 bounds、integer_bounds、resource_lifetime，不含 known_disclosed_cves 和 null_dereference。D2 默认组回放验证三个泛化家族（9900、92391、33416），结果见同 README `:7–14`。

`A_DISCLOSED_CVE_SCAN_PROFILE_20261019.md:24–38` 中的 source-shaped 已知 CVE CLI 测试通过显式选择 known-CVE detector；`I1_A_DISCLOSED_CVE_PROFILE_OWNER_REQUEST_20261019.md:7–19,22–35` 明确这是共享 owner 后续需实现/批准的具名 profile 请求。当前脚本封装不等于普通默认扫描或 Catalog 中已存在的 profile。`known_cves.py` 的 CVE 标签和模式应作为症状候选/回归 oracle，泛化 detector 的 rule_id、机制与证据义务不应按 CVE 编号 hardcode。

## 应新增或扩展的泛化检测机制

1. **跨函数缓冲生命周期与解压流读取（46675）**：建模 input/chunk buffer 的 owner/free 与 zstream/decompress callback 后续读取；API 调用顺序签名不足以代表释放后读取。要求状态可跨 parser 函数/回调传播，unknown 保留在无法解析/证明的路径。
2. **递归算法的两类资源复杂度（67216、67215；92391 已有较窄通用规则）**：分别检测递归树比较叠加每层重复线性查找的复杂度放大，以及不受限的嵌套复制/树增长/递归清理造成的栈耗尽。扩展现有 callback recursive-cleanup 规则时避免把循环遍历、有限深度或迭代实现报为等价缺陷。
3. **不可信共享内存范围到动态目的容器（27648）**：追踪可信映射长度、offset、length 的溢出安全约束及 `offset+length <= mapped_size`，并将输入序号/循环条件与 `vector.size()` 或实际容器 capacity 关联。已有 `bounds` 固定数组/有限 AST 范围不能证明此动态关系已覆盖。
4. **历史通用检测器继续按机制回归（0587、23420、26690）**：0587/23420 已有当前 source-bound CLI 配对，接下来做逐候选根因审查；26690 仍需恢复 source pair 和原始结果，用当前显式 null detector 重放并加入安全/无关控制。

## 后续可执行核验顺序

1. 先更正/补证 source binding：确认 `memory-bounds v0.3.6` 报告运行源、三个旧 detector 版本字段的真实构建身份，以及 curl 8.8.0 范围错判。
2. 保持现有 D2 默认-profile 结论仅限 9900、33416、92391；注明 partial 阻断及 curl 完整解析的差异。
3. 对 46675、67216、67215 和 27648 用精确漏洞源码、修复源码、safe/unrelated/partial control 重跑当前 CLI；source-shaped signature fixture 单列为规则 smoke control。
4. 独立复核 CVE-2025-0587/23420 的当前 source-bound replay，并恢复 CVE-2025-26690 的源对/current detector replay；N/A 两项保留排除口径。
5. 对新泛化机制按机制 family 命名并独立验收，CVE 编号只放在 coverage/test mapping，避免把 CVE signature 写成生产根因检测器。

## 可核对的证据位置

- 精确 12 项输入清单：`D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\cpp\源漏洞审查记录_20261018_A线整合版.md:233–278`。
- 当前 Registry/default semantics：`src/ohscanner/detectors/catalog.py:20–99`；CVE pack opt-in 原因 `:37–42`。
- CVE-specific signatures：`src/ohscanner/detectors/known_cves.py:267–272,339–395,407–419,436–472`。
- 通用 integer offset 规则：`src/ohscanner/detectors/cpp/integer_bounds_detector.py:34–35,332–384,514–515`。
- 通用资源生命周期规则：`src/ohscanner/detectors/cpp/resource_lifetime_detector.py:30–32,209–285,299–454,587–628`。
- 通用数组范围规则的当前限制面：`src/ohscanner/detectors/cpp/bounds_detector.py:181–294,303`。
- D2 profile 结果及 detector version：`research/evidence/cpp/d2-disclosed-vulnerability-regression.md:8–14,53–64`。
- 默认八 detector 真实 CLI replay：`research/evidence/cpp/a-default-profile-replay-20261019/README.md:1–20`。
- explicit CVE scan matrix、source-shaped CLI limitations 与 owner request：`research/deliveries/cpp/A_DISCLOSED_CVE_SCAN_PROFILE_20261019.md:7–19,24–46`；`research/deliveries/cpp/I1_A_DISCLOSED_CVE_PROFILE_OWNER_REQUEST_20261019.md:7–35`。

所有扫描/复现数字均限定在上述记录的源码、detector version、解析状态和 scope；未据此确认任何当前产品漏洞，也未将 partial/blocked 的零 finding 当作安全结论。
