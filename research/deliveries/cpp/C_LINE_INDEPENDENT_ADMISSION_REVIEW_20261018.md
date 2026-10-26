# C 线 Ark Runtime 历史对照重放与独立准入复核

首次复核：2026-10-18；更新：2026-10-19（中国标准时间）  
结论：**重放阻塞；C 线维持研究候选，不具备准入或漏洞确认依据。**本报告按当前冻结的 TypeSafety 0.3.2 评估。它不修改产品准入状态，也不把历史不同版本、parser 或配置的输出拼成同一组指标。

## 冻结范围

当前冻结记录为 [算法冻结 JSON](ark-runtime-c-line-algorithm-freeze-20261018.json)：Detector `ohscanner.ark.runtime.type_safety` 0.3.2，模型摘要 `6f26027b58baed730d5b8287c77f4c5f763873ab5f78416c8484f6a712f212df`。复核期间冻结文件多次更新；本轮最新捕获快照见 [2026-10-19 observed freeze](C_LINE_FREEZE_OBSERVED_20261019.json)，SHA-256 `852d403e158816ee2a9f29ac00e925f53c3d33064f929dd56ec4259c5d205cae`，捕获时间 2026-10-19 00:00:36 +08:00。快照中全部实现/模型哈希匹配当前文件。Runtime Core holdout manifest 与旧 replay manifest 仍写 `0b8b08…8291`；其 digest 不匹配最新 freeze，不能证明 holdout 当前绑定到本版 freeze。冻结只允许以下两个 Ark Runtime 源码 profile：

| 样本 | Commit | Tree | 目标文件 blob | 相关 creator blob |
|---|---|---|---|---|
| Filter 父版本 | `830e85b40240677039719fcbf14f721ad3b19050` | `579712c1ebbb703d17cea422b1572023bed5d8a4` | `054451b1be4f39254d56a1683cc9d1c1b5e55018` | `757b8d050d306d349822600deacb295c7a54245e` |
| Filter 修复版本 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `82af11ced4297818410ccf61906b703d25b69165` | `95f54f2875f401afe3167c62f8c1e7799782be8c` | `757b8d050d306d349822600deacb295c7a54245e` |

冻结实现绑定 `analysis.py`、`detector.py`、`model.py`、`runtime_ir.py`、`syntax.py`、`type_origin.py` 的 SHA-256。最新快照里各实现/模型 digest 与当前文件相符；本轮聚焦回归 32/32 通过。复核期间 freeze 自报的 binding/history test count 从 22 增至 27；更新前曾观察到一次 stale digest failure，随后 freeze 与工作树实现同步。当前结论绑定 2026-10-19 捕获快照，早期失败是更新前状态。

## 当前重放结果

当前 0.3.2 没有产生可归属为 candidate、safe 或 miss 的历史 Detector 结果。本轮通过 WSL 只读 Git 校验确认两个冻结 profile 的 commit/tree/target/creator 对象，并逐项验证每个 profile 的 30 个模型依赖绑定（共 60 个 commit/path/blob/byte SHA 核对）；结果见 [source binding verification](C_LINE_SOURCE_BINDING_VERIFICATION_20261018.json)。因此当前阻塞不是目标历史对象缺失或最终 freeze 的实现哈希不匹配，而是 GN 输入类型合同无法表达、产品构建/parser profile 不完整及产品闭包未证实。逐样本状态如下：

| 样本 | 状态 | 对象/内容校验 | 结果与预期差异 |
|---|---|---|---|
| Filter 父版本 | `blocked` | WSL Git object store 中 commit/tree/path/blob 全匹配；目标源码 blob/SHA 与保存字节相符；profile 的 30/30 模型依赖绑定匹配。 | 没有当前 Detector 输出。若只解释规则预期，父版 store 使用接收者类型来源，是待检候选，不是已观测命中。 |
| Filter 修复版本 | `blocked` | WSL Git object store 中 commit/tree/path/blob 全匹配；目标源码 blob/SHA 与保存字节相符；creator 来源存在；profile 的 30/30 模型依赖绑定匹配。 | 没有当前 Detector 输出。补丁将 store 的类型来源改为新数组类型；但新类型读取位于 pending-exception 检查之前，不能据此记 safe，按现有契约应保留 `unknown`。 |
| Set 安全对照 | `blocked` | 属于冻结 profile 的对照，但所需同一版本解析/依赖闭包未运行。 | 0 finding 不能解释为安全，也不能记作 miss；无同管线结果。 |
| Map 无关对照 | `not_analyzed` | 不在冻结 caller profile。 | 不适用，不覆盖为安全或 miss。 |
| `slowpath_lowering.cpp` 异常传播父/修复版本 | `not_analyzed` | 来源绑定保存在另一研究记录，属于独立词法探针。 | 不是 TypeSafety 0.3.2 冻结规则的样本，未纳入本轮指标。 |

本报告附有 [当前 0.3.2 复核 manifest](C_LINE_HISTORY_REPLAY_REVIEW_MANIFEST_20261018.json)，逐项绑定冻结 commit/tree/path/blob/source SHA，并记录当前执行状态及阻塞。它是审查 manifest，不伪称 Detector 已运行。完整的 60 条模型 source binding 复核见 [source object manifest](C_LINE_SOURCE_BINDING_VERIFICATION_20261018.json)（SHA-256 `46da2ec5…d6ab`，另有 detached `.sha256`），通过 WSL Git object store、`GIT_NO_LAZY_FETCH=1` 完成。旧 [历史恢复记录](../../experiments/ark-runtime-history-replay-20261018/README.md) 与同目录 `replay-manifest.json`、`run-summary.json` 仍表示当时 Windows-side 0.3.1 恢复尝试；对象不可读结论已由新 WSL 校验更新，不应继续引用为当前事实。它们也不是当前 0.3.2 Detector 结果。

## 不能重放的具体原因

1. **旧依赖摘要不能充当当前 0.3.2 的闭包证明。**历史 `dependency-manifest-v1.json` digest `238ecaa18f68067a18434078d02a9ec07d51851b9b2b2b3ade54eb0c3d39b60e` 绑定 21 inputs、33 obligations；其验证器报告旧 `detector.py`/`model.py` 哈希，与最终 0.3.2 freeze 不同。当前 freeze 自身 implementation/model SHA 校验通过；模型声明的 30 个 source binding/profile 也已逐项验证。但完整 C++ 编译/预处理依赖闭包仍未证明，不能用模型 30 项语义 binding 代替产品 depfile。
2. **当前规则要求的一个输入类型无法通过公开 SourceUnit 合同表达。**`model.py` 将 `ecmascript/compiler/BUILD.gn` 绑定为必需依赖；`detector.py` 要求每个依赖单元语言为 C++；`SourceUnit` 允许列表不含 GN。因而按当前合同提供这个依赖会被拒绝，不能把缺项伪造成 C++ 源文件或 fixture。
3. **历史源对象身份已补强，但仍不等于产品分析闭包。**WSL `git show`/`rev-parse` 在 lazy fetch disabled 下确认两个目标 commit/tree/blob 与当前模型 30 个绑定/commit 全匹配，creator bytes 也可直接读取。C1 所需产品 compile closure 仍未提供；异常传播 pair 属于另一规则/配置，不能补齐当前 TypeSafety replay。
4. **分析输入不完整。**C1 profile `a65a2853ccae13da167d9aa4720ab8b11ec16656` 有目标源码绑定，但缺少 `compile_commands`、`args.gn`、编译器路径/版本、命令 argv、defines、include 顺序、生成输入与依赖闭包。C2 解析报告有 13 个 Tree-sitter error/missing 节点；宏未展开，命名空间/类型解析和完整构建未证实。C1 profile 还不属于当前冻结的两个源码 profile。

这些阻塞使本轮无法在同一冻结模型、parser/toolchain、预处理配置和 scope 下运行父/修复/安全/无关版本的统一管线。最终 live freeze 没有固定 parser/toolchain 包版本或二进制摘要；旧 C3/C4/C5 的 parser/Python 记录不能代替本版配置。严格模型的两个历史 profile 也不含 C1 产品候选 `a65a…6656`。不得从 0.2.0、0.3.0、0.3.1、异常规则或不同 parser 的历史结果中拼出指标。旧运行保留原状态与含义，参见 C2 exact-source、exception-guard 和 exception-rule 原始记录。

## C0–C6 证据索引与独立判断

仓库没有找到一个权威的 C0–C6 主登记表；以下按实际交付材料归档，不把它说成项目原有编号。每项分开列出已证明、未证明和决定：

| 项 | 证据与已证明 | 未证明 / 矛盾 | 决定与最小补救 |
|---|---|---|---|
| C0 合同/冻结 | `ark-runtime-c-line-contract-20261018.md` 与最新 0.3.2 freeze 定义 exact owner/signature/source profiles，partial/unknown 与 blocked 边界；source binding manifest 通过 WSL Git 校验两个 commit/tree 和 60/60 模型依赖对象；最新 freeze 与当前实现哈希匹配，聚焦回归 32/32。 | Freeze test count 在复核期间从 22 增至 27，需将未来 holdout/结果绑定到稳定快照。旧 dependency verifier 校验的是旧版 manifest。模型把 `ecmascript/compiler/BUILD.gn` 列为依赖，但 SourceUnit 只允许 c/cpp/js/ts/arkts，Detector 又拒绝非 cpp 依赖，当前合同无法表达 GN 输入；freeze 也未固定 parser/toolchain binary/package。 | 不准入。先为真实 GN 输入建立可校验合同并重建 product/dependency/parser profile；冻结后从干净环境复核实现/模型/清单和状态语义。 |
| C1 构建 profile | HiHope/RK3568 manifest pins 的 runtime、vendor、board commit/tree/blob 与配置摘要有记录；runtime 目标文件与 pin 的 blob/SHA 可对照。 | 无同一构建的 args.gn、compile command/compile_commands、clang 身份/版本、target triple、defines、include 顺序、生成头和依赖闭包；profile checker 实测 exit 2。Profile commit `a65a…6656` 不属于 0.3.2 两个分析 commit。 | `blocked/unknown`。向 build provider 获取同一 manifest 的原始 GN/Ninja/compiler/depfile 证据并绑定。 |
| C2 parser/owner | 在 `a65a…6656` pin 上，Filter/Map syntactic owner 可解析为 `BuiltinsTypedArrayStubBuilder`；21 个依赖 blob/SHA 核对记载于 provenance。 | Tree-sitter TU 仍 `partial`，13 个 error/missing 节点；其私有重跑因缺 `tree_sitter_c` 未到 parser 阶段。2026-10-19 同一 pin 的实际产品 compile edge 已成功；派生 Clang AST/宏表确认当前产品 `Filter`、creator、store 的签名、重载与宏/类型流。此 compiler AST 是当前 a65 产品 profile 的证据，不会把 research parser 的 partial 标记覆盖成 complete，也不替代旧历史 profile 的解析。 | 既有 partial-contamination/identity 契约仍须保留并由研究适配器回归；产品 Clang AST 只用于当前 TU 的方法/type/build 复核，不构成 C-line Detector public Runner 输出或漏洞证据。 |
| C3 历史 TypeSafety 重放 | 0.2.0 exact-source raw record 绑定父/修复 source bytes 的 blob/SHA；记录 parent candidate、fix matched、Set matched、Map 无观察，所有文件为 partial。 | 不是当前 0.3.2；Python 3.13.9 对历史 frozen 3.12.0 有漂移；profile 假设宏且无预处理。原始 record 顶层和逐输入 model 摘要字段不一致，需回到 frozen code/argv解释；本报告不将其结果用于当前准确率或当前重放。 | 仅作历史开发控制。重建匹配 frozen code/environment 后才能复验历史结果；当前分数不拼接。 |
| C4 exception-guard 修订 | 0.3.0 raw result 表明父版 candidate、fix pre-guard read unknown、post-guard control matched、unknown call 后 unknown，保留 partial。 | 与 0.3.2 模型/parser/config 不同；不是当前 TypeSafety 对照指标；没有产品 runtime evidence。 | 作为保守状态语义的回归线索，不作为当前算法结果。 |
| C5 exception-protection 独立规则 | 0.1.0 研究规则绑定 `slowpath_lowering.cpp` 父/修复与 JS 回归 source；raw record parent candidate/fix matched，另有 safe / not_applicable control，whole-TU aggregate blocked。 | 不是 TypeSafety rule，parser虽版本号匹配 C3，Python不同；CFG/dominance/state dependence及运行时异常语义未知。 | 继续独立研究规则，不能计入 TypeSafety 样本或产品准入。 |
| C6 holdout、动态、修复、性能 | Frontend blind packet 不含 Detector 输出；Runtime Core packet 明示开发者 freeze 前查看 source；动态门和 species review 记录产品入口/影响、二进制及测试缺失。 | Frontend 1 样本、Runtime Core 20 样本均 reviewed=0，标签字段为空；没有 reviewer identity、分歧/裁决。无真实 PoC、产品二进制、影响版本、修复后运行回归；无 C-line benchmark/性能比较。两个 holdout freeze digest 仍旧于最新 live freeze。 | 不支持 precision/recall、CWE/CVE 或漏洞确认。最小补救：基于稳定最终 freeze 盲选多根因官方样本、独立双审并记分歧裁决；同 build 跑 vulnerable/fixed/safe PoC 和回归；同 scope 记录 wall/RSS 与 baseline。 |

### partial / failed 状态处理核对

- 源码实现将 parse `failed`/`not_run`、缺 AST 和严格 Runner 不支持的非完整 C++ 输入记为 `not_analyzed`；精确 source/repository/commit binding 不满足时在分析前返回聚合 `blocked`。
- `analyze_unit` 遇到字节哈希不符或 parser 抛出所捕获错误时返回 file outcome `failed`；Detector 将任一此类结果聚合为 run status `failed`。不完整但已产生候选的文件仍附带 findings，同时 aggregate `blocked`，符合保留局部候选和未完成义务的要求。
- budget timeout/state ceiling 返回 `partial`/`not_analyzed`，不会变成 safe；strict Detector 的 aggregate 会因非 complete outcome 维持 `blocked`。本轮没有同配置 Detector 结果，因此这些是代码路径结论，不是本轮样本输出。
- 聚焦回归有明确的 partial→public blocked、精确 binding 和失败关闭覆盖，但未找到直接触发 TypeSafety `AnalysisResult('failed')`、aggregate `failed` 或 timeout 分支的回归样例。因此失败/超时路径尚未达到回归证明门；补 source hash tamper、parser exception 和预算超时用例，确认 `failed`/`partial` 与 findings 保留规则。

### 独立标签与公开材料检查

两个 holdout CSV 分别有 1、20 个 sample rows，但所有 label 字段为空；Runtime Core manifest 明确 `developer_inspected_source_before_freeze=true`、`counts_as_independent_holdout=false`。因此无审查者之间的分歧或裁决数据可复核。Frontend 样本在 0.3.1 freeze 后选择，当前 C0 记录为绑定增强；其 manifest freeze digest 仍与最新 0.3.2 freeze 不同，review 仍为 0。公开 blind packets 不含 Detector 输出；本次只读搜索未发现 admin-only 文件或泄露预测的材料。该检查不能替代未来交付前的独立盲化复核。

## C1/C2、标签与产品证据

- **C1 profile（2026-10-19 更新）**：HiHope/RK3568 候选源码 commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`、tree `8781f036a3e7e04d8e0b34970d5f623b42875016`、目标 blob `68fb3b0adc4f9062889a861be51b7be90362e37a`、SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`。隔离 GN 生成和目标 ARM32 编译现已提供 compile command、clang、宏/有序 include、生成头文件、512 项依赖闭包及目标 `.o`；同命令派生的预处理/Clang AST 进一步核对出 `NDEBUG=1`、`ENABLE_ASM_ASSERT` 未定义，以及当前 Filter/creator/store 的实际 C++ 签名与类型流。profile JSON/checker 的 schema 仍报告字段未齐（退出码 2），故以带完整 build artifacts 的 `c1_product_gn_20261019/profile.json` 为该单目标构建的权威证据。它只绑定当前 a65 产品目标；不覆盖当前 0.3.9 模型使用的历史 parent/fix profiles，也未构建完整产品镜像或运行 VM。
- **C2 parser/owner**：Tree-sitter parser 仍是 `partial`；当前 a65 产品编译的 Clang AST 已补齐这一个真实 build 下的 method/overload/type resolution 和宏证据。Clang AST 不覆盖 parser partial→source identity 隔离测试、历史 replay，亦不改变公共 Runner 不准入；产品 VM/runtime 类型来源仍未证实。
- **Holdout**：ETS Frontend 包含 1 个同名 near-miss，blind label 为空且无人复核；Runtime Core packet 有 20 个 excerpt，但在 0.3.2 冻结前已由开发者查看，属于 exploratory，标签表 20 行均空。没有独立 reviewer、逐样本标签、分歧记录或裁决。开发控制不计入 holdout，也不作 precision/recall 真值；当前不能报告这些指标。
- **动态与影响**：无产品构建、可执行 PoC、攻击者边界/触发条件、敏感状态变化、可重复崩溃或 CIA 影响证据；影响版本/分支未证实。`CWE-843` 仅为模型候选标签；不能确认 CWE、CVE 或产品漏洞。
- **修复与性能**：Filter 补丁的源码差异可支持预期类型来源变化，不能证明运行效果或修复有效。没有 C 线同范围性能 baseline、wall time/RSS 或对比 Detector 测量。旧 step counters 不是性能基准；精确绑定与 fail-closed 设计是实现属性，不是比较实验结论。
- **竞赛交付决定项**：目前有证据支持的 CWE/CVE 为无；`CWE-843` 只是候选字段，不能升级为报告分类，CVE 不支持。待调查源码模块为 `arkcompiler_ets_runtime/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`，但受影响产品版本/分支尚无证据。没有可复现产品 PoC。条件性修复建议是确认 store 使用新数组真实元素类型，并确保异常创建后的对象读取只在异常检查通过后发生；随后在同一产品构建上对 vulnerable/fixed、默认 species、异类型 Number species、BigInt/Number 不兼容、getter 重入/异常和 safe/unrelated controls 做运行回归。这是复验建议，不是已确认补丁。

## 准入决策与负责人决定项

**独立结论：不准入。**保持 C 线 `admission_status=blocked`、`execution_enabled=false`，不注册为默认 Detector；当前 `src/ohscanner/detectors/admission.py` 中 C 记录仍如此，freeze 也声明 public Runner 未注册。本次没有改动产品准入元数据。候选研究材料允许继续留存，但 `candidate/partial/blocked/unknown` 不提升为 confirmed 或安全结论。

负责人后续要决定/安排的最小事项：

1. 冻结实现与 live detector 文件校验一致；重做 dependency manifest 并解决 `BUILD.gn` 的类型表达，使严格 Runner 可在不伪造输入的情况下表示真实模型依赖。
2. 获得匹配的 C1 product GN/Ninja/clang/preprocess profile 与完整编译依赖闭包；针对 exact parent/fix 和有效 safe/unrelated commits 使用同一个冻结管线复放。
3. 为重新冻结后的独立 holdout 指定未参与规则开发的审查者；留存 reviewer identity、盲标签、独立分歧和裁决记录，满足样本量/根因覆盖后再算 precision/recall。
4. 若要形成漏洞或修复结论，在隔离环境取得匹配产品二进制，证明可达入口、权限/攻击者控制、可行触发和 CIA 影响，运行 vulnerable/fixed 与安全控制，保存可重放输入、退出状态、日志及二进制/源码 hash。
5. 另做同范围、同工具链性能实验，记录所有运行的 wall time、RSS、失败和覆盖分母；创新结论需有可比较 baseline。

这些工作完成后再进行下一轮独立准入复审并由负责人决定是否开放显式选择。当前不标记 PR Ready，不合并、不发布。

## 复现命令与现有验证

从 `CyberSecurity-Innovation-Audit` 仓库根目录执行：

```powershell
$env:GIT_NO_LAZY_FETCH = '1'
python research/deliveries/cpp/verify_ark_runtime_source_bindings.py
python research/experiments/ark-runtime-history-replay-20261018/replay.py
python research/experiments/ark-runtime-exact-source-20261018/verify_dependency_manifest.py --json
python research/experiments/ark_runtime/c1_profile_20261018/profile_check.py
```

第一条只读复核两个 exact profile 的 commit/tree、60 个依赖 blob OID 和内容 SHA-256，写出可重复的 source binding manifest；本轮结果通过。第二条只复现旧 0.3.1 恢复记录中的 blocked disposition，不代表 Detector replay 成功。第三、四条检查当前依赖/profile 阻塞。当前 0.3.2 review manifest 记录实际冻结与来源，不伪称 Detector 已运行；只有修复明列阻塞并恢复一致冻结后才能生成 Detector 结果。适用的回归验证为：

另尝试在 WSL 当前环境运行 C2 `typedarray-parser-gap-20261018/reproduce.py`。它在加载 parser 前失败：WSL Python 缺少 `tree_sitter_c`；因此本轮未把 C2 已有 reproduction JSON 说成新复跑。C1 profile 检查在当前 Windows Python 环境运行并按缺失字段退出 2。

```powershell
python -m unittest research.tests.test_ark_runtime_type_safety_freeze research.tests.test_ark_runtime_type_safety_binding research.tests.test_ark_runtime_exception_guard research.tests.test_ark_runtime_exception_protection_detector -v
```

本轮最终聚焦命令记录为 **32 passed / 0 failed**；freeze implementation/model digest 与最新快照相符。旧依赖验证器退出码 2，因为其 manifest 记录旧 `detector.py`/`model.py` 哈希，并列出 33 项尚无产品 build/include/parser/toolchain 证据的义务；C1 profile checker退出码 2。聚焦测试是项目自有合同/绑定/保护测试，不构成漏洞真值、holdout 或产品验证。未运行完整产品构建、动态 PoC、跨版本测试或性能测试；这些执行缺少必要构建/预处理配置，且严格输入合同不能表达 GN 依赖。

## 重新进入重放的最低条件

1. 固定并保存同一版本的 Detector 实现、模型、依赖 manifest、parser/toolchain 和预处理配置，确保哈希自洽；修正 GN 依赖的类型合同，使真实依赖能被表达和校验。
2. 对已经验证的父/修复 profile 保留来源 manifest；对拟加入的安全/无关 profile 逐项验证 commit、tree、path、blob 和源码 SHA，并确认匹配的模型 caller/scope。
3. 提供与目标源码 commit 匹配的 GN/编译 profile、生成输入及完整依赖闭包；使用同一 parser/toolchain/scope 重跑，逐样本保留 `candidate`、`partial`、`blocked`、`not_analyzed`、`failed` 的原始语义。
4. 由独立审阅者在冻结后标注 holdout，记录身份、逐样本理由、分歧和裁决；仅在标签和分母充分时计算准确率指标。
5. 若要提出产品漏洞/CWE/CVE 或修复有效结论，另需产品入口、攻击前提、运行时影响及修复版本复验的可重复证据。

本报告与 [项目现状](../../../docs/项目现状与下一步.md) 的 C 线状态同步。当前结论不改变准入状态。


### 2026-10-19 frozen model-integrity follow-up

The research adapter is now version 0.3.9 and pins the full `RuntimeTypeModel.digest` in addition to its version string. A same-version mutation of the species assumption is rejected as `model_digest_mismatch` before semantic analysis. The 0.3.9 freeze SHA-256 is `5dd9870e02dd7c62693257aa3a277201b3422917fc837b5c037c179522fa608a`; its model SHA-256 is `83755d687bcb46621656abed4b2f0c22f4a85dbcd09d79904c3b588bda212738`. Targeted C-line freeze, binding, historical partial replay, parser/model controls, and build-source binding ran **37 tests, all passed**. The independent ETS Frontend packet was regenerated against this exact freeze: 21 samples/21 translation units, 0 labels completed. This improves model integrity only; historical analyses remain partial and the public Runner stays blocked/disabled.
