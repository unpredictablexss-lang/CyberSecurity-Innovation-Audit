# C1 研究方案：TypedArray 写入的类型来源一致性

日期：2026-10-17（Asia/Shanghai）。状态：供负责人审查；没有检测器实现、规则执行结果或漏洞确认。

## 1. 这次想交什么

首版只研究 `BuiltinsTypedArrayStubBuilder::Filter` 内的一条 Runtime 不变量：写入 TypedArray 的类型 token 应来自实际目标对象，或有独立可核实的同型保证。不能用“原数组和新数组看起来相似”替代保证。

拟议 Detector ID：`ohscanner.ark.runtime.type_safety`，需负责人确认。
拟议首条 Rule ID：`ark.runtime.typedarray-store-type-origin`；首发版本建议 `0.1.0`。

目标属于 ArkCompiler Runtime 仓库中**内建函数的快路径生成逻辑**，不是解释器侧 `BuiltinsTypedArray::Filter`。C++ 在此构建生成代码的图；`GateRef` 是图中值的引用，不能直接等同于宿主 C++ 对象地址。请负责人确认该首发范围符合 C 的职责。

不扩展到通用 OOB、UAF、整数溢出或 IPC；不实现第二套扫描器；不修改公共 Runner/Catalog/contracts/数据库/UI。不做全库类型混淆承诺。

## 2. 实际找到的历史补丁

- 仓库：`openharmony/arkcompiler_ets_runtime`，读取自官方 GitHub 组织的镜像。
- 修复提交：`a0e30483ab3e4aead67ecfb5c708489915e447f9`。
- 直接父提交：`830e85b40240677039719fcbf14f721ad3b19050`。
- [修复 diff](https://github.com/openharmony/arkcompiler_ets_runtime/commit/a0e30483ab3e4aead67ecfb5c708489915e447f9)。直接 parent 和 tree 信息已通过 GitHub commit API 核对。
- [修复前目标文件](https://github.com/openharmony/arkcompiler_ets_runtime/blob/830e85b40240677039719fcbf14f721ad3b19050/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp#L1372)：`arrayType` 来自 `thisValue`，写入 `newArray` 时仍传入 `arrayType`。
- [修复后目标文件](https://github.com/openharmony/arkcompiler_ets_runtime/blob/a0e30483ab3e4aead67ecfb5c708489915e447f9/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp#L1478)：新增从 `newArray` 取 `newArrayType`，并在写入中使用它。
- [创建函数模型依据](https://github.com/openharmony/arkcompiler_ets_runtime/blob/a0e30483ab3e4aead67ecfb5c708489915e447f9/ecmascript/compiler/new_object_stub_builder.cpp#L2272)：`NewTypedArray` 有快路径和调用 `TypedArraySpeciesCreate` 的慢路径，不能一概推断返回值与输入对象同型。
- `StoreTypedArrayElement` 已有 detached/index 检查，但仍将传入的 `jsType` 交给 Runtime 写入操作。因此 C 研究的是对象与类型来源的关系，A 的普通索引检查不能替代。

这是有来源的历史修复，不是本次发现的新漏洞。上游提交附带 AOT 测试，但本机未执行。没有证据将本补丁绑定到 `CVE-2025-27536`；不附会 CVE、严重度或影响版本。

来源边界：3 份精确提交下的文件字节均重新计算 Git blob OID 和 SHA-256，并与 API 返回 OID 一致。文件缓存在忽略的 `.tmp/c1-ark-runtime/source/`，不进入提交。**这只核验远端获取内容，不等于完成本地 Git commit/tree/blob 对象链扫描。** GitCode 交叉核验及本地 pinned snapshot 扫描仍未完成。精确记录见 `source_evidence.json`。

## 3. parser 的实际能力和最小缺口

已复用本地 `.tmp/pydeps`：tree-sitter `0.26.0`、tree-sitter-c `0.24.2`、tree-sitter-cpp `0.23.4`；没有修改依赖文件或系统环境。

实际解析结果：

- 修复前文件：`partial`，missing 节点位于 3362、3675 行；目标 Filter 为 1372–1511 行，其函数子树 `has_error=false`。
- 修复后文件：`partial`，missing 节点位于 3363、3676 行；目标 Filter 为 1372–1512 行，其函数子树 `has_error=false`。
- 模型依据 `new_object_stub_builder.cpp`：`complete`。
- 公共 AST 摘要返回 functions/calls/variables、解析状态和问题；没有完整语法树、赋值定义—使用边、对象身份、IR 标签图或支配证明。
- `facts_v1` 的 guards 当前为空，不得把它解释成已经计算了类型守卫。
- 默认 Runner 对 `required_facts` 含 `ast` 的检测器只传入 complete 文件；上述真实目标在这一接入方式下会被阻塞。这不是规则漏报，也不是组件安全。

原始结果见 `parser_probe_result.json`；`probe_parser.py` 只运行语法解析与哈希核验，不包含漏洞检测逻辑。

建议向负责人提出的最小接口/执行需求：

1. **局部语法事实**：在本线模块中使用既有 Tree-sitter grammar 获取函数限定身份、作用域、初始化/赋值、调用实参和节点源码范围；与 SourceUnit SHA 绑定。不申请修改公共摘要格式，不复制 B 的权限分析代码。
2. **IR 控制事实**：只建模已核实的 `BRANCH/Bind/Jump/LoopBegin/LoopEnd` 及当前家族所需的异常/slowPath/exit 边。生成图的路径和 C++ 源码顺序分开记录。未知标签、多义调用、未支持宏、分支汇合和预算耗尽均回退 unknown。
3. **partial 准入 RFC**：建议负责人参考已有 IPC 局部证据语义，审批本线的错误无关函数范围检查、依赖检查及 partial 输出策略。不能因为目标子树无错就把整文件升级 complete，也不能删除 required facts 或改解析状态来取得命中。批准前，生产真实复扫保持 blocked；不自行改 Runner/Catalog。

即使局部语法可用，错误区域仍可能遮蔽类型声明、宏和调用依赖，因此“错误离函数较远”不能自动证明无影响。相关候选必须保留解析完整性义务。

## 4. 首条规则的最小设计（尚未实现）

拟议 `RuntimeTypeModel` 仅包含版本绑定、精确符号和参数语义，不用名称包含关系判断：

- 类型来源：`GetObjectType(LoadHClass(object))`；记录 object 的局部定义身份和版本。
- 创建摘要：`NewObjectStubBuilder::NewTypedArray` 具有 species 创建路径；无同型证明时，不假设返回对象类型等于源对象类型。
- sink：已解析为 `BuiltinsTypedArrayStubBuilder::StoreTypedArrayElement` 的调用；目标对象为第 2 个实参，类型 token 为第 5 个实参（按 C++ 调用实参从 1 计数，不含隐式 this）。
- 首发 caller：来源已核验的 `BuiltinsTypedArrayStubBuilder::Filter`；不向其他类的同名函数扩张。

记录链为：**caller → 类型 token 来源对象 → 新目标创建 → 已建模的生成代码路径 → sink 使用的目标和类型**。

判定约定：

- 类型 token 来自目标自身同一有效定义版本，或有已建模的可靠同型证明：此条窄规则不产 candidate；不推导产品安全。
- token 来自其他对象，创建摘要允许类型不同，且在受支持路径模型中可到达 sink、没有已知矛盾约束：产 candidate，说明类型一致性义务未建立；不声称已证明实际不同型或漏洞可利用。
- 来源、调用身份、版本、作用域、路径或宏语义无法建立：输出 unknown/limitation，不能把“证明缺失”单独升级为具体类型混淆候选。
- 支持无重赋值、无逃逸的直接局部对象别名及 token 复制；重赋值失效旧事实。首版不推理任意 alias、跨函数值传播、C++ CFG/phi 或任意 IR。
- C++ 的 if 及生成图 BRANCH 两种控制必须区分；普通 AST 中“没有 if”不代表生成代码无分支。

拟议输出使用现有 DetectorFinding/message/EvidenceObligations 和 DetectorRun/file_outcomes/limitations。义务至少说明对象/类型身份、生成路径、创建摘要适用性、parse 完整性、实际构建模式、入口/触发及 CIA 影响。所有诊断保持 source-bound candidate/unassessed；CWE-843 仅作为有机制依据的候选分类。

覆盖按每个 SourceUnit 如实闭合。经批准在 partial 文件保留的有效局部候选应与 partial 文件结果绑定，不因整体 blocked 被丢弃；无法解释的函数不能作为已分析安全范围。未批准 partial 策略前不承诺本案例能够进入生产 Runner。

## 5. 12 个验收用例（均待执行）

完整机器可读计划见 `case_matrix.json`，预期不是运行结果，也不是独立漏洞真值集。

1. C01 真实修复前：在获批的能力和路径模型下预期 candidate；当前生产路径受 partial 准入阻塞。
2. C02 真实修复后：预期不触发此条规则；当前准入阻塞相同。
3. C03 全部变量改名：错误来源仍应产生 candidate。
4. C04 从目标对象取得类型：不触发此条规则。
5. C05 目标的直接局部别名：身份可证明时不误报。
6. C06 类型 token 直接复制：保留来源，不因不是内联调用而误报。
7. C07 取类型后目标被未知 helper 重赋值：unknown，旧事实失效。
8. C08 其他类的同名 API：不因名字相同套用本规则。
9. C09 不同来源在普通 C++ 分支汇合：首版 unknown。
10. C10 未建模的 IR 控制操作：unknown，不按源码顺序猜可达性。
11. C11 目标函数自身解析损坏：unknown/not_analyzed，不能 complete。
12. C12 没有可达前驱的生成标签：证明不可达才不产 candidate；无法证明则 unknown。

后续实施时还应补回归：同名局部遮蔽、同型守卫、循环预算耗尽、异常出口、宏/跨 TU 和来源 hash 拒绝。不能为了使 C01 报警而省去上述证据门。

## 6. 已执行验证与复现

解析探针（不执行上游代码）：

```powershell
python research/experiments/ark_runtime/c1_20261017/probe_parser.py
```

默认读取已有 `.tmp/pydeps` 和 `.tmp/c1-ark-runtime/source/`，先按 manifest 核验源字节，结果写入忽略目录。其他环境可用 `--deps-path`、`--source-dir`、`--output` 指定现成路径。干净 checkout 不附带第三方源代码；缺缓存时明确 BLOCKED，需要按 manifest 的精确 commit/path 重新取得文件并验证，不能替换为当前 master。

既有契约测试最终命令：

```powershell
$env:PYTHONPATH = (Resolve-Path -LiteralPath '.tmp/pydeps').Path
python -m unittest tests.test_ohscanner_contract tests.test_contract_v2_source_binding -q
```

结果：45 项，44 通过、0 assertion failures、1 error；error 为符号链接测试的 Windows WinError 1314，命令退出码 1，不计为全套通过。此前不带依赖路径时出现导入失败；仅在父进程设置 sys.path 的首次重试也使 CLI 子进程缺依赖，设置继承的 PYTHONPATH 后该失败消失。

离线安装尝试失败：环境 `PIP_NO_INDEX=1`，没有取得可安装包。随后发现并复用了仓库已有 `.tmp/pydeps`，未放宽网络或修改全局配置。没有运行新规则、完整项目回归、AOT/解释器、动态 PoC 或性能基准。

3 份源码 blob 内容验证已完成；本地 Git 来源扫描未完成；12 个新规则用例未执行。没有 Precision/Recall 或确认漏洞数量的效果结论。

## 7. 新增文件与后续交付边界

本轮新增的仅是此研究目录内的方案、用例计划、来源清单、实际解析结果和解析探针。大文件仅在忽略的 .tmp 中；现有 UI、文档 dirty work 未覆盖；没有修改生产代码、提交、推送或 PR。

方案获批后建议本线新增目录：`src/ohscanner/detectors/ark_runtime/`，测试位于 `tests/detectors/` 与对应 fixture 子目录；先实现一条规则和私有模型。Runner/Catalog/contracts 以及源码同步/验证编排由负责人维护；Catalog 注册由负责人选择性集成。

前三项风险：生成代码控制图被误当普通 C++ 顺序；对象/类型身份或 species 摘要绑定错误；partial 文件导致准入阻塞或覆盖被夸大。资源预算和不支持语义必须显式记录，不把零命中解释成安全。

若现有能力无法建立最低类型来源与路径事实，则按任务书退出机制交付覆盖缺口和所需接口，不退化为关键字扫描器。未来产品漏洞交付仍需真实入口、触发、CIA 影响、隔离 PoC、修复复验和有来源的影响版本/CWE/CVE；C1 的静态研究不替代这些目标。

## 8. 可发给组长的首次回复草稿

> 组长，我已完成 C1 初步调研。首版建议研究 TypedArray Filter 快路径中“写入目标对象与类型信息来源不一致”的问题，已找到真实历史修复及父提交，并整理了 12 个待执行用例。
>
> 目前的主要接入难点是：真实目标文件整体解析为 partial，虽然目标函数子树无语法错误，但这不足以证明周边解析问题不影响分析；现有完整 AST 准入会跳过该文件，需要您审查局部分析和 partial 证据的处理方案。
>
> 请确认以下三个事项：
>
> 1. 是否采用检测器 ID `ohscanner.ark.runtime.type_safety`。
> 2. 是否同意首版聚焦 Runtime 仓库中的 TypedArray Filter 内建函数快路径生成逻辑，检查写入目标与类型信息来源的一致性。
> 3. 是否批准按本方案进入 C2，先在本线独立目录和测试中实现局部语法、类型来源与 IR 路径模型。partial 证据准入方案另请您审查，未获批前真实复扫保持 blocked；不自行改动公共 Runner、Catalog、contracts、数据库或 UI。
>
> 本次历史案例仅用于规则回归，不作为新漏洞成果。后续候选将按赛题补齐真实入口、触发条件、具体安全影响、隔离 PoC、影响版本和修复重验；不会仅凭类型失配或普通崩溃认定安全漏洞。目前未写检测器算法、未改公共接口，详细来源、用例和限制见所附 C1 方案。

远端开放 PR 搜索曾返回 #8–#12；未看到专门 C 线 PR。该清单仅是检索观察，不证明所有远端分支内容已审查，实施前还需以当时最新 main 和相关 PR 固定 SHA 重新核对。
