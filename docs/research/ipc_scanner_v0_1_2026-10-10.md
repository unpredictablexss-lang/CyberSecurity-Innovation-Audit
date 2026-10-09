# IPC 扫描器 v0.1：实现、实验与交接（2026-10-10）

代码位于 WSL Ubuntu-22.04 的 `~/openharmony-audit/CyberSecurity-Innovation-Audit-b`，分支 `feat/oh-a-interface-detectors`。开始前已 fetch 并将 B 分支快进到队长核心提交 `3b437e4`。没有推送、合并 main 或修改队长工作区。重型工具、目标源码、数据库和原始日志位于 `~/openharmony-audit/ipc-research`；E 盘保留说明文档与表格副本。

## 结果与证据边界

- 实现独立的 `IpcInterfaceDetector`，检测器 ID `ohscanner.interface.ipc`，通过既有 Registry / fixed-Git execution 接口运行；没有另起竞争 CLI，也没有修改公共 schema、catalog 或队长 runner。
- 用户历史清单整理为 39 条官方公告核对记录，初步分为 25 条 IPC 核心候选、14 条邻接候选。公告 ID 命中不等于已确认 IPC 根因。
- 12 个独立根因建立 S2 修复前后源码对；另有 1 个混合修复补丁保持 S1 待定。98 个源码文件均验证 SHA-256、Git blob ID 和固定提交。两个 CVE 共用 PR470 只计一个根因；同一缺陷不同分支补丁不重复计数。
- 12 组设计集均出现“漏洞版本对应根因候选 > 0，修复版本对应根因候选 = 0”。其中仅 5 组两侧文件公共解析均完整，另外 7 组 retained candidates + blocked/unknown。不能把它写成 12/12 真实漏洞检出率；不能把 fixed 根因候选为零写成整个文件安全或全部告警为零。
- 29 个自编设计场景全部符合预期。源码冻结后的 13 个生成变体有 12 个符合预期，1 个安全对照误报（直接按请求 UID 授权）。它们与设计集同源，不能作为独立历史留出集。
- 全项目 `python -m unittest discover -s tests`：218 项通过。真实 OpenHarmony 产品编译、设备运行、攻击可达性和安全影响验证未执行，S3 数量为 0。

## 历史漏洞逐项结果

表中数字是“同一目标符号内的预期主规则候选数”，不是漏洞个数、命中函数覆盖率或全部告警。partial 时零候选仍然 unknown。

| 根因实例 | 子类 | 漏洞版候选 | 修复版候选 | 两侧执行覆盖 | 官方补丁 |
|---|---|---:|---:|---|---|
| background-470 | AUTH-03 / ipc.auth.object-owner | 2 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/resourceschedule_background_task_mgr/pulls/470) |
| cve-2022-38064 | AUTH-02 / ipc.auth.missing | 1 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/window_window_manager/pulls/1480) |
| cve-2022-38081 | AUTH-02 / ipc.auth.missing | 3 | 0 | complete | [PR](https://gitee.com/openharmony/security_access_token/pulls/397) |
| cve-2022-38700 | AUTH-02 / ipc.auth.missing | 1 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/multimedia_camera_framework/pulls/247) |
| cve-2023-0036 | AUTH-01 / ipc.relay.descriptor-boundary | 1 | 0 | complete | [PR](https://gitee.com/openharmony/inputmethod_imf/pulls/228) |
| cve-2024-0285 | DATA-01 / ipc.parcel.position-underflow | 2 | 0 | complete | [PR](https://gitee.com/openharmony/communication_ipc/pulls/907) |
| cve-2025-26691 | AUTH-02 / ipc.auth.missing | 7 | 0 | complete | [PR](https://gitee.com/openharmony/telephony_call_manager/pulls/2071) |
| cve-2025-26693 | AUTH-03 / ipc.auth.caller-class | 1 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/security_access_token/pulls/2962) |
| cve-2025-27563 | AUTH-03 / ipc.auth.caller-class | 3 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/security_access_token/pulls/3203) |
| sa-2022-0602 | AUTH-01 / ipc.relay.descriptor-boundary | 8 | 0 | complete | [PR](https://gitee.com/openharmony/notification_common_event_service/pulls/245) |
| sa-2022-0603 | AUTH-01 / ipc.relay.descriptor-boundary | 3 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/update_updateservice/pulls/115) |
| sa-2022-0604 | AUTH-01 / ipc.relay.descriptor-boundary | 5 | 0 | partial → unknown | [PR](https://gitee.com/openharmony/multimedia_player_framework/pulls/567) |

CVE-2025-27563 补丁涉及五个 handler，目前主规则定位其中三个，不应宣称五个全覆盖。CVE-2025-26474 的 PR1870 同时有 FD 清理、有效性判断和测试改动，尚未把信息泄露公告与唯一根因绑定，因此不参与正样本计分。

## 工具对比协议与结果

实际使用 Semgrep OSS native core 1.180.0（非付费 Pro），Joern 4.0.652 + Temurin JDK21，CodeQL CLI 2.27.2 + cpp-all12.2.0，以及系统 Clang Static Analyzer。前三者使用本项目自编公开规则/查询，并非厂商默认安全能力排行榜；没有复制第三方实现。Clang 仅在内存边界类上相关。

Semgrep 对每个文件运行，105 个进程正常结束，但 20 个文件报告解析错误。Joern 对 26 个历史 revision 建图/查询，CodeQL 对同样 26 个 revision 以 build-mode=none 建库/查询。Joern AST 成功与 CodeQL no-build 成功不等于完整 OpenHarmony 宏、头文件、类型和可达性覆盖，历史负结果统一保守标 unknown。Clang 29 个合成 TU 编译分析成功，8 个真实 TU 因缺失工程头文件失败；后者不能当漏报。

合成场景按正确子类核对；safe 场景出现该子类候选计 false_positive，positive 缺失计 miss。NA 表示本次查询配置不建模该子类（例如所有者 UID、调用者类别，或传输位置下溢），并不表示整个工具无法实现。设计样例上的方法比较有开发偏差，不是独立泛化检验。

| 当前配置 | 符合预期 | 漏掉正例 | 安全对照误报 | NA | unknown |
|---|---:|---:|---:|---:|---:|
| OHScanner | 29 | 0 | 0 | 0 | 0 |
| Semgrep | 12 | 5 | 5 | 7 | 0 |
| Joern | 8 | 4 | 3 | 14 | 0 |
| CodeQL | 10 | 4 | 4 | 11 | 0 |
| Clang | 1 | 2 | 0 | 26 | 0 |

按根目录 AGENTS.md 的要求，生成实验矩阵与原始工件不提交，仅保留本地/E盘副本；脚本可重新生成。完整逐漏洞、逐版本、逐工具记录在 `research/experiments/interface/ipc/results/historical.{json,csv}`；逐子类场景在 `synthetic.{json,csv}`。候选数与覆盖状态分别存列，unknown 中可能有候选，NA 的候选数为空而非 0。表格数据直接取自上述 JSON，所有中间原生日志保留外部；`evidence_manifest.json` 固定原始运行清单 SHA-256。执行耗时存在运行清单中，但未统一预处理成本/峰值 RSS，不作性能优劣结论。

最明显的有效点：Semgrep 与 Joern 的 descriptor 规则可定位早期 SA/输入法未校验入口，适合候选定位。最明显的失败点：存在权限调用并不能保证其返回值生效；客户端校验不能替代服务端校验；直接调用存在性看不到本地包装函数和调用者类别。CodeQL Parcel 污点查询确实追踪到 ReadInt32 → copy length，也报告了已经有范围判断的 fixed 样例，说明需要补充路径与数值约束。

合成样例最初共用 Stub 类，引发 CodeQL 多 TU 定义合并；最终给每个样例添加唯一编译类名并重新建库，最终使用 `synthetic-v2` 结果。早期错误运行保留，未纳入最终矩阵。Semgrep 规则也补齐了带/不带花括号和 descriptor 别名对照后重新运行。首次 Joern 使用 CodeQL 精简 JRE 缺少模块，后换完整 JDK21；这些失败不算检测漏报。

## 算法选择与六类检测方法

建议继续以静态程序分析为主，采用模型驱动的有界路径解释，而非先训练分类器。目前正样本少、同补丁重复多、独立标签不足，机器学习很容易学到函数名/版本痕迹。v0.1 的状态显式存调用者身份、授权事实、descriptor、对象归属、长度上下界和敏感操作路径；if/else 分裂、return 截断、switch 独立 case 入口与 fallthrough、循环保守零/一次展开。本地同文件同类调用摘要深度默认 2，路径预算 96；溢出通过交集保留仅在所有合并路径成立的保护事实，不丢弃未授权路径。它不是编译器 CFG、完整 SMT 或任意指针/虚调用分析。

| 子类 | 来源与目标 | 必须成立的保护 | 当前告警逻辑 | 主要边界 |
|---|---|---|---|---|
| AUTH-01 SA/descriptor 信任边界 | OnRemoteRequest 请求 Parcel → 分发/回调 | 同一请求 Parcel 的 token 与本服务 descriptor 比较，拒绝不匹配路径 | 仅 ReadInterfaceToken、校验 reply Parcel、无拒绝分支不能建立保护 | descriptor 只隔离接口，不等于访问权限；完整 SA 代理跨服务转发链尚未恢复 |
| AUTH-02 缺失服务端鉴权 | 审核入口/本地 handler → 敏感 API/设备对象创建 | 原始调用者的权限/受信类别保护到达操作的路径 | 任一结构化路径缺保护即候选；仅客户端 NAPI 校验不算 | API 名称和 required permission 必须版本化审查；上游 dispatcher 保护可能需人工核对 |
| AUTH-03 身份/归属/调用者类别错误 | caller token/UID、self、Parcel 派生 ID、对象 owner | UID/token 域匹配；original caller；资源 owner 或特定 caller class | self/reset 后身份、请求自报身份、缺 owner 绑定、缺 native/system 条件分别出规则 | 无全程序别名；直接请求 UID 安全绑定存在已知误报；身份问题必须关联敏感效果 |
| AUTH-04 鉴权路径覆盖 | 权限结果 → 分支 → 敏感操作 | 拒绝分支真正退出；每个可达敏感 case 都受保护 | 结果忽略、检查过晚、仅一分支保护、case 掉落分别保留路径证据 | 循环/复杂条件保守近似，不能把语法路径当实际可达攻击路径 |
| DATA-01 Parcel 长度/位置 | 读取长度 → memcpy/ReadBuffer；数据总长减 PAD/idLen → RewindRead | 长度非负且不超过同一目标容量；减法前足够剩余量 | 无关上界不消警；检测已审核传输入口的减法位置下溢 | 非通用整数分析；乘法、整数类型溢出、复杂容器生命周期未覆盖 |
| CAP-01 能力导出 | WriteRemoteObject / WriteFileDescriptor | 原始调用者授权覆盖导出路径 | 无授权导出非空 capability 为候选，空对象不报 | 需核对是否公开合法 API、对象权限语义、FD 所有权；不等于已证实能力泄漏 |

策略 `IpcPolicy.expected_permissions` 可为特定敏感调用绑定所需权限。没有绑定时，只能识别“存在被模型认可的授权”，不能证明检查了正确权限。所有规则输出 candidate、syntax evidence、unassessed confidence，并附 entry_reachability / callee_and_policy / security_impact 三项义务。

为稳定处理鸿蒙日志宏，私有分析只对白名单 PRI 字符串格式宏和 unresolved member pointer dispatch 做等字节等换行规范化。后者保持未知目标，不假定它调用某个 handler。公共 SourceUnit 仍保留原始 parse_status，任何 partial 都使执行状态 blocked；这避免规范化把不完整扫描包装成成功。

## 对成功机制的源码分析与独立实现

- Semgrep `v1.180.0/src/tainting/Taint.ml`：污点来源/汇以及调用轨迹分开表示；源码注释明确指出该分析 path-insensitive，并讨论 compare identity 不当导致重复集合膨胀。借鉴的是显式来源域、稳定根因键和预算控制的思路；本项目 Semgrep 基线实际运行结构规则，不能说实验验证了其 taint 引擎优劣。另一个计划读取的 Match_patterns.ml 返回 404，未作为证据。
- Joern `v4.0.652/.../AstForStatementsCreator.scala` 与 `AstForExpressionsCreator.scala`：前端建立控制结构和表达式节点，随后查询必须补充业务语义。本次“权限调用存在性”查询虽能找到敏感调用，却无法证明 guard dominance。自研部分用结构化分支状态替代存在性消警，并加入 original caller、owner、caller class 模型。没有从 Scala 源码复制实现。
- CodeQL cpp-all12.2.0 的 Global TaintTracking 配置通过源/汇和可选 barrier 构造污点路径；本项目 ParcelFlow.ql 在合成样例成功保留数据路径，但未定义范围 barrier，fixed 仍告警。自研针对少量模式维护来源、非负事实、目标容量关联和减法前置条件；复杂算术留待后续 SMT 扩展，不宣称替代 CodeQL 全局数据流。
- 官方 `telephony_permission.cpp`、`access_token.h`、`accesstoken_kit.cpp` 的固定版本文件验证 CheckPermission 使用 GetCallingTokenID、VerifyAccessToken 返回 granted/denied 的模型依据。版本与部分历史分支不同，属于显式模型假设，不能当每个历史版本行为证明。`model_sources.json` 记录 URL/提交/内容哈希。

第三方只用于离线对照与阅读，二进制、源码、目标数据库不入仓库。Semgrep 该文件 LGPL2.1 + linking exception、Joern Apache2.0，原始 license 与内容 SHA-256 存外部 `artifacts/tool-source/manifest.json`；使用版本 tag + 内容哈希，不把 tag 伪装成固定 commit。CodeQL 的发行/使用条款应在后续发布含工具环境时重新核对；本仓库仅含原创查询。

## 消融、误报与下一步检出率目标

消融只在 29 个开发样例上进行，改变局部摘要、身份来源或敏感 API catalog 的一项配置，其余保持一致；不是泛化证明：

- full：29/29 符合预期。
- no-local-call-summary：27/29 符合预期。
- no-caller-provenance：20/29 符合预期。
- no-sensitive-api-catalog：19/29 符合预期。

要把“历史多数漏洞高检出”变成可验收目标，首先从 39 条清单剩余记录继续复核，按独立 root cause 去重并留出尚未开发接触的组件/时间段，锁定规则后才运行。AUTH-04/CAP-01 目前只有合成控制，没有足够独立 S2 历史正例，不能报历史召回率。为每个根因标注入口、敏感点、保护条件、编译分支、修复点，报告完整扫描覆盖率、根因级 recall、safe-fixed false-positive rate 和 unknown 比例，分别按子类统计。

建议顺序：①修复 parser/宏与构建上下文覆盖，降低 unknown；②构造共享 IR 后接入跨文件调用与 dispatcher edge，保留不确定边；③用 caller/owner/permission 的关系域替代名字启发式，解决直接 UID 安全绑定误报；④对最常见数值/逻辑模式接入 SMT 路径可满足性和位宽约束；⑤新增每个 missed subtype 的真实 patch pair 后先做盲测，再建模型。先不承诺某个百分比，不把当前 design 结果写成真实 100% 召回。

## 复现与集成

在 B 工作区中安装项目依赖并使用 `.venv`。工具已在本机外部 workspace 安装；重建工具环境时版本、规则哈希见 manifest，第三方下载不是 runtime 必需步骤。当前 Python3.10 / tree-sitter0.26.0 / tree-sitter-cpp0.23.4 / tree-sitter-c0.24.2；版本以 environment.json 的实际锁定记录为准。

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit-b
.venv/bin/python -m unittest discover -s tests
.venv/bin/python research/experiments/interface/ipc/validate_corpus.py --workspace ~/openharmony-audit/ipc-research
PYTHONPATH=. .venv/bin/python research/experiments/interface/ipc/run_own.py --workspace ~/openharmony-audit/ipc-research
PYTHONPATH=. .venv/bin/python research/experiments/interface/ipc/run_variants.py --workspace ~/openharmony-audit/ipc-research
.venv/bin/python research/experiments/interface/ipc/run_semgrep.py --workspace ~/openharmony-audit/ipc-research
PYTHONPATH=. .venv/bin/python research/experiments/interface/ipc/summarize.py --workspace ~/openharmony-audit/ipc-research
```

`acquire_sources.py` 按 metadata 下载被动源码并验证哈希，`--git-objects` 可向已 clone/fetch 的组件仓库填入校验 blob，供 existing Git source reader 使用。网络不可用时可先由 Windows curl 下载到 WSL 后执行 validator。`replay_baselines.py --tool joern|codeql|clang` 默认只打印保存的 argv，`--execute` 才执行；CodeQL 既有数据库不能覆盖，先改为新输出目录并保留原始记录。最终合成对照必须使用独立类名版本（synthetic-v2），旧结果仅供审计。`run_synthetic_baselines.py --workspace ... --prefix synthetic-replay` 可重新建库，拒绝覆盖既有输出。`run_variants.py` 重算冻结变体与消融。

核心接入示例（需要队长后续 review 注册，不修改现有公共文件）：

```python
from src.ohscanner.runner import DetectorRegistry
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.detectors.interface import IpcInterfaceDetector
registry = DetectorRegistry()
registry.register(IpcInterfaceDetector())
report = run_reviewed_detectors(repo_path, component_name, full_commit_sha, tuple(cpp_scope), registry)
```

不需要目标代码执行、不下载攻击载荷。报告接口返回 JSON，证据义务与 blocked coverage 延续队长现有协议。扫描自己指定的其他组件时，应先审核 API catalog、dispatcher、upstream guards 和 expected_permissions；未入模型 API 不表示安全。

## 执行记录与未完成事项

已完成：同步基线、阅读队长/用户文档、公告清单结构化、12+1 源码对哈希验证、工具安装、适用配置实验、失败运行保留、成功/失败机制分析、六类第一版实现、生成对照/消融、218 项回归、逐例机器可读矩阵、MD 与 Excel。

仍未证明：独立真实历史多数覆盖、全部 39 条都是 IPC、完整 OpenHarmony 工程可达性、S3 runtime、安全权限准确性、全程序别名/整数域。批量汇总中遇到原生 Tree-sitter 多树遍历崩溃，汇总对齐改用只读词法符号/括号定位；检测代码冻结且回归通过；另对检测器本身执行 94 个真实 .cpp 文件 × 3 轮，共 282 次解析/分析并显式 GC，全部完成（`stress_parser.py`）。这不排除其他原生绑定生命周期问题，后续仍需进程隔离评估。词法对齐只用于基线候选归属，不参与检测或构造漏洞标签。
