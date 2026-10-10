# IPC 扫描器 v0.1 开发全过程、命令与产物索引

整理日期：2026-10-10。对应实现提交：`9495b09`，分支 `feat/oh-a-interface-detectors`。

这份文档根据现存脚本、Git reflog、源码版本、运行清单、原生日志、测试日志和交付文件逐项回查后整理。它是**事后补全的过程说明**，不是当时每条终端操作的逐字录像。已保存的实际工具 argv 可以在运行清单中找到；本文把等价的复现命令明确标为 R，避免把后来补写的自动化脚本说成最初就已使用的命令。

先说明计数：**29 是测试场景数，不是 29 个真实漏洞**。其中 16 个为漏洞模式正例，13 个为修复版/安全对照。历史实验另有 12 个 S2 根因修复对；没有运行验证的新漏洞或 S3 样本。

## 1. 文件位置与记录口径

| 缩写 | 实际位置 | 内容 |
|---|---|---|
| B | `/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` | B 分支代码、测试输入、复现脚本、已审阅文档 |
| W | `/home/audit/openharmony-audit/ipc-research` | 工具、下载包、目标仓库、源码对 |
| A | `/home/audit/openharmony-audit/ipc-research/artifacts` | 原始报告、运行清单、失败日志、CPG/CodeQL 数据库 |
| E | `E:\读研\网络安全创新大赛\实验记录\IPC_v0.1_2026-10-10` | 用户阅读的 MD、Excel、JSON/CSV 和交接副本 |

以下 Bash 命令在 WSL Ubuntu-22.04 / audit 用户下运行。先设置目录变量：

```bash
cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b
IPC_WS=/home/audit/openharmony-audit/ipc-research
IPC_ARTIFACTS="$IPC_WS/artifacts"
IPC_EXPERIMENT=research/experiments/interface/ipc
```

命令标签：

- **A（实际命令）**：原始 argv 已保存在本地 manifest，或此前执行的命令与日志可对应。
- **R（复现命令）**：根据最终脚本/目录整理，用于重跑同一方法；不声称与当时临时脚本逐字相同。
- 重跑 `run_own.py`、`run_variants.py`、`run_semgrep.py`、`summarize.py` 会覆盖其默认输出。先复制旧工件到新的实验目录，或修改输出位置，保留旧 SHA。CodeQL 建库和 synthetic replay 需使用新的输出路径。
- 生成结果不提交 Git，这是根目录 AGENTS.md 的要求。仓库提交源码/规则、固定样本元数据、测试输入、方法卡和叙述报告；原始实验/表格在本地。

## 2. 第一步：同步项目，确认队长已实现什么

**输入**：GitHub 项目、B 分支、队长 core 分支、已有 B 工作树。

**做的事情**：先检查工作树与远端，读取队长的架构、状态、接口契约和分工文档；通过 Windows Git 对 WSL UNC 工作树 fetch，随后将 B 分支快进到队长已提交 core。WSL 内私有仓库 HTTPS 认证和 SSH 曾不顺畅，因此采用 Windows 已授权 Git，没有把代码改放 E 盘。

现存 reflog 可核查：

```text
dcd9629  原始 B 基底
3b437e4  merge origin/feat/ohscanner-core: Fast-forward
9495b09  commit: feat(interface): add first-party IPC candidate detector and reproducible research
```

检查命令（R，只读，不重新推进分支）：

```bash
git status --short --branch
git reflog --format='%h %gs'
git show --stat 9495b09
git show 3b437e4:PROGRAM_STATUS.md
```

需要重新获取远端时的等价 Windows PowerShell 命令（R；并非一份已保存的完整 Git 网络会话）：

```powershell
git -C '\wsl.localhost\Ubuntu-22.04\home\audit\openharmony-audit\CyberSecurity-Innovation-Audit-b' fetch --all --prune
```

**阅读的项目文件**：B 下 `AGENTS.md`、`docs/architecture_2026.md`、`PROGRAM_STATUS.md`、`docs/strategy/ohscanner_three_track_master_plan.md`、`docs/strategy/team_parallel_multi_scanner_plan.md`、`docs/contracts/ohscanner_detector_contract_v1.md` 及队友开发/接入指南。

**结论**：复用队长的 SourceUnit、ScanContext、Registry、fixed-Git execution 和结果桥接；B 不建立竞争 CLI，不修改队长工作树，不擅自修改公共 schema/catalog。实现后只做本地提交，没有 push/PR/main merge。

**输出/证据**：Git reflog、本地提交 `9495b09`、`research/methods/interface/IMPLEMENTATION_LOG.md`。

## 3. 第二步：读取用户思路，确定六类范围

**输入**：

1. `E:\读研\网络安全创新大赛\OHScanner队友BIPC接口安全研究与自研检测器总体思路.md`。
2. `E:\读研\网络安全创新大赛\OpenHarmony_IPC近五年漏洞集.md`。

两份文档的研究副本保存在 W 根目录同名文件中。

**分析过程**：将“权限、身份、数据、能力”等大方向落实为可检验的来源、保护条件、敏感操作和修复对照；将公告线索与已复核源码分开；先选择能得到固定补丁与源码的样本开发模型。

| 子类 | 研究对象 | 实际 v0.1 范围 |
|---|---|---|
| AUTH-01 | descriptor/接口信任边界、SA relay 相关模式 | 请求 Parcel 的 descriptor 校验与拒绝路径；还不是完整跨 SA 转发链分析 |
| AUTH-02 | 服务端缺失鉴权 | 认可入口到建模敏感操作的路径上缺原始 caller 授权 |
| AUTH-03 | 身份、资源归属、caller 类别错误 | self/request/original caller、UID/token 域、owner UID、native/system caller 限制 |
| AUTH-04 | 鉴权路径遗漏 | 忽略返回值、检查过晚、分支只保护一侧、switch case/fallthrough |
| DATA-01 | Parcel 长度/位置边界 | 长度到复制目标容量的关系；已审核传输位置减法的前置条件 |
| CAP-01 | 能力导出 | RemoteObject/FD 的非空导出是否受 caller 授权保护 |

**输出**：`research/methods/interface/IPC_METHOD_CARD.md` 与原结果报告中“算法选择与六类检测方法”。

**结论**：六类都能输出候选；AUTH-04/CAP-01 的当前证据主要是合成控制，不能宣称都有充分历史正例验证。未知敏感 API、不在模型中的入口与复杂调用链仍可能漏掉。

## 4. 第三步：将历史清单变成可核查的公告索引

**输入**：用户历史清单与 OpenHarmony 官方 security 仓库。

**做法**：读取清单表格，提取公告/CVE、暂定子类、组件和补丁引用；从官方 security 固定提交读取公告 Git blob，匹配 ID 并保存公告内容哈希。记录共享 PR，避免多个别名重复计根因。

复现命令（R，使用固定官方仓库；输出到临时审查文件，避免覆盖已审阅数据）：

```bash
git -C /home/audit/openharmony-audit/_research_sync/openharmony-security rev-parse HEAD
.venv/bin/python "$IPC_EXPERIMENT/import_inventory.py" \
  --inventory "$IPC_WS/OpenHarmony_IPC近五年漏洞集.md" \
  --security-repo /home/audit/openharmony-audit/_research_sync/openharmony-security \
  --output "$IPC_ARTIFACTS/advisories-reimport.jsonl"
```

对应原索引的官方提交为 `ceaf1b4fbe38e46cd18bfcffd7353516bdc34227`；如果该研究仓库 HEAD 已变化，先用隔离工作树指向这个提交再重导入，不能把不同公告快照混成同一次实验。

**输出**：B 下 `research/corpus/interface/ipc/advisories.jsonl`，39 条；每条包含官方固定 URL、公告 SHA-256、匹配行、补丁引用和 provisional 分类。

**结论**：39 条公告 ID 均可匹配固定官方源；25 条暂定 IPC core、14 条邻接。**公告匹配只到 S1，不证明每一条都是 IPC，也不证明漏洞根因已经复现。**

## 5. 第四步：阅读补丁，建立真实修复前后源码对

**做法**：按官方 PR 找固定合并提交，比较修复前后补丁，审阅入口、caller/参数来源、敏感点与新增保护。不是看到 parent SHA 就自动把前版标漏洞；标签来自本次静态补丁审阅，未做独立双人标注或产品运行验证。

元数据分别保存：repository、full commit、revision、路径、符号、预期主规则、根因实例 ID、PR URL、review note、Git blob ID、SHA-256、证据等级与 split。

**输出**：

- B：`research/corpus/interface/ipc/verified_pairs.jsonl`，12 个 S2 独立根因，全部 design。
- B：`research/corpus/interface/ipc/pending_pairs.jsonl`，1 个 S1 混合补丁。
- W：`pairs/<sample_id>/vulnerable/<source_path>` 与 `fixed/<source_path>`。
- W：`repos/<component>`，供 fixed-Git reader 使用的目标仓库。
- A：`pair-downloads.json`，保留其中一阶段 78 个下载任务记录；它不是最终 98 个源码文件的全量收集账本。

去重/排除的重要决定：

- CVE-2024-21816 与 CVE-2024-39612 共用 background PR470，算一个根因。
- 同一缺陷的多分支补丁不算多个漏洞，如 IPC PR907/908。
- CVE-2025-26474 / PR1870 同时出现 FD 清理、有效性判断和测试等改动，未唯一绑定公告根因，保持 S1，不参与正例计分。

补齐/验证命令（R；源码下载不会运行目标代码）：

```bash
.venv/bin/python "$IPC_EXPERIMENT/acquire_sources.py" --workspace "$IPC_WS"
.venv/bin/python "$IPC_EXPERIMENT/validate_corpus.py" --workspace "$IPC_WS"
```

`acquire_sources.py` 是收尾整理的复现入口。初始抓取曾用 Windows curl/临时脚本解决 WSL 网络问题，不把它说成全部初始下载的原始命令。

Git source reader 还需要目标 clone 已有精确提交和 tree；`acquire_sources.py --git-objects` 只往已有仓库写入已核验 blob，不能替代 clone/fetch commit/tree。

**已核实结果**：13 个根因记录（12+1）、98 个文件 SHA-256 与 Git blob 匹配，冻结检测源码哈希匹配。运行验证 `runtime_validation=not_run`，`validated_vulnerability=0`，S3=0。

## 6. 第五步：安装工具，保存失败而不是丢掉

所有重型工具在 W，未复制到 B 提交中。

| 工具 | 最终实际配置 | 安装位置/证据 |
|---|---|---|
| Semgrep | OSS native core 1.180.0，未用 Pro | W/tools/semgrep-native；A/semgrep-install.log、semgrep-pypi-install.log、windows-pip-deps.log |
| Joern | 4.0.652，完整 Temurin JDK21 | W/tools/joern-cli、W/tools/jdk-21.0.12.1+1；A/joern-cli-linux-x86_64.zip.windows-download.log、jdk-download.log |
| CodeQL | CLI2.27.2，cpp-all12.2.0，build-mode=none | W/tools/codeql；A/codeql-linux64.zip.windows-download.log、codeql-pack.log、codeql-pack-install.log |
| Clang | Ubuntu14.0.0，core/unix/alpha.security.ArrayBoundV2 | 系统 clang++；A/clang-runs.json |

下载包保存在 W/downloads：`codeql-linux64.zip`、`joern-cli-linux-x86_64.zip`、`jdk21.tar.gz`、wheels 目录。完整工具安装命令没有统一保存成一个 bootstrap 脚本；本次不虚构逐字的安装 shell history。版本检查与运行命令可以复现：

```bash
"$IPC_WS/tools/codeql/codeql" version
.venv/bin/python -m pip show tree-sitter tree-sitter-c tree-sitter-cpp
clang++ --version
export JAVA_HOME="$IPC_WS/tools/jdk-21.0.12.1+1"
export PATH="$JAVA_HOME/bin:$PATH"
java -version
```

**遇到的问题与调整**：

1. Semgrep Python CLI 依赖安装出现 Windows 依赖标记/PyPI 网络超时；最终直接使用 wheel 内真实 OSS native core，记录配置差异。
2. native core 不能按最初方式直接处理目录，最终改成逐文件任务，使用 `-json_nodots` 得到可解析 JSON；失败目录尝试仍保留。
3. Joern 初次使用 CodeQL 附带精简 JRE，缺少 `com.sun.net.httpserver.HttpHandler`；换完整 JDK21，同时设置 JAVA_HOME 和 PATH。失败见 A/joern-synthetic.log。
4. CodeQL pack install/download 成功后使用 lock；没有把 no-build 提取成功当成 OpenHarmony 工程完整编译成功。

**输出**：B 的 `research/experiments/interface/ipc/environment.json`、CodeQL pack lock；A 的下载/安装/失败日志。

**结论**：实际扫描配置可运行，失败环境不记漏报。没有“一键重建所有工具环境”的完整保证，也未验证全部安装包的签名/发行校验和。

## 7. 第六步：写适用基线，跑历史源码与控制场景

这些是**本项目原创的实验规则/查询**，不是厂商默认能力排行榜。

| 配置文件 | 检查逻辑 | 没有声称实现的能力 |
|---|---|---|
| B/research/experiments/interface/ipc/semgrep-rules.json | descriptor、权限调用/忽略结果、复制长度、导出等结构候选 | 全局鉴权证明、完整 caller/owner 关系 |
| B/research/experiments/interface/ipc/joern-ipc.sc | AST 方法与调用存在性、部分身份/导出模式 | guard dominance 和完整范围约束 |
| B/research/experiments/interface/ipc/codeql/IpcBoundary.ql | 入口、直接调用与结构边界候选 | 业务授权路径全证明 |
| B/research/experiments/interface/ipc/codeql/ParcelFlow.ql | 实际 Global TaintTracking：Parcel 标量→copy length | 有效长度 sanitizer/barrier 与整数位宽证明 |

Semgrep 单文件实际 argv 模板（A，逐任务在 `semgrep-file-runs.json`）：

```bash
"$IPC_WS/tools/semgrep-native/semgrep-1.180.0.data/purelib/semgrep/bin/semgrep-core" \
  -rules "$PWD/$IPC_EXPERIMENT/semgrep-rules.json" -lang cpp -json_nodots -j 1 \
  "$PWD/tests/fixtures/ipc/auth_positive.cpp"
```

批量入口（R）：

```bash
.venv/bin/python "$IPC_EXPERIMENT/run_semgrep.py" --workspace "$IPC_WS"
```

Joern 实际命令示例（A，sample/revision 固定，完整 26 任务见 `joern-runs.json`）：

```bash
"$IPC_WS/tools/joern-cli/joern-parse" "$IPC_WS/pairs/background-470/vulnerable" \
  --language C --output "$IPC_ARTIFACTS/background-470-vulnerable.cpg" --frontend-args --log-problems
"$IPC_WS/tools/joern-cli/joern" --script "$PWD/$IPC_EXPERIMENT/joern-ipc.sc" \
  --param "cpgFile=$IPC_ARTIFACTS/background-470-vulnerable.cpg" \
  --param "outFile=$IPC_ARTIFACTS/joern-background-470-vulnerable.json"
```

CodeQL 实际命令示例（A，完整 26 任务见 `codeql-runs.json`；原路径已有数据库，不能直接重建覆盖）：

```bash
"$IPC_WS/tools/codeql/codeql" database create "$IPC_ARTIFACTS/codeql-db-background-470-vulnerable" \
  --language=cpp --build-mode=none --source-root="$IPC_WS/pairs/background-470/vulnerable" --threads=1
"$IPC_WS/tools/codeql/codeql" database analyze "$IPC_ARTIFACTS/codeql-db-background-470-vulnerable" \
  "$PWD/$IPC_EXPERIMENT/codeql" --format=sarif-latest \
  --output="$IPC_ARTIFACTS/codeql-background-470-vulnerable.sarif" --threads=1 --ram=2048
```

Clang 实际命令模板（A，见 `clang-runs.json`）：

```bash
clang++ --analyze -std=c++17 -Xanalyzer \
  -analyzer-checker=core,unix,alpha.security.ArrayBoundV2 \
  tests/fixtures/ipc/parcel_positive.cpp -o /dev/null
```

**输出与规模**：

- Semgrep：A/semgrep-file-runs.json 和 semgrep-files/*.{json,stderr.log}，105 个任务，105 次 exit0，最终 39 个规则匹配、20 项解析错误；匹配数不是漏洞数。
- Joern：26 个历史 revision 建图/查询；A/joern-runs.json、joern-parse-*.log、joern-query-*.log、joern-*.json、*.cpg。
- CodeQL：26 个历史 revision 建库/查询；A/codeql-runs.json、codeql-create-*.log、codeql-query-*.log、codeql-*.sarif、codeql-db-*。
- Clang：37 个任务；29 个合成 TU 成功，8 个真实 TU 缺少工程头文件而失败。A/clang-runs.json、clang-*.log。

**结论**：存在性规则适合快速定位 descriptor/敏感调用；“出现权限函数”并不说明权限检查生效。Parcel 污点路径能找到输入到复制长度，却仍报告有界 fixed 场景，需要补充范围与路径模型。解析、提取、缺头文件问题必须反映为 unknown，不能变成 miss 或安全结论。

## 8. 第七步：复核工具源码与官方 API，决定自研机制

**输入**：成功/失败对照结果，以及固定版本的工具源码和官方 API 源。

**阅读证据**：

- A/tool-source/semgrep-Taint.ml：显式来源、污点轨迹、集合身份与 path-insensitive 的限制。
- A/tool-source/joernio-AstForStatementsCreator.scala、AstForExpressionsCreator.scala：前端控制结构/表达式构图。
- `/home/audit/.codeql/packages/codeql/cpp-all/12.2.0/semmle/code/cpp/dataflow/new/TaintTracking.qll` 等：全局污点配置的源/汇与 flow module。
- A/model-sources 下官方 telephony permission、access token 头文件与实现；对应固定 URL/提交/SHA 在 B/research/corpus/interface/ipc/model_sources.json。

B/research/experiments/interface/ipc/tool_source_manifest.json 保存工具来源、tag、文件、下载退出码、内容 SHA；Match_patterns.ml 返回404，没有拿它作为成功阅读证据。tag+内容哈希没有冒充 commit SHA。第三方源码/二进制不入代码提交，也没有复制工具实现后改名字。

**结论**：自研需要补足 caller 身份域、拒绝分支、保护条件覆盖与长度—目标关联，而非仅缝合三个工具的告警。当前 API 模型有版本假设，不能自动推广为所有历史分支事实。

## 9. 第八步：实现独立 IPC 检测器

**输入**：队长契约、六类方法、静态补丁根因、官方 API 假设和设计控制。

**文件分工**：

| 代码文件（B） | 职责 |
|---|---|
| src/ohscanner/detectors/interface/models.py | IpcPolicy、入口/敏感 API/caller/owner 模型，深度/路径预算 |
| src/ohscanner/detectors/interface/analysis.py | 私有 Tree-sitter 分支解释、状态传播、局部摘要、六类观察 |
| src/ohscanner/detectors/interface/detector.py | 契约适配、候选/义务、完整与 blocked 状态 |
| src/ohscanner/detectors/interface/__init__.py | 对外导出 IpcInterfaceDetector |

**实现顺序与机制**：

1. 识别审核入口、Parcel 参数与同文件函数。
2. 将值区分为 original caller token、caller UID、self、request 派生值、权限判断结果等。
3. if/else 分裂；拒绝 return 截断；switch 分别考虑 case 入口和 fallthrough；循环采用保守零/一次近似。
4. 在路径状态上记录 descriptor、授权、owner、caller class、非负与上界事实。
5. 到达敏感调用时检查该路径的保护事实，生成带入口、行号和路径的候选。
6. 加入深度2的同文件同类摘要；路径默认预算96，超预算用证明事实交集进行保守合并。
7. 格式宏白名单等字节等换行规范化；未知 member pointer 仍保留未知，不捏造调用边。
8. 任一输入公共 parse_status 为 partial 时，保留已分析候选但将运行标 blocked，不能用修复版零告警证明安全。
9. 输出 syntax evidence、unassessed confidence、三项证据义务，不把工具匹配或历史标签升级成 confirmed。

**记录**：A/development-probe.json、development-probe2.json 是中间探测，不是最终冻结版本成绩。最终源码位于提交9495b09；设计冻结文件按内容哈希绑定最终检测器。

**结论**：可以对没有 CVE 标签的新 C/C++ 源码做同类候选扫描；扫描时不加载历史漏洞标签，也不依赖 Semgrep/Joern/CodeQL。尚不具备完整跨文件调用、宏展开、全局别名、任意虚调用、SMT 位宽约束和真实攻击可达性证明。

## 10. 第九步：构造控制，发现基线实验的不公平因素并重跑

**输出**：B/tests/fixtures/ipc/manifest.json、common_types.h、29 个 .cpp；B/tests/test_ipc_detector.py。

29 个设计场景组成：

| 子类 | 场景数 |
|---|---:|
| AUTH-01 | 4 |
| AUTH-02 | 6 |
| AUTH-03 | 7 |
| AUTH-04 | 6 |
| DATA-01 | 3 |
| CAP-01 | 3 |

总计16个正例、13个修复/安全对照。覆盖 ignored/late guard、分支/switch、错误 Parcel、重置/缓存 caller、helper、无关上界、dead path、空对象等。

**发现并修正**：最初不同 TU 共用 Stub 类名，CodeQL 可能合并不同样例定义。最终每个文件添加独立编译类名，然后重新建合成库；最终用 A/joern-synthetic-v2.json、codeql-synthetic-v2.sarif，而非早期同名结果。

**复现命令（R，使用新前缀，不覆盖 v2）**：

```bash
PYTHONPATH=. .venv/bin/python "$IPC_EXPERIMENT/run_synthetic_baselines.py" \
  --workspace "$IPC_WS" --prefix synthetic-replay-doc-check
```

新结果默认不会自动替代 summarize.py 读取的 v2 文件；如需制作新一轮矩阵，先审查新工件并显式更新输入绑定。

另将 denied_complement_positive.cpp 的预期标为 safe：只有在已审核 API 返回域严格 granted/denied 时，相应补集表达式才建立保护；文件名含 positive 不等于标签仍为正例。Semgrep descriptor 规则也补齐花括号/别名等对照后重跑。

**结论**：最终设计样例29/29符合预期；这说明当前模型与开发样例一致，不能说明发现29个历史/新漏洞。

## 11. 第十步：冻结源码，生成变体与做消融

**输出**：B/research/corpus/interface/ipc/design_freeze.json、generated_holdout.json；A/ablation-results.json、generated-holdout-results.json。

冻结时间保存为 UTC `2026-10-09T17:30:59.632049+00:00`，对应北京时间 **2026-10-10 01:30:59**。冻结文件绑定四个检测代码文件 SHA-256；之后生成并评估13个变体，没有根据这一误报调参后再把它冒充盲测。

**复现命令（R）**：

```bash
PYTHONPATH=. .venv/bin/python "$IPC_EXPERIMENT/run_variants.py" --workspace "$IPC_WS"
```

最终保存的消融结果（本次重新读取 manifest，不沿用中间版本数字）：

| 配置 | 符合预期/设计场景 |
|---|---:|
| full | 29/29 |
| no-local-call-summary | 27/29 |
| no-caller-provenance | 20/29 |
| no-sensitive-api-catalog | 19/29 |

生成变体12/13符合预期。`direct-requested-uid-safe` 被报 `ipc.auth.object-owner`，是安全对照误报，保留未删除。

**结论**：局部摘要、身份来源和模型目录对开发样例有效；这些数字不是统计泛化能力。生成变体与设计集同源，不是独立真实历史 holdout。

## 12. 第十一步：通过队长执行链扫描固定历史源码

**复现命令（R；最终报告来自同一脚本方法）**：

```bash
PYTHONPATH=. .venv/bin/python "$IPC_EXPERIMENT/run_own.py" --workspace "$IPC_WS"
```

内部调用 `DetectorRegistry.register(IpcInterfaceDetector())` 与 `run_reviewed_detectors(...)`，输入绑定组件、完整 commit 和限定 .cpp scope；不是向检测器喂 CVE 的答案。历史元数据只在实验层用于挑 scope 和核对主规则。

**输出**：A/own-runs.json，24个revision记录；A/own/<sample_id>-<revision>.json。

主规则仅在已审阅 affected symbol 内计数，和整个文件全部告警分开：

| 根因 | 子类 | 漏洞版主规则候选 | 修复版主规则候选 | 两侧运行覆盖 |
|---|---|---:|---:|---|
| background-470 | AUTH-03 | 2 | 0 | partial → blocked/unknown |
| cve-2022-38064 | AUTH-02 | 1 | 0 | partial → blocked/unknown |
| cve-2022-38081 | AUTH-02 | 3 | 0 | complete |
| cve-2022-38700 | AUTH-02 | 1 | 0 | partial → blocked/unknown |
| cve-2023-0036 | AUTH-01 | 1 | 0 | complete |
| cve-2024-0285 | DATA-01 | 2 | 0 | complete |
| cve-2025-26691 | AUTH-02 | 7 | 0 | complete |
| cve-2025-26693 | AUTH-03 | 1 | 0 | partial → blocked/unknown |
| cve-2025-27563 | AUTH-03 | 3 | 0 | partial → blocked/unknown |
| sa-2022-0602 | AUTH-01 | 8 | 0 | complete |
| sa-2022-0603 | AUTH-01 | 3 | 0 | partial → blocked/unknown |
| sa-2022-0604 | AUTH-01 | 5 | 0 | partial → blocked/unknown |

**结论**：12个设计根因都有主规则候选的修复前后差异；只有5组两侧 complete，其余7组 unknown。修复版主规则为零不表示全部其他候选都为零，也不证明整个文件安全。CVE-2025-27563 五个被补丁调整的 handler 中当前主规则定位三个，不能宣称五个全检出。

## 13. 第十二步：整理对比矩阵，明确评分口径

**复现命令（R）**：

```bash
PYTHONPATH=. .venv/bin/python "$IPC_EXPERIMENT/summarize.py" --workspace "$IPC_WS"
```

**输入**：最终 own/Semgrep/Joern/CodeQL/Clang manifest、设计样例标签、v2合成结果和根因元数据。历史匹配以文件、目标符号区间、正确子类为条件，不用“工具有告警”替代根因命中。

**输出（B 本地 ignored，未提交）**：

- `research/experiments/interface/ipc/results/historical.json`、`.csv`：96条，12根因×2revision×4工具。
- `synthetic.json`、`.csv`：145条，29场景×5工具。
- `evidence_manifest.json`：7个原始运行清单的 SHA-256。

历史矩阵没有给 Clang 造出缺失任务：8个真实 TU 失败仍在 clang-runs.json，不宣称它扫描了全部12根因。

| 状态 | 含义 |
|---|---|
| candidate | 完整限定范围内存在对应候选，仍需验证 |
| not_observed | 完整限定范围内未见对应主规则，不表示安全 |
| unknown | 解析、编译或工程语义覆盖不足；可同时保留非零候选 |
| NA | 本次查询配置不建模该子类，候选数留空；不是整个工具永远不能做 |
| met/miss/false_positive | 设计控制上的期望一致/缺正例/安全对照告警 |

Joern AST 与 CodeQL no-build 未建立完整 OpenHarmony 工程类型/宏语义覆盖，因此历史比较统一保守 unknown。Semgrep 解析错误同样 unknown。本次不存在跨工具公平性能基准，峰值 RSS 未统一记录，不能拿部分耗时做性能优劣结论。

| 当前配置 | met | miss | false_positive | NA | unknown |
|---|---:|---:|---:|---:|---:|
| OHScanner | 29 | 0 | 0 | 0 | 0 |
| Semgrep | 12 | 5 | 5 | 7 | 0 |
| Joern | 8 | 4 | 3 | 14 | 0 |
| CodeQL | 10 | 4 | 4 | 11 | 0 |
| Clang | 1 | 2 | 0 | 26 | 0 |

**结论**：可以比较这组明确配置在开发场景上的表现；不能将此表写成厂商工具排名或真实社区漏洞召回率。真实历史多数覆盖仍未证明。

## 14. 第十三步：回归、压力与工件验证

**已执行的验证命令/方法（A；部分 stdout 有独立日志，部分只有当时工具回执）**：

```bash
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m compileall -q src/ohscanner/detectors/interface research/experiments/interface/ipc
.venv/bin/python "$IPC_EXPERIMENT/validate_corpus.py" --workspace "$IPC_WS"
git diff --cached --check
```

**输出**：A/final-regression.log：`Ran 218 tests ... OK`；A/full-regression.log 保存较早全量回归。218是整个项目测试数，包含此前核心测试，不能说新增218个IPC用例。

汇总脚本曾在重复原生 Tree-sitter 多树遍历中崩溃，结果对齐改为只读词法符号/括号定位，仅用于基线告警归属，不参与检测或漏洞标签判断。

另外对检测器本身做94个真实 .cpp ×3轮并显式GC，282次完成。A/parser-stress.log 是当时临时脚本输出，临时脚本在 A/parser-stress.py；收尾整理的可复现入口为：

```bash
PYTHONPATH=. .venv/bin/python "$IPC_EXPERIMENT/stress_parser.py" --workspace "$IPC_WS" --rounds 3
```

这是 R，运行输出文字可能与临时脚本不同，但扫描/显式GC方法对应；不能声称因此排除一切原生解析生命周期问题。

Excel 另做 ZIP/工作表/单元格错误类型/候选数字列检查，五页数据行（含表头）分别14、97、146、14、40；并渲染逐页检查。冻结源码哈希保持一致。

**结论**：当前已检查路径未出现回归，工件有内容与来源绑定；未完成 OpenHarmony 产品构建、设备执行、攻击可达性或安全影响验证。

## 15. 第十四步：输出文档、Excel，完成本地提交

**已提交叙述产物（B）**：

| 文件 | 用途 |
|---|---|
| docs/research/ipc_scanner_v0_1_2026-10-10.md | 算法、历史根因结果、工具比较、局限、复现/接入 |
| research/methods/interface/IPC_METHOD_CARD.md | 输入/输出、六类方法、控制、证据与独立holdout计划 |
| research/methods/interface/IMPLEMENTATION_LOG.md | 七阶段执行清单与未证明事项 |
| research/corpus/interface/ipc/README.md | S0–S3、design/生成变体、源文件位置与校验 |
| research/experiments/interface/ipc/README.md | 全部复现入口的职责 |
| research/experiments/interface/ipc/environment.json | 实际版本与配置 |
| research/experiments/interface/ipc/tool_source_manifest.json | 工具源码阅读来源、tag、内容哈希、失败 |

**E盘交付物（本次补全文档之前已有）**：

| E目录下文件 | 用途 |
|---|---|
| ipc_scanner_v0_1_2026-10-10.md | 中文结果报告副本 |
| IPC_v0.1_实验矩阵.xlsx | 阅读说明、历史对比、子类控制、冻结后变体、公告清单五页 |
| historical.json / historical.csv | 逐根因×revision×工具机器记录 |
| synthetic.json / synthetic.csv | 逐设计场景×工具记录 |
| environment.json | 环境副本 |
| evidence_manifest.json | 原始运行清单哈希副本 |
| 本地提交与接入交接.md | WSL工作树、分支、提交、接入状态 |
| 交付文件校验.json | 当时交付文件内容哈希 |

Excel生成脚本在 A/create_workbook.mjs，使用本机 @oai/artifact-tool，不是扫描器依赖；预览在 A/workbook/*.png，导出在 A/workbook/IPC_v0.1_实验矩阵.xlsx。生成命令为 Windows `node <上述UNC路径的create_workbook.mjs>`。脚本依赖本机固定 artifact-tool 安装位置，不是跨机器零配置脚本。

**本地提交命令（A）**：

```bash
git commit -m "feat(interface): add first-party IPC candidate detector and reproducible research"
```

结果9495b09，67个文件、2425行新增。未push。此前旧研究计划/旧17条种子/旧corpus README仍为既有未跟踪文件，不混入此次提交。

## 16. 已有记录的缺口与本次核查发现

1. 有执行清单、实际工具argv、原始告警、失败日志、版本、源码与结果哈希；没有每次临时shell/Python操作的全量逐字历史。
2. 一些自动化脚本在收尾时整理，本文标R，不把它们冒充最早原始流程。
3. pair-downloads.json只有一阶段78条，最终98文件由元数据与validator核验；不能把该文件说成完整下载轨迹。
4. 没有完整工具环境bootstrap、统一峰值RSS、全部下载包签名/校验流程。
5. 标签为本次静态根因审阅，非独立双人标注；12根因全部开发集，未完成独立真实holdout。
6. 本次发现E盘旧结果报告有两处文字与仓库版不同，旧交付校验中的该报告SHA不匹配；其余旧交付项核对匹配。保留旧文件与旧校验，未静默覆盖或重新签署旧证据。正确技术内容可参考B已提交版本；本次新增说明和“过程记录核查快照”单独保存。
7. 本文补写不重跑或覆盖历史实验，不修改冻结检测代码，不自动把候选升级为漏洞。

## 17. 现在扫描器能做什么，以及新源码扫描处于哪一步

现在能通过既有 Registry/fixed-Git API，分析指定C/C++提交和文件范围，输出六类已建模问题的候选、位置、路径及待核查义务；算法不依赖CVE名称/历史答案，因此**能够用于新源码**。

但 `run_own.py` 是历史实验驱动器，默认读取12组元数据，不是任意仓库的新扫描CLI。对新源码应显式给 `run_reviewed_detectors(repo_path, component, full_commit_sha, cpp_scope, registry)` 的真实输入，审核服务入口/敏感API，并保留完整范围与unknown。

本次任务是过程核查和文档补全，**尚未输出“最新社区代码扫描报告”，也没有证明发现新的未公开漏洞**。真正挖掘时还要核对候选的真实caller/权限、dispatcher上游保护、工程宏/可达性、具体影响、是否已有补丁或公告；最终能报告的发现可能少于候选数，也可能为零。

后续新扫描应另建带日期/精确提交的新实验目录，记录“选目标→固定版本→范围/模型→扫描→逐候选排假→修复对照/验证→结论”，不覆盖这次开发集工件。
