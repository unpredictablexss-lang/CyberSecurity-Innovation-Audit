# c_utils 当前版本完整组件静态扫描试点

日期：2026-10-08。试点分支：`codex/cutils-component-pilot`，基于历史分支 `dd908f2`。
本次只推进静态扫描和覆盖核验，历史 PR #4 保持 draft。

## 固定版本与范围

- 仓库：`openharmony/commonlibrary_c_utils`。
- 查询远端默认分支 HEAD 后固定提交：`b807d3dadb7dbb7639fe85b3a5f72da18d318da2`。
- 从该提交的 Git 对象生成完整快照，共 228 个仓库文件；验证 commit 对象、完整
  tree、每个 blob 和 SHA-256，扫描前后再次核验文件清单和内容。
- C/C++ 范围为 123 个文件、47,822 行，其中生产代码 62 个文件，测试代码 61 个。
  Rust、构建文件和文档属于快照，但未计入 C/C++ 已扫描范围。
- 完整组件指该仓库的完整文件范围，不代表已经构建完整 OpenHarmony 产品。

第三方源码位于审计仓库之外。已阅读组件 AGENTS.md、base/BUILD.gn 和 bundle.json；
组件源码、公共 API、构建定义均未修改。构建声明依赖 bounds_checking_function、hilog、
rust_cxx 等组件，本次没有伪造其头文件、宏或编译数据库。

## 实际执行结果

| 配置 | 运行/覆盖状态 | 原始诊断数 | 生产代码 / 测试代码 | 限制 |
|---|---|---:|---|---|
| own_text | completed | 0 | 0 / 0 | 仅现有危险调用模式；零诊断不代表安全 |
| own_ast | blocked | 0 | 0 / 0 | 93 个文件完整解析、30 个部分解析 |
| Cppcheck 2.7 | failed | 86 | 40 / 46 | 包含 47 条 syntaxError、22 条 unknownMacro |
| Semgrep CE 1.179.0 / vendor raptor | failed | 953 | 104 / 849 | 文件清单覆盖 123 个，但原生结果有 8 条分析错误 |
| Semgrep CE / OH 两条规则 | failed | 7 | 0 / 7 | 文件清单覆盖 123 个，但 parcel.h 有 1 条解析错误 |

failed/blocked 表示过程失败或覆盖不完整，原始诊断仍保留。诊断数量包含解析问题、
风格提示和候选模式，不能相加作为漏洞数，也不能据此计算准确率或误报率。
两种 Semgrep 配置共用一个引擎，不算两个独立扫描器。

OH 的 7 条诊断均为测试代码中的 reset 模式：event benchmark 3 条、singleton
benchmark 1 条、event unittest 3 条。现有规则匹配任意 `.reset()`，不能证明对象类型、
线程竞争或释放后使用；这些候选仍需上下文审查，本次未修改规则或宣布误报/漏洞。

首轮轻量批次中 Clang、CodeQL、Joern 尚未执行；后续 host 实验见下节。历史样本上的
执行记录不能替代当前版本实验。没有 PoC、运行时触发、可利用性或新漏洞结论；
validated_vulnerability=0。

## 与历史基线的隔离

当前组件使用 `experiment_kind=current_component` 和
`target_id=current-component:openharmony/commonlibrary_c_utils`，独立保存 summary。
不生成历史 root-cause hit/miss 矩阵。回归测试验证即使 commit 被设置成历史样本版本，
当前组件报告也因 target_id 不匹配而无法进入历史矩阵。
历史分支仍为 dd908f2，64 格基线为 possible_hit=5、miss=29、unknown=20、
not_applicable=10；本次没有改写这些实验产物。

## 复跑与产物

先显式获取组件仓库，再固定提交。快照脚本只读取本地 Git 对象，不 fetch、不 checkout。
在 WSL 文件系统保存源码和工作产物：

```bash
python -m scripts.prepare_component_snapshot \
  --repo /path/to/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2 \
  --output-dir /path/on/wsl/cutils-snapshot
python -m scripts.run_component_pilot \
  --snapshot /path/on/wsl/cutils-snapshot \
  --output-dir /path/on/wsl/cutils-results \
  --semgrep-root /path/to/semgrep-python-dependencies
python -m unittest discover -s tests -q
```

快照准备要求新的输出目录，避免残留文件混入。产物包含 snapshot.json、五份原生
输出、执行参数/规则 hash、五份归一化报告和 summary.json。报告副本位于本地
outputs/reports/component_pilot，已加入 Git 忽略；第三方源码和生成产物不推送。

本地完整回归：160 项通过。新增测试覆盖源码漂移、仓库/提交混用、路径越界、
清单遗漏/额外文件、语言范围伪装、tree 路径/模式绑定，以及当前/历史结果隔离。

## 下一步

历史线继续核验缺依赖和宏解析；试点线先审查生产代码诊断、归类 30 个 AST 部分解析
文件，再准备固定依赖和原始编译配置。公共修复携带历史回归后单独引入历史分支。
先完成 c_utils 一个试点的覆盖改进，再考虑 dsoftbus，不同时铺开四个完整组件。

## 第二批：固定依赖与 Linux host 编译分析

securec 依赖仓库 openharmony/third_party_bounds_checking_function 固定为
61baa7a3eb9347efca58397d1d0504faa96d79f0；56 个仓库文件从 Git 对象生成并核验。
该版本独立固定，尚未与某个 OpenHarmony 产品 manifest 的依赖锁核对。

从固定 base/BUILD.gn 的 sources_utils 读取 21 个 TU，建立 utilsbase Linux host
bootstrap 配置。显式采用 C++17、Clang 14、系统 libstdc++ 和组件/securec include。
GN host 分支不加入 ashmem，且不启用设备 CONFIG_HILOG / UTILS_FDSAN。
这是依据 GN 重建的测试配置，不是 GN 执行后导出的完整产品配置。

| 工具 | 实际执行 | 结果与覆盖 |
|---|---|---|
| Clang Static Analyzer 14 | 21 TU 先语法检查再 --analyze | 21/21 成功；1 条 warning、30 条路径 note |
| CodeQL 2.27.1 / cpp-queries 1.9.0 | manual 模式跟踪实际 clang++ -c，再执行 security-and-quality 查询套件 | 21/21 对象编译成功；21 TU 成功提取，无 failed-include 指标；11 条诊断 |

对象文件仅编译，不链接或运行组件代码。CodeQL 首次启动因构建命令在 source-root
执行、缺少审计项目 PYTHONPATH 而失败；修正执行环境后另目录重跑，失败日志保留。
Clang 的唯一 warning 位于 parcel.cpp:404；CodeQL 包含 8 条重复 include guard、
1 条 free 前冗余判空、1 条注释代码、1 条枚举风格诊断。均未提升为漏洞。

host 的两个归一化报告使用独立 target_id 后缀 utilsbase-linux-host-bootstrap，并验证
同 commit、21 TU 范围与 LOC 后形成能力矩阵。不能与 123 文件轻量范围混成同一比较。
compile_commands.bootstrap.json 明确标注重建配置，不冒充 GN 导出的 compile_commands.json。
设备、Rust、ashmem、测试及未实例化模板仍有覆盖缺口；第二批结束时 Joern 仍为 not_run，第三批覆盖核验见下节。

生产候选上下文及解析问题见 docs/reviews/cutils_component_context_review_2026-10-08.md。
第二批完整回归 164 项通过；新增 host 源文件范围、审查版本隔离及 CodeQL 机制误标回归。

```bash
python -m scripts.prepare_component_snapshot \
  --repo /path/to/third_party_bounds_checking_function \
  --repository openharmony/third_party_bounds_checking_function \
  --commit 61baa7a3eb9347efca58397d1d0504faa96d79f0 \
  --output-dir /path/on/wsl/securec-snapshot
python -m scripts.run_component_clang_host --snapshot /path/on/wsl/cutils-snapshot \
  --dependency /path/on/wsl/securec-snapshot --output-dir /path/on/wsl/clang-host
python -m scripts.run_component_codeql_host --snapshot /path/on/wsl/cutils-snapshot \
  --dependency /path/on/wsl/securec-snapshot --output-dir /path/on/wsl/codeql-host \
  --codeql /path/to/codeql --suite /path/to/cpp-security-and-quality.qls
python -m scripts.inventory_component_review --snapshot /path/on/wsl/cutils-snapshot \
  --reports /path/to/light.normalized.json /path/to/clang-host/normalized.json \
  /path/to/codeql-host/normalized.json --output /path/on/wsl/review/inventory.json
```

## 第三批：候选审查账本、AST 归因与 Joern 覆盖核验（2026-10-09）

本批只推进固定组件的静态候选审查和覆盖核验，没有执行 PoC、运行时触发、
可利用性判断或动态验证。PR #4 仍为 draft，未改 ready、未合并。

### 生产候选审查字段

基于同一 b807d3dadb7dbb7639fe85b3a5f72da18d318da2 快照和八份归一化报告，
生成逐条上下文账本。生产条目保持 132 条：Semgrep 104、Cppcheck 16、
Clang SA 1、CodeQL 11。相同位置或相同规则的诊断不去重、不合并，也不把
条目数称为问题数或漏洞数。

每条记录均绑定 repository、commit、snapshot tree、source_report_path、
source_report_sha256、tool/version、run_id、target_id、report_status、
精确 file/line/column/rule/symbol 和七行源码上下文，并显式包含
input_control、destination_capacity、length_origin、guard_evidence、
reachability、security_impact、runtime_validation 字段。由于尚未人工裁决，
前六类审查字段保持 unknown，runtime_validation 保持 not_run；
candidate_status=candidate、review_status=unassessed、case_status=draft。
validated_vulnerability=0。生成的 JSON/Markdown 账本位于被忽略的
outputs/reports/component_pilot/review/，不作为提交产物。

### AST partial 归因候选

30 个 partial 记录逐文件保留：生产 6、测试 24。所有记录继续为
parser_status=partial、cause_status=candidate_cause、
source_syntax_status=unknown、real_syntax_issue_status=unknown。

生产文件的可能原因候选为：safe_map.h 与 unique_fd.h 的模板/未实例化；
thread_safety_analysis_macros.h 的宏与条件编译；ashmem.cpp 与
io_event_epoll.cpp 的条件编译/实现分支；parcel.cpp 的成员函数指针或
解析器方言。测试文件主要记录测试框架/注解宏候选，同时保留文件中实际
出现的条件编译和模板上下文。以上只表示源码相关性，不证明唯一归因；
没有剥离宏、删改注解或修改第三方源码。

### Joern 当前 nothrow/判空查询

选择此前 not_run 的 Joern 缺口，使用 Joern 4.0.649 和
scripts/joern_nothrow_guard.sc。查询文件 SHA-256 为
72c5da852f8b8ed44232dad6b97b48fbbc2d6ed31467423d2aa06bca9a2e20f5；
组件 snapshot.json SHA-256 为
711cedce3386ab3ce21f82902e5a8b6da94f46cdf9fed16bf7196bbbd7f8514c。
执行范围账本固定 123 个 C/C++ 文件、47,822 行，并逐文件记录 Git blob 和
SHA-256。c2cpg 与查询命令均退出 0，原生命令、耗时、stdout/stderr、
CPG 和查询输出保存在被忽略的 outputs/reports/component_pilot/joern/。

解析覆盖没有闭合：c2cpg 覆盖表只发现并标记 62/62 个生产文件，
61 个测试文件没有覆盖行；日志还记录 8 次 CASTProblem。因此归一化状态为
blocked，analysis_interpretation=unknown。查询输出 0 条结构候选，
这不是 miss、零漏报或安全证明。Joern 查询仍不验证 guard 支配、并发、
输入控制、影响或可利用性。

### 回归与剩余限制

复跑候选账本与 Joern 覆盖记录（路径按实际固定快照和工具安装位置替换）：

```bash
python -m scripts.run_component_joern --snapshot /path/on/wsl/cutils-snapshot \
  --output-dir /path/on/wsl/component_pilot/joern \
  --joern /path/to/joern --query scripts/joern_nothrow_guard.sc
python -m scripts.inventory_component_review --snapshot /path/on/wsl/cutils-snapshot \
  --reports /path/to/cppcheck.normalized.json /path/to/own_ast.normalized.json \
  /path/to/own_text.normalized.json /path/to/semgrep.normalized.json \
  /path/to/semgrep_oh.normalized.json /path/to/clang_host/normalized.json \
  /path/to/codeql_host/normalized.json /path/to/joern/normalized.json \
  --output /path/on/wsl/review/candidate_review.json \
  --markdown /path/on/wsl/review/candidate_review.md
```

`python -m unittest discover -s tests -q` 在 WSL Python 3.10.12 下
174/174 通过；`git diff --check` 通过。新增回归覆盖审查字段默认值、
重复诊断保留、报告/commit/target 混用拒绝、报告 SHA-256 不匹配拒绝、
AST partial 候选归因、Markdown 全量集成，以及 Joern scope/hash、
解析覆盖、绝对路径归一化和 unknown 判定。

仍未覆盖：设备路径、Rust、ashmem/设备条件分支、测试代码的完整编译/分析、
未实例化模板、产品 GN 导出的真实 compile database。失败或部分解析均不写成
miss，未执行扫描器不写成覆盖；本批不扩大到 dsoftbus。
