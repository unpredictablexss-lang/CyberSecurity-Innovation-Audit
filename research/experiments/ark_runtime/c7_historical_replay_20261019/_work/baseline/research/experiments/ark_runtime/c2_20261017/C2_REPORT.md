# C2 V0.1 Runtime 类型来源检测器交付报告

日期：2026-10-17。分支：`codex/teammate-c-ark-runtime-type-safety`；main 基线：`e510c99c67f31ec6c73365f9ab749c79ca6ff0a1`。本报告描述已运行的独立原型，不是新漏洞确认报告。

## 结果

- 实现 `ohscanner.ark.runtime.type_safety 0.1.0`，唯一规则 `ark.runtime.typedarray-store-type-origin`。代码只在 C 专属模块；未修改公共 Runner/Catalog/contracts、数据库/API/UI 或默认检测器集合。
- C01–C12 均实际执行，规则行为预期 12/12 通过。它们是开发控制，不是独立真值集，不计算 Precision/Recall。
- C 专属自动化回归 41/41 通过，含真实 Git 双版本、对象别名/token 复制、重新赋值、同名 API、unknown 控制、源 hash 拒绝、稳定 ID、v2 契约、partial/完整范围混合及预算回退。
- 真实父提交 `830e85b40240677039719fcbf14f721ad3b19050` 独立实验产生 1 条类型来源候选；修复提交 `a0e30483ab3e4aead67ecfb5c708489915e447f9` 产生 0 条该规则候选，并记录目标来源匹配。两者文件均保持 partial，公共 Runner 两次均 blocked/not_analyzed。没有把研究结果冒充生产扫描成功。
- 45 项既有契约测试在 Windows 实际重跑：44 通过、0 assertion failure、1 error（符号链接权限 WinError 1314），退出码 1。未修改或跳过该测试以制造全绿。
- 本机 WSL 查询未得到可用发行版，Docker/Podman 命令不可用；本地 Ubuntu/WSL 复测未执行。独立 Draft PR 将沿用现有 Ubuntu 22.04 CI；CI 结论以该 PR 对应 SHA 的实际运行记录为准。CI 未提供固定 Ark 对象库时，两个历史测试明确 skip，不等于历史用例已在 Linux 执行。

## 实现与边界

`syntax.py` 复用既有 Tree-sitter C++ grammar，不修改公共 parser 输出。函数绑定使用命名空间/类/名称/参数类型，局部变量按作用域及定义位置绑定，不硬编码变量名或修复行号。

`type_origin.py` 记录对象身份、类型 token 来源、简单别名和复制；重新赋值使旧变量事实失效。未知修改调用会使相关同型保证回退 unknown。无法解析的 creator、sink receiver、签名、目标或 token 不推断类型混淆。

`runtime_ir.py` 单独建模 `BRANCH/Bind/Jump/LoopBegin/LoopEnd` 和外部出口，不把宿主 C++ 的大括号顺序当运行时可达性。支持常量分支、稳定局部谓词矛盾检查和窄范围类型相等守卫；普通 C++ 分支汇合、未知宏/标签、lambda、类型/调用遮蔽及未建模控制均回退。

`analysis.py` 有字节、嵌套、指令、状态、步数和时间预算。预算/超时中断不会发布截断候选集合。候选路径是**有界模型中的符号图路径**；没有完整数值约束求解、全程序 CFG/phi、编译器级 C++ 类型解析或真实 Runtime 触发证明。保留结构路径不等于证明其全部条件在产品中可满足。

`detector.py` 使用现有 `DetectorFinding/DetectorRun/EvidenceObligation`。保留 `required_facts=('ast',)`；partial 源和缺少共享 AST 资格证据在直接适配器中同样被拒绝。候选包含源码 SHA、caller、类型/创建位置、生成图路径、模型 digest 和未满足义务；归一化后为 v2、CWE-843 候选和 unassessed。默认 Catalog 未启用。

partial 独立实验是负责人明确允许的研究路径。它不升级 SourceUnit.parse_status，且始终记录解析依赖污染未知与生产未准入。详细方案见 `PARTIAL_ADMISSION_RFC.md`，尚待负责人决定。

## 来源复核

通过显式 Git fetch 获取两个固定历史提交及 tree 到本地研究对象库。选定的 3 份源码字节从 C1 已校验缓存写入 Git blob，再逐项核对真实 commit/tree/path/OID/SHA-256 和读取字节；公共 `prepare_git_context/load_git_sources` 能在禁用隐式网络的条件下加载它们。还验证两个版本的创建函数使用相同 blob，避免将修复后的创建摘要无条件套给修复前。

采用的远端为官方 GitHub 组织镜像。GitCode 官方主库精确 fetch 返回 `upload-pack: not our ref`，因此主库交叉核验记 unavailable，不把镜像当成已核验 GitCode 发布版本。没有用当前 HEAD 替代历史提交。原始源代码、Git 对象库与依赖缓存留在 .tmp，不入 PR；提交仅保留小型来源/结果记录。上游文件 Apache-2.0 头已检查，检测逻辑与 fixture 自研，没有调用外部漏洞扫描器或读取历史 verdict 决策。

本例是公开历史修复。未绑定 `CVE-2025-27536`、严重度、产品受影响分支或新漏洞奖励结论。未执行上游构建、AOT 测试、PoC 或动态攻击。未来确认仍需入口、受控输入、真实执行模式、具体 CIA 影响、隔离复现及修复重验。

## 复现

先按项目依赖安装环境。以下命令中的 Git 同步是独立显式准备步骤；检测/测试本身不联网，也不执行上游代码。

```powershell
python -m pip install -r requirements.txt
git init --bare .tmp/ark-source.git
git -C .tmp/ark-source.git fetch --depth=1 --no-tags https://github.com/openharmony/arkcompiler_ets_runtime.git 830e85b40240677039719fcbf14f721ad3b19050 a0e30483ab3e4aead67ecfb5c708489915e447f9
$env:OHSCANNER_ARK_REPO = (Resolve-Path .tmp/ark-source.git).Path
python -m unittest discover -s tests/detectors/ark_runtime -t . -v
python research/experiments/ark_runtime/c2_20261017/replay.py --repo-dir .tmp/ark-source.git --output .tmp/c2-results
python -m unittest tests.test_ohscanner_contract tests.test_contract_v2_source_binding -q
git diff --check
```

本机实际复用了已有依赖，通过 `PYTHONPATH` 向父/子进程提供它们，版本记录见 `run_manifest.json`。不要把 C1 的离线安装失败或 Windows 符号链接错误描述成安装成功/契约全绿。

Linux 可将设置环境变量的行替换为 `export OHSCANNER_ARK_REPO="$PWD/.tmp/ark-source.git"`。GitCode 不能提供固定对象时保留来源限制。干净 checkout 若没有准备真实对象库，历史单测会明确 skip；replay.py 必须提供对象库，不会静默换成合成样本。

`test_results.json`、`historical_results.json`、`source_evidence.json`、`run_manifest.json` 和 `artifact_hashes.json` 是本次运行产物。耗时为本轮实验实测，RSS 未测，不包装成大规模扫描性能。机器专属缓存/输出绝对路径从清单脱敏，所用 commit/tree/blob/hash 均未脱敏；测试命令及退出码按实际记录。

## 验收回执

- 第一版算法与 12 案例：已完成并执行。
- 来源：本地 Git 对象链已核验；GitCode 主库对照 unavailable。
- 生产准入：blocked，partial RFC 待审；不申请默认启用或自行改公共协议。
- Windows：新增 41/41；既有契约 44/45，1 环境错误。
- Linux：等待对应 PR 的实际 CI；固定历史对象在 Linux 的独立复扫未执行。
- 公共模块：无改动；只按 AGENTS 要求在推送前追加当前状态记录。
- 新漏洞确认、产品 PoC、影响版本及大规模性能：未完成，不能据本次结果作结论。
- Draft PR：创建后以聊天中的附加 PR 为准；保持 Draft，不合入 main。
