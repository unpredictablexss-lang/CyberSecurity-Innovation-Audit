# D104／T103 主线选择性集成与工程验收

日期：2026-10-20（中国标准时间）

## 状态快照

| 项目 | 实际状态 |
|---|---|
| D 研发分支 | 已完成 D104／T103 收尾；`origin/codex/d-owner-20261020-01a1571f` = `d39685ba504d9bd31978107fce7e19f803cf1353`。检测器版本为 `sensitive_exposure 0.21.17`、`known_disclosed_cves 0.19.11`。 |
| 本次集成分支 | `codex/d-integration-20261020`；代码验收快照 `f076b8c667b619c1454b03da3e5ef4e0e8a23611`，基于最新核实的 `origin/main 0f53af62283dbd0f249280805e8286a04b2d43b9`。 |
| main | 已 fast-forward 至 `4b0e16576a45a111b4fad7e8f82819a47ed472f5`；推送回执确认从 `0f53af62283dbd0f249280805e8286a04b2d43b9` 更新成功。 |
| 运行服务 | 未在本次可确认授权的运行环境内检查或重启；不能声称服务运行了本 D 版本。 |

原项目 checkout `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit` 是 A 线工作树，存在 723 项未提交修改；全程保留。集成工作只在独立 worktree `D:\openHarmonyScanner\worktrees\d-integration-20261020` 完成。启动时重新 fetch 后确认远端 main 从历史线索 `dd8b12b9f` 前进到 `0f53af622`（两条 IPC closeout 提交），集成提交已 rebase 到该最新基线。

## 接入差异

必要的 D 代码、直接依赖、回归输入和收尾证据已选择性接入，共 107 个文件。包含：

- D 检测器实现、角色/属性模型和 catalog 元数据；两个 detector 仍 `default_enabled: false`，需请求显式选择。
- 共享 Parser 的窄 C++ 赋值逗号恢复、原始字节跨度保留，以及空 `extern "C"` 包装恢复；相关兼容和负例测试。
- 已披露 CVE detector 使用的 artifact/source identity adapters 与固定 known-case fixtures。
- D84–D101 定向测试及 D104/T103 closeout、引用核对材料。

共享改动单列：`src/parser/ast.py`、`src/parser/syntax_normalize.py`、新增 `src/parser/cpp_assignment_comma.py`；`src/ohscanner/detectors/catalog.py`；新增 `src/ohscanner/detectors/adapters/`。这些是 D 分析与已披露 CVE adapter 的直接依赖，并通过 Parser/CVE 接口兼容集验证。没有带入 D 分支上的 C 线 detector、A/B 线研究实现或旧平台代码。

## 本轮实际检查

最终代码快照 `f076b8c…` 上，使用项目 WSL Python 3.12 环境：

| 命令组 | 实跑结果 |
|---|---|
| D focused：T100/T101/parser 定向用例 | 51/51 通过 |
| `python -B -m unittest discover -s tests/detectors/data -q` | 431/431 通过 |
| AST、C++ linkage、assignment-comma、known CVE/corpus compatibility | 69/69 通过 |
| `git diff --check` | 通过 |
| 全仓库 `python -B -m unittest discover -s tests -q` | **未完成**：修正到集成 worktree Git 管理目录后运行超过 10 分钟，WSL 子系统重启，进程以 1 退出且没有 unittest 汇总。无全仓库通过数；未把历史 1,470/431/69/51 等记录当成本轮结果，也未将重叠数量相加。 |

早期 Windows 原生试跑未计入通过：D data suite 因 POSIX `resource` 模块和当时未带入的 D5/D93 测试输入报错；compat 命令因当时未带入的直接 adapters/corpus 文件报导入错误。补齐所需文件后在项目支持的 WSL 环境重跑，D/data/compat 三组分别得到上述通过结果。全量测试首次误用了主仓库 Git 环境，已停止并排除；第二次使用正确集成 worktree HEAD 运行后被 WSL 重启中断。全量结果仍为未完成。

## 固定源码接线回放

使用本地固定源 `openharmony/security_certificate_framework`：commit `e270363a042bf8f0126881c76d1341ad457cc187`，tree `e69153afa89928e1318d8b36cf37c65386465fe7`。将本地对象以浅克隆方式复制到隔离目标根后确认 HEAD/tree 与固定值一致。显式扫描 manifest 锁定的 3 个文件：`napi_cert_utils.cpp`、`napi_cert_defines.h`、`cf_log.h`，共 81,770 bytes；3/3 前端解析 complete。扫描请求显式包含全部 12 个 catalog detector。

本次实际完成 API 扫描提交 → Worker → JSON/Markdown 报告 → 每个候选的源码定位接口。Job `2acbf73280c84e2e91fc36ddfe19517e` 状态 `completed_with_limitations`；全 detector 126 个候选，126 个均通过源码 SHA 对照定位。D detector 为 `0.21.17`、状态 `blocked`、24 个 candidate diagnostics、0 个 `validated_vulnerability`。这 24 个均保留来源 blob/SHA/byte span；报告的 stable/occurrence identity 仍是 unknown，未合成候选身份。源绑定只确认扫描字节对应固定源码，不证明漏洞成立。完整候选身份、每个源 hash/span 及报告/verification 产物 hash 见 [固定源码接线 JSON](D_INTEGRATION_REAL_SOURCE_REPLAY_20261020.json)。

- 固定源码 snapshot SHA-256：`9894780c6bf1ac9ddcfc78defb41fce95402a936b240e1375a13fe4aa7842eb7`
- Worker 报告 SHA-256：`59535facac4bb5c50feef299ef7487068405280f56fe33a1c0d5775686bdae54`
- 验证摘要 SHA-256：`8e6077281b3e1de66986a1aac9d7ee05ba09301d2df3428e6026750029c26322`
- 集成 JSON SHA-256：`58b74c831358e919fd6a5a943dbf7fd372f4b039e73afc6d7aa7df3925726a97`
- 本地 data-dir：`D:\openHarmonyScanner\tmp\d-cert-scan-data-20261020b`；未提交数据库/运行缓存。报告和 artifacts 保留于该目录，summary JSON 保存各文件名、大小和 SHA-256。

历史 D103 arkui_napi 回放仍是 0 diagnostics 且 `blocked`，分析 3 项 partial；零候选不是安全结论。T103 的历史 24 条 certificate diagnostics 与本轮接线中 D 24 条一致，当前 job 额外运行其他显式 detector，故总数 126 不与历史 24 混为同一统计口径。

## 限制和未验证项

已知交接边界保持原状态：不匹配/截断 C++ 括号跨度、`const char **` 输出摘要、赋值操作数类型证明、未知/重载 comma、一般 CFG/alias/namespace/preprocessor；N-API 版本/类型绑定、cleanup 函数绑定、真实日志 sink 匹配。产品构建、目标执行/运行时影响、部署状态和准确率未验证；precision/recall 与产品安全/漏洞结论为 unknown。无需以这些未知项开启新研发轮次。

## 发布动作

集成分支与报告已推送到远端；`git push origin HEAD:refs/heads/main` 成功将 main 从 `0f53af62283dbd0f249280805e8286a04b2d43b9` fast-forward 至 `4b0e16576a45a111b4fad7e8f82819a47ed472f5`。后续一次 fetch 因 GitHub HTTPS 暂时不可达而失败；推送成功回执和本地更新后的 origin/main/ref 均记录相同 SHA。服务重启仅能在其已授权的部署环境完成并核对运行版本；本次没有声称已重启或已部署。

没有自动开启 D105 或第二层模型研发。
