# 队友 A 分支整合报告（2026-10-10）

## 范围

本报告只覆盖：

- `codex/**`
- `experiment/**`
- 对应的 `origin/codex/**`、`origin/experiment/**`

非队友 A 命名空间的分支不纳入本报告，也不在本次整合中修改。

整合基线：`6afb7d0a589056bf68f0373c723678b7f5fd2275`。  
整合分支：`codex/teammate-a-fragment-consolidation-20261010`。

## 1. 已整合内容

### shared_ptr race 基线

`6afb7d0` 已包含：

- `ohscanner.cpp.shared_ptr_race` detector；
- exact Git origin/commit/tree/blob/source hash 绑定；
- review evidence verifier；
- positive/fixed/safe/unrelated/unknown fixtures；
- holdout manifest 隔离；
- M-gate 回归和 CI 记录。

该基线直接保留，不重新实现。

### lifetime / evidence / corpus

从 `codex/teammate-a-lifetime-evidence-next` 整合：

- `src/ohscanner/detectors/cpp/lifetime_detector.py`；
- `lifetime_review.py`；
- lifetime / bounds research slices；
- native evidence builder / validator；
- `research/corpus/native/**`；
- lifetime / bounds / UAF / OOB method cards；
- lifetime holdout plan；
- lifetime fixtures 和定向测试；
- teammate A evidence package 回归。

interface baseline 已改绑当前 A 线基线：

- head：`6afb7d0a589056bf68f0373c723678b7f5fd2275`；
- `src/ohscanner/contracts.py` SHA-256：`ff942f17f0be8e74504516ba2a5a3ed4310e6aa96c5d10b2d471845c47a728e8`。

`lifetime_uaf_native_run_2026-10-10.json` 是生成实验 manifest，不提交；依赖它的测试保持明确 skip。

### c_utils product / component research

从 `codex/cutils-component-pilot` 和 `experiment/cutils-product-scan` 整合：

- product manifest 读取和 partial lock 校验；
- component dependency / review modules；
- component snapshot、host Clang/CodeQL、Joern、product probe scripts；
- component/product manifest tests；
- component pilot 与 product preflight 文档。

这些能力是 product/build research 工具，不注册到 production detector catalog，不作为 OHScanner 自研漏洞检测能力。

### dataset research

从 `codex/dataset-pilot-20261009` 整合：

- `docs/testing/数据集调研报告.md`

## 2. 分支处置

| 分支 | 状态 | 处置 |
|---|---|---|
| `codex/teammate-a-shared-ptr-race-migration` | `integrated` | 作为本次整合基线 |
| `codex/teammate-a-lifetime-evidence-next` | `integrated` | lifetime、evidence、corpus 与测试已重放 |
| `codex/cutils-component-pilot` | `integrated / reference-only` | component research modules 已整合，但不是 production detector |
| `experiment/cutils-product-scan` | `integrated / reference-only` | product manifest、partial lock、probe 已整合，产品构建仍未闭合 |
| `codex/dataset-pilot-20261009` | `integrated` | 数据集调研报告已整合 |
| `codex/teammate-a-oh-vuln-corpus-next` | `superseded` | 有效 corpus/evidence 内容由 lifetime 整合版本覆盖 |
| `codex/teammate-a-oh-vuln-corpus` | `superseded` | 旧版 corpus 状态切分 |
| `codex/teammate-a-oh-vuln-corpus-pre-cleanup` | `obsolete` | cleanup 前快照，仅含 prompt/旧文档 |
| `codex/teammate-a-cpp-detectors` | `obsolete` | 仅 prompt 文件 |
| `codex/teammate-a-cpp-detectors-393f` | `superseded` | 早期 lifetime 测试，无当前独有新增 |
| `codex/teammate-a-shared-ptr-race-evidence` | `superseded` | 旧 shared_ptr 证据包，被 `6afb7d0` 加固版取代 |
| `codex/reviewed-a-integration-20260909` | `superseded` | 历史 A/c_utils 集成快照 |
| `codex/a-merge-review-20261010` | `superseded` | 历史 review 快照 |
| `codex/vulnerability-dataset-survey-20261009` | `obsolete` | 与 dataset-pilot 重复 |
| `origin/codex/**` | `mirror` | 与对应本地分支相同，不另建集成路径 |
| `origin/experiment/cutils-product-scan` | `mirror` | 已由 experiment 分支内容覆盖 |

## 3. 未完成但不判废

- product scan 的完整 GN/Ninja/Node 工具链、compile_commands 和传递依赖锁尚未闭合；
- component research scripts 依赖外部工具/真实源码工作区，不能作为 production detector runtime；
- lifetime native replay 的 ignored run manifest、原始日志和 artifact index 仍需外部保存；
- 各 detector 的独立 holdout、PoC/dynamic、confirmed/reportable promotion、影响版本和漏洞报告仍属于 C-gate。

## 4. 验证

- lifetime + evidence targeted：`77 tests`，`2 skipped`，`OK`；
- c_utils component/product targeted：`36 tests`，`OK`；
- 新模块 `py_compile`：通过；
- 全量 `unittest discover`：在整合完成后执行；
- `git diff --check`：执行前需清除 EOF 空白；
- 不 push、不创建 PR、不标 ready、不合并 main。
