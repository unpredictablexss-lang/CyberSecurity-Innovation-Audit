# OHScanner M1：固定 Git Commit 的源码索引与 Frontend 试点

> 当前状态：开发分支 `feat/ohscanner-core` / Draft PR #5 上的 M1 **代码实现**；真实 OpenHarmony 组件扫描实验需要在本地 Ubuntu/WSL 补跑。
>
> **非常重要**：`ohscan-index` 是“源码和 AST 索引命令”，不是漏洞扫描器。没有运行任何 Detector，也没有发现或确认漏洞；生成 `candidate_count: 0` 只能解释为本阶段没有运行检测器。

## 1. 实现了什么

| 层 | 路径 | 能力和限制 |
|---|---|---|
| Git 版本/范围 | `src/ohscanner/git_source.py` | 只读取本地 Git 的指定 full commit/tree/blob，无 checkout/fetch；过滤源码范围、跳过 symlink/submodule；内容大小有界 |
| Frontend | `src/ohscanner/frontend.py` | C/C++ 重用 `src/parser/ast.py` 中 Tree-sitter，返回函数、调用与变量概要；失败/partial 显式记录 |
| JS/ArkTS 占位 | 同上 | JS、TS、ETS 只记录路径/内容 hash，`parse_status=not_run`；**没有 JS/ArkTS AST、跨语言/IPC/权限分析** |
| 接口与报告 | `src/ohscanner/contracts.py` + `indexing.py` | 接入 M0 `ScanRequest` / `SourceUnit`，按固定 commit、tree、文件哈希输出 JSON/Markdown |
| Runner 兼容 | `src/ohscanner/runner.py` | 未来自研 Detector 可读 `ScanContext`；需要完整 AST 而某文件 partial 时直接 blocked；保留 M0 的模拟测试 |
| CLI | `src/cli/main.py` | 新增 `ohscan-index`，不覆盖原 `scan` 和 M0 `ohscan` |
| Tests | `tests/test_ohscanner_m1.py` | 在 CI 本地临时初始化 Git 仓库验证 SHA 固定、HEAD 变化、覆盖状态、文件跳过、CLI 与适配行为 |

Git 仓库名称是使用者提供的 `--repository` 字符串；当前不会向官方服务器验证远端归属。Git 对象身份、固定 SHA 与 tree/blob 范围在本地校验，但这不是 Gitee/OpenHarmony 官方身份背书。

## 2. Ubuntu / WSL 本地安装与复现

不需要启动 CodeQL、Semgrep、Clang Static Analyzer，也不需要构建整个 OpenHarmony 产品。本阶段只依赖 Python 3.10+、Git、仓库 Python 依赖。

在 Ubuntu 终端执行（仓库路径按实际位置替换）：

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

# 本仓库：从项目根目录执行
git fetch origin
git switch feat/ohscanner-core
git pull --ff-only origin feat/ohscanner-core
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -q

# M0 回归：只对合成样例执行两个 Mock
python -m src.cli ohscan \
  --fixture-root tests/fixtures/ohscanner \
  --json-out outputs/reports/ohscanner_m0.json \
  --md-out outputs/reports/ohscanner_m0.md
```

接着准备 OpenHarmony 的 c_utils **外部本地仓库**。如果你之前已在 WSL 中克隆该仓库，直接使用原目录；否则可以尝试：

```bash
mkdir -p ~/oh-audit-targets
git clone https://gitee.com/openharmony/commonlibrary_c_utils.git \
  ~/oh-audit-targets/commonlibrary_c_utils

# 试点使用的历史固定版本；必须在本地 Git 对象中存在
TARGET=~/oh-audit-targets/commonlibrary_c_utils
COMMIT=b807d3dadb7dbb7639fe85b3a5f72da18d318da2
git -C "$TARGET" cat-file -t "$COMMIT"
git -C "$TARGET" rev-parse "$COMMIT^{tree}"
```

若克隆站点不可访问，可以使用你已有的官方镜像 Git 仓库，但必须确认指定 commit 对象存在；若对象缺失，先在网络允许的环境正常 `git fetch`。不要为了让测试通过而把随意 HEAD 伪装为历史固定提交。**项目本身的索引命令不会 fetch。**

在**审计系统代码仓库根目录**运行：

```bash
python -m src.cli ohscan-index \
  --repo-dir "$TARGET" \
  --repository openharmony/commonlibrary_c_utils \
  --commit "$COMMIT" \
  --json-out outputs/reports/cutils_m1_index.json \
  --md-out outputs/reports/cutils_m1_index.md
```

也可以先对一个较小的目录试跑，例如加 `--include base`。多次 `--include` 可指定多个相对源码路径/目录，但文件总数不应超过 v1 的安全上限。对于大仓库应分组件运行，而不是直接尝试一次索引整个 OpenHarmony 源码树。

## 3. 结果怎么核对

```bash
python - <<'PY'
import json
p = "outputs/reports/cutils_m1_index.json"
r = json.load(open(p, encoding="utf-8"))
print("commit:", r["commit"])
print("git tree:", r["git_tree"])
print("source files:", r["scope"]["selected_source_files"])
print("languages:", r["coverage"]["languages"])
print("parse statuses:", r["coverage"]["parsing_status"])
print("skipped:", r["scope"]["skipped"][:10])
print("detector runs:", len(r["detector_runs"]))
print("validated vulnerability:", r["validated_vulnerability"])
PY
```

应检查：
1. commit 与你指定的一致、tree 真实存在；
2. 语言和实际文件范围相符；
3. C/C++ 的 `complete/partial/failed` 与 JS/ArkTS 的 `not_run` 有明确区别；
4. symlink/submodule/非 UTF-8/超过 1 MiB 的单文件有统计，不能默默计为已扫描；
5. `detector_runs` 为空，`validated_vulnerability=0` 不是安全结论。

请反馈运行时终端输出中的 commit、文件总数、parse statuses、skipped 数量；如果失败，请贴 **完整错误摘要和所用命令**（去除个人路径或私有信息）。不用上传全部第三方源码或大型工作产物。

## 4. 本阶段安全与覆盖边界

- 固定的是 Git commit/tree/blob 的本地对象，不是产品 manifest 的统一依赖锁；`--repository` 是使用者声明的目标身份；
- Git 源码对象与工作区文件独立；工作区的未提交变更不会进入 M1 报告；
- C/C++ 仅 Tree-sitter 语法层，无正式 GN 构建参数、宏展开、类型解析或路径敏感执行；
- `.h/.hh/.hpp` 暂按 C++ 解析，纯 C/条件编译头可能部分解析，后续按 TU/BUILD.gn 再改进；
- JS/TS/ArkTS 只是资源目录索引，不是实际语法覆盖；没有声称对 Web/IPC 具备漏洞检测；
- 超过 1 MiB 的单文件、总量超过 32 MiB、超过 2000 个文件将跳过/拒绝；不静默假称“全量扫描”；
- Runner 目前同步、未实现强制时间/内存隔离，因此不运行不受信任的检测器插件；
- 已有历史 benchmark 和第三方工具 Adapter 未被替换，更不能据此计算 Precision、Recall、FPR 或已验证漏洞数量。

## 5. M1 Done 条件与下一步

- [x] `ohscan-index` 完成固定 local Git SHA 输入和有界范围索引；
- [x] SourceUnit 与 ScanContext 对接已有接口；JS/ArkTS 不伪造 AST；
- [x] CI 临时 Git fixture 验证工作区/HEAD 变化不影响 pinned commit；
- [x] CI 验证路径范围、symlink、non-UTF8、超大文件和 partial parse；
- [ ] 在 **Ubuntu 本地真实 c_utils 固定提交** 上跑索引，记录文件数与语法覆盖率；
- [ ] 若真实源码触发解析性能/范围问题，记录并修复；
- [ ] 之后进入 M2：固定真实组件资产 + 首个队友自研 Detector + SourceUnit/AST 接口验收。

此阶段不把现有 `codex/cutils-component-pilot` 整体 merge 进来。可以将其作为真实组件参数/覆盖数对照，但本分支只迁移经过复核的共享底层思想。
