# A-NULL-02 real fixed-component review delivery

日期：2026-10-16。范围只包括 A 线 NULL dereference Detector、家族 Harness、控制、
方法卡和未实施的 Catalog metadata 建议；未修改公共 contracts、runner 或 catalog。

## Checkout 与固定对象

- OHScanner checkout：branch `codex/full-runtime-performance-audit-20261014`，
  full HEAD `8e97f152ef747c1e1d21ae179a048910f147e07a`，
  HEAD tree `e50c111e3b487b048e8807dafe06625a87f296ad`，
  remote `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`。
- 目标仓库：`E:\网安\_wsl_targets_stage\communication_dsoftbus`，remote
  `https://github.com/openharmony/communication_dsoftbus.git`，当前 HEAD
  `0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`，worktree clean。
- 分析只读取 pinned objects，不 fetch/checkout。vulnerable/fixed commit、tree、blob、
  source SHA-256、snapshot SHA-256 与 `light-ast` profile 见
  `replay_results.json` 和 `catalog_metadata_suggestion.json`。

## 真实候选复核表

| root-cause group | sites | source relation | guard/error-path | alias/rebind | fixed relation | label |
|---|---:|---|---|---|---|---|
| `A-NULL-02-RC-NOTHROW-CLIENTPROXY-ALLOC` | 5 | `new (std::nothrow) BusCenterClientProxy` -> `clientProxy->...` | vulnerable 无前置 guard | 无已识别同函数 alias；source/sink 间无局部重绑定 | 五处均新增 `if (clientProxy == nullptr)` + early-return shape | `plausible_unproven` |

五处精确关系为 L70→L71、L81→L82、L96→L97、L107→L108、L122→L123。完整函数名、
source/sink/fixed guard 行、AST/source binding、finding identity 和义务状态见
`candidate_review.md` 与 `replay_results.json`。

漏洞计数采用独立根因组：`independent_root_cause_count=1`、
`candidate_site_count=5`、`validated_vulnerability=0`。不得按五行告警报告五个漏洞。

## 根因和误报分析

- 根因假设是同一 `nothrow` allocation family 在同一构造器和同类 immediate pointer
  sink 前缺少局部 null guard；fixed commit 使用同一 guard/error-path repair shape。
- 19 个 synthetic controls 的结果为 positive 6/6 稳定保留、fixed 5/5 为 0、
  safe 4/4 为 0、unrelated 4/4 为 0，`likely_false_positive=0`。
- fixed counterparts 仅将局部 missing-guard relation 标为 `refuted`，不证明产品安全。
- `new (std::nothrow)` 以前会被误当作未知 return value 或非空初始化；rule `1.2.0`
  将其建模为 `may_be_null` source，并防止初始化 assignment 误触发非空重绑定。
- 有限 synthetic controls 不能计算 Precision/Recall，不支持 zero FP/FN。

## Review 标签

- 5 个 vulnerable sites：`plausible_unproven`。
- 5 个 fixed local relations：`refuted`。
- 1 个产品升级门：`insufficient_evidence`。
- fixed/safe/unrelated 噪声：`likely_false_positive=0`。

## 方法卡和 Catalog 建议

- 方法卡已修订：`research/methods/cpp/NULL_DEREFERENCE_METHOD_CARD_V2.md`。
- `research_candidate` metadata 建议：
  `research/evidence/cpp/a_null_02_fixed_component_review_20261016/catalog_metadata_suggestion.json`。
- 建议绑定 detector `0.2.0`、rule `1.2.0`、CWE-476、C/C++、per-file、light-ast、
  complete/partial/failed/not_analyzed coverage、默认 severity/confidence `unassessed`。
- 建议未实施；`src/ohscanner/detectors/catalog.py`、公共 contracts 和 runner 均未修改。

## 未验证、unknown 和不得升级理由

- 未验证真实产品入口/权限边界、攻击者控制、allocation failure 触发条件和部署 trace。
- 未绑定产品构建、完整宏/模板实例化、跨函数 alias/CFG、并发或 destructor/exception 语义。
- 未证明可达敏感操作或具体 CIA impact；未运行产品 PoC、修复产品重验或 CVE 流程。
- historical sample、advisory/CVE 和 fixed commit 只作 candidate index/context，不能作为
  detector truth 或升级证据。
- AST/pattern 关系不证明 guard dominance、ownership、attacker control 或 CIA impact。
- 因此保持 `candidate/unassessed`、`validated_vulnerability=0`，不得标记
  `confirmed/reportable`，不得声称产品漏洞数、Precision/Recall、zero FP/FN 或产品安全。

## 验证记录

- 定向回归：`PYTHONPATH=.:tests .venv-web/bin/python -m unittest tests.detectors.test_cpp_null_dereference_detector tests.detectors.test_cpp_null_dereference_signal_controls -v`。
  实际在 WSL2 Python 3.10 环境执行等价命令；19 executed / 19 passed / 0 failed /
  0 errors / 0 skipped，见 `targeted_test_run.txt`。
- 控制 manifest：19 fixtures passed，见 `control_manifest_check.txt`。
- 固定组件 replay：1 root-cause group / 5 candidate sites，完整 JSON 跨 replay 一致，
  见 `replay_check.txt`。
- 文档预算：`default=10615/13500`、`docs=16953/32500`，通过，见
  `docs_context_budget.txt`。
- `git diff --check`：exit 0；仅记录 Git 的 LF/CRLF advisory，无 whitespace error，
  见 `git_diff_check.txt`。
