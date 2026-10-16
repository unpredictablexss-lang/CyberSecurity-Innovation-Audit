# 最小交付记录 — lanes.ipc

> 填充自 `research/coordination/parallel-20261017/DELIVERY_TEMPLATE.md`（模板本身未改动）。

## lane / branch / base full SHA / head full SHA

- lane `lanes.ipc`；branch `work/ipc-20261017`
- base `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- head：本记录所在提交（`work/ipc-20261017` 上本线唯一提交，未 push）
- worktree `/home/audit/ohscanner/worktrees/parallel-ipc-20261017`

## 选择性迁入来源提交、文件与依赖

**本次没有迁入来源代码。** 检测器一行未改。来源树
`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` @
`635b3e0449c552f0ccc25118850d245962845568`（`0.8.0` / `oh-ipc-2026.10-v6`）
只作**只读**运行与逐行核对，用于生成交付项 3 的实测数字与逐条触发链的 `file:line`。

**本线反而依赖 worktree 里另一会话尚未提交的 v0.8 import**（`src/ohscanner/detectors/interface/`
的 `families/`、`models.py`、`analysis.py`、`entry_index.py`、`detector.py`，
写入时间 02:57:44，`git status` 为 `M`/`??`）。本线新增的夹具与测试只依赖
`models.py` 的**具名常量表**与 `analysis.py` 的 emit 点；若该 import 被回退或改写，
夹具与测试会随之失败。这是依赖，不是本单元自身的缺陷。

## 问题触发条件、改动后行为

- **触发条件**：11 条目录规则里 3 条（`ipc.auth.caller-class`、`ipc.auth.identity-domain`、
  `ipc.parcel.position-underflow`）**没有任何正例控制**，即从未被证明能够触发；
  3 个家族（AUTH-01 / AUTH-03 / DATA-01）没有 `safe` 控制。
- **改动后**：11/11 规则有正例、6/6 家族有 positive+fixed+safe，且该不变量由
  `tests/test_ipc_family_depth.py` 机器校验（逐规则、逐家族，不是总数）。
- **同时量化了真实代码上的落差**：18 个组件 / 1.53M 行里只有 5 条规则命中过；
  AUTH-01 占 54/100 条候选，AUTH-03 仅 2 条，DATA-01 为 0。

## 修改文件、scope check 命令与真实输出

新增（全部只增不改检测逻辑）：

```text
research/deliveries/ipc/20261017-v080-dependency-inventory.md
research/deliveries/ipc/20261017-six-family-depth-unit.md
research/deliveries/ipc/20261017-six-family-component-measurement.md
research/deliveries/ipc/20261017-lane-delivery-record.md      (本文件)
research/evidence/interface/ipc/component_audit_20261017/     (components.json, index.json, 18×manifest)
research/methods/interface/IPC_METHOD_CARD.md                  (+68 行，仅新增一节)
tests/fixtures/ipc/auth01/                                     (manifest + 1 cpp)
tests/fixtures/ipc/auth03/                                     (manifest + 5 cpp)
tests/fixtures/ipc/data01/                                     (manifest + 3 cpp)
tests/test_ipc_family_depth.py                                 (12 项测试)
```

```console
$ .venv-web/bin/python scripts/check_change_scope.py \
    --base 6a41dc9b1aa030158e09be6241e2b14341f9256d --lane ipc
  "violations": []
```

## 公共接口申请

**无。** 未改 `contracts.py`、`runner.py`、`catalog.py`、`analysis.py`、`models.py`、
`src/report/`、`src/case/`、`src/benchmark/`、`src/evidence/`。夹具走既有的
`tests/fixtures/ipc/<family>/` 家族目录约定，由**他人**已存在的
`tests/test_ipc_family_matrix.py::FamilyFixtureMatrixTests` 自动接管。
需要集成人另开请求的一项：共享 `tests/fixtures/ipc/manifest.json` 的
`account_role_authorized_fixed` 行（见末节"下一项"）。

## exact argv、环境版本、通过/失败/skipped 与原因、日志和哈希

```console
$ .venv-web/bin/python -m unittest discover -s tests -q
Ran 568 tests in 24.338s
FAILED (failures=2, skipped=4)

$ .venv-web/bin/python -m unittest tests.test_ipc_family_depth tests.test_ipc_family_matrix -v
Ran 25 tests ... OK
```

两个失败**不是本单元引入**，且与交付项 1 §3.1 的预判逐字一致 —— 并发 import 把来源树的
覆盖侧车断言照抄成 `'blocked'`，本基线 `runner.py:119-131/250-255` 在无 `file_outcomes`
时给出 `'partial'`：

```
tests/test_ipc_detector.py:61  AssertionError: 'partial' != 'blocked'
tests/test_ipc_detector.py:168 AssertionError: 'partial' != 'blocked'
```

本基线上应保留 `'partial'`，该文件属并发 import，本线未改。

4 项 skip 为既有跳过，与本单元无关。实测运行的 argv 与 18 份报告哈希见
[交付项 3](20261017-six-family-component-measurement.md) 与 `components.json` 的
`report_sha256`。

## 固定目标 repo/commit/tree/blob/source SHA、scope/profile、detector/model 版本

- detector `ohscanner.interface.ipc` `0.8.0`；model `oh-ipc-2026.10-v6`；
  驱动 `src/ohscanner/detectors/interface/audit.py`，来源树 HEAD `635b3e0`
- 18 个组件逐仓库 `rev-parse HEAD` 现场固定，清单见交付项 3 §1；
  scope = 驱动默认（production-only，`//production-segment:test|tests|unittest|fuzz|mock|sample|example|demo|benchmark|third_party|3rdparty` 排除），
  **头文件在范围内**
- 候选身份：`source_sha256` + `rule_version` + `interpretation_id` + `observed_detector_versions`
- 目标仓库必须 `git status --porcelain` 干净才跑；脏树记 `dirty` 跳过

## positive/fixed/safe/unrelated 与 holdout 是否独立

- 三件控制齐全（positive + fixed + safe），且按家族各自持有；不存在"借用别家负证据"。
- `unrelated`：`caller_class_unreviewed_name_safe.cpp`、`position_underflow_safe.cpp`、
  `relay_unreviewed_call_safe.cpp` 是**不相关形状**控制（不触发目标规则、也不触发别的规则）。
- **不是独立 holdout。** 夹具是为规则手工写的同源设计样例，作者知道规则逻辑；
  18 个真实组件是独立的真实代码，但**没有标签**，因此只能报候选数，不能算 P/R。
  任何"零 FP/FN"的说法都不成立。

## 候选移动的逐项原因，candidate/confirmed/unknown 的证据边界

本线**没有改动任何规则**，因此**候选集零移动**：18 个组件、1.53M 行上的 100 条候选
全部来自未改动的 `0.8.0` 检测器。全部 100 条保持 `candidate`（`unassessed`），
`confirmed_vulnerabilities` 按构造为 0。**零候选不代表组件安全；候选不等于漏洞。**

一处**数字上的移动**必须区分清楚：`window_window_manager` 曾被读作 0 候选，
那是**失败运行的残留报告**（`shard_errors: [ValueError: invalid declared repository name]`，
`files_not_analyzed: 1069`），重跑后为 10 条。这不是候选移动，是**把一个非测量纠回测量**。

## 旧报告、候选 ID、人工复核的兼容性

- 未改任何历史报告、候选 ID 或复核记录；未改 `detector.py` 的 `detector_id` /
  `interpretation_id`，因此新旧候选身份不冲突。
- 前几轮（v0.8 卡片记录的 41 条复核、WWM 14 条、sat/update 5 条）是在**其他 model 版本**
  下得到的，与本表的 100 条**不可直接比较**，本次未做归并，也未重跑那些组件。

## 未验证、阻塞、下一项

1. **形状普查（未做）** —— 区分"这 6 条规则不能触发"与"语料里没有这些形状"，
   需要在语料里数 `caller_class_sensitive_calls` 的具名调用、`RewindRead(<expr>)` 的减法、
   `result_permissions` 的实参个数。这是把 AUTH-03/DATA-01 对齐 AUTH-01 的**下一步**。
2. **机制字段（未做）** —— AUTH-01 有具名机制结果（`descriptor_identity` 等），
   AUTH-02/03/04、CAP-01、DATA-01 的候选仍只能靠 `message` 文本区分，没有可断言的字段。
   需要改 `analysis.py` / `models.py`，属并发 import 正在写的文件，本线未抢。
3. **共享 manifest 一行需集成人裁决** —— `tests/fixtures/ipc/manifest.json` 的
   `account_role_authorized_fixed`：并发 import 把它从"必须零候选"改成断言
   `ipc.auth.missing`，却保留 `variant: "fixed"` 与已失效的 `notes`。
   `matrix()` 只按 `expected_rule` 分支、且**全测试集无人读 `variant`**，所以这次改写不会被任何测试发现。
   本线把 `variant` 改为 `positive` 并把 `notes` 补正（不改任何检测行为），
   并在 `test_ipc_family_depth.ManifestContractTests` 里第一次给该字段加上约束。
   **该文件同时含并发 import 新增的 18 行，故本线未提交它**，留给集成人；
   若要保留为真正的负控制，需让它走显式 policy 路径（该行自带 `policy_context` 已指向此方案）。
4. **未做的动态验证 / PoC** —— 本交付只到静态候选与测量，无 PoC、无动态验证。

## 本地提交完成；push/merge/Ready 需另有明确授权

- 仅本地提交到 `work/ipc-20261017`；**未 push、未开 PR、未标 Ready、未 merge**。
- 只提交上列"新增"清单中的本线自有路径；**不提交**并发 import 的
  `src/**`、`tests/test_ipc_detector.py`、`tests/test_ipc_entry_index.py`、
  `tests/test_ipc_family_matrix.py`、`tests/test_ipc_integration_safety.py`、
  `tests/fixtures/ipc/*.cpp`（`account_role_*` / `helper_preproc_*` / `onehop_*` /
  `relay_lookahead_*` / `role_predicate_*`）与共享 `tests/fixtures/ipc/manifest.json`
  ——其 dirty 状态被保留。
- **本提交不能单独检出运行 —— 这是实测结论，不是推测。** 在 `d45e602` 的独立
  `git worktree` 检出上跑 `tests.test_ipc_family_depth`：

  ```text
  ImportError: cannot import name 'families' from 'src.ohscanner.detectors.interface'
  ```

  因为本线的家族目录约定（`Family.fixture_dir`）、`families.registry()`、
  `family_of_rule()` 全部来自并发 import 的 **`src/ohscanner/detectors/interface/families/`**，
  而它是**未跟踪**目录、不在本提交内；`tests/test_ipc_family_matrix.py`（家族目录的
  既有入口）同样未跟踪、不在本提交内。**集成顺序必须是 import 先落、本单元后落**，
  或由集成人把两者并入同一批。
- 本线新增的 3 个家族目录与 12 项测试对**基线**（`6a41dc9`）的共享 manifest 是自洽的
  （已逐一核对）：基线的 48 行里 AUTH-01/AUTH-03/DATA-01 缺 `safe`，由本线家族目录补齐；
  基线 48 行的 `variant` 与 `expected_rule` 一致、`family` 与 `family_of_rule()` 一致，
  正例覆盖 8/11 条规则，本线补上其余 3 条后正好 11/11。
  **但这只在 `families/` 包存在时才成立**，所以它不构成"可单独检出"。
