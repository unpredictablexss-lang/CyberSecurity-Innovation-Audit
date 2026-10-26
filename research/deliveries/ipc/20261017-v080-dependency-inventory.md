# 交付项 1：v0.8.0 六家族组合相对本线旧 IPC 实现的依赖清单（2026-10-17）

本线：`lanes.ipc`，worktree `/home/audit/ohscanner/worktrees/parallel-ipc-20261017`，
分支 `work/ipc-20261017`，基线 `6a41dc9b1aa030158e09be6241e2b14341f9256d`。
被迁入来源只读固定：`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`，
分支 `feat/interface-ipc-detector`，HEAD `635b3e0449c552f0ccc25118850d245962845568`
（该工作树 `git status` 只有 ` M PROGRAM_STATUS.md`，是本会话 Phase 1 写的记录，本清单不改它）。

任务单 [B_IPC.md](../../../research/coordination/parallel-20261017/B_IPC.md) 要求先做依赖清单再选择性迁入。
本文件即该清单；**第二交付（实际迁入）在 `20261017-v080-family-migration.md`**。

---

## 0. 一句话结论

来源不是"更新的同名文件"，而是**另一条血缘的分支**。目标基线在 `contracts.py` / `runner.py` /
`execution.py` 三个负责人共享面上**比来源更新**，所以本次是**按依赖顺序的移植**，
不是目录覆盖；且来源的两条测试断言（sidecar 状态 `blocked`）在本基线**必须改写为 `partial`**。

---

## 1. 文件级对照（`src/ohscanner/detectors/interface/`）

| 文件 | 基线 | v0.8.0 | 差异 | 处置 |
|---|---:|---:|---|---|
| `__init__.py` | 1 | 1 | sha256 相同 | 不动 |
| `cpp_macros.py` | 322 | 322 | sha256 相同 | 不动 |
| `analysis.py` | 1118 | 1736 | +646 / -28 | 拆为 U5a–U5h 迁入 |
| `entry_index.py` | 1098 | 1298 | +208 / -8 | U4 |
| `models.py` | 166 | 222 | +57 / -1 | U1 |
| `detector.py` | 152 | 161 | +14 / -5 | U3 |
| `families/`（7 个模块 434 行） | 不存在 | 新增 | 全新 | U2 |
| `audit.py`（1522 行） | 不存在 | 新增 | 全新 | U6 |
| `m2_adapter.py` | 58 | 不存在 | 仅基线有 | **不删**，见 §5 |

来源侧其余引用面：`research/experiments/interface/ipc/review_descriptor_rule.py` 与
`review_delegated_descriptor.py` 从 `.audit` 导入；`tests/test_component_audit.py`（843 行）同样。
这三者都**不在本线允许范围**（见 §5），不迁。

---

## 2. 版本口径（迁入会改候选身份，必须一起记账）

| 口径 | 基线 | v0.8.0 |
|---|---|---|
| `IpcInterfaceDetector.version` | `0.5.0` | `0.8.0` |
| `models.MODEL_VERSION` | `oh-ipc-2026.10-v3` | `oh-ipc-2026.10-v6` |
| 已注册 detector id | `ohscanner.interface.ipc`（经 `m2_adapter.M2IpcInterfaceDetector`） | 同 |
| 变体 id | `ohscanner.interface.ipc.complete-ast`，`interpretation_id` 两者相同 | 同 |

`MODEL_VERSION` 与 `version` 都进 `diagnostic_id` 之外的持久化身份与覆盖侧车，所以六家族组合前后
**同一固定源/范围的候选差异必须逐项解释**（验收要求）。当前基线的六家族已经存在（见 §4），
所以本次迁入**不是**"从零加家族"，而是**同一批规则换一套解释**。

---

## 3. 共享面差异：基线更新，来源更旧（本次移植的主要风险源）

| 共享文件 | 方向 | 事实 |
|---|---|---|
| `src/ohscanner/contracts.py` | 基线更新 | 来源在 `DetectorRun.__post_init__` 加了 `completed` 不得含非 `complete` 文件结局；基线已删该约束，改为"执行完成度与逐文件分析深度互相独立"。基线**更宽松**，来源的 adapter 仍合法 |
| `src/ohscanner/runner.py` | 基线更新 | 基线有 contract v2 源绑定（`_bind_source`/`_source_bindings`）、`coverage_counts`、`coverage_semantics`、`source_binding` 块、`analysis_status: failed`、`INCOMPLETE COVERAGE` 限制；来源没有 |
| `src/ohscanner/execution.py` | 基线更新 | 基线有 `files_in_scope_without_a_claiming_detector` 与 6 列报告表；来源是 5 列旧表 |
| `src/ohscanner/fixture.py`、`src/parser/ast.py` | 相同 | sha256 一致，测试可原样迁移 |

### 3.1 由此产生的一条必须改写、不能照抄的断言

来源 `tests/test_ipc_detector.py` 两处把覆盖侧车的 detector 状态从 `'partial'` 改成 `'blocked'`：

```
- self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'partial')
+ self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'blocked')
```

来源改成 `blocked` 是因为它那边的 runner 只在**显式 `file_outcomes`** 里认 partial，
没有 `file_outcomes` 的 blocked 运行 `analyzed`/`partial` 都算空集。本基线相反：
`runner.py:119-131` 在没有 `file_outcomes` 时把 `set(analyzed_files) - completed` 记成
`partly_inspected`，`runner.py:250-255` 于是给出 `partial`。

**结论：本基线上该断言保留 `'partial'`。** 这是共享面演进的结果，不是规则行为差异；
照抄会让两条测试失败，且掩盖不了任何检测器问题。已复核的两个单元：
`test_partial_source_is_recorded_not_missed`、`test_partial_source_keeps_diagnostics_and_blocks_completion`。

---

## 4. 迁入单元（按依赖顺序，每个单元可独立复审与回滚）

依赖方向：U1 → U4 → U2 → U3 → U5\*；U6 依赖 U2/U3。

### U1 · `models.py`：服务账户角色与评审过的调用方角色谓词
- 新增 `ServiceAccountRole` dataclass（`constant` / `uid` / `role` / `accepted_operations` / `origin`）。
- 新增 `IpcPolicy.caller_role_guards: Tuple[Tuple[str, str, str], ...]`（9 条具名谓词）。
- 新增 `IpcPolicy.service_account_roles: Tuple[ServiceAccountRole, ...] = ()`（默认空，由家族补）。
- `MODEL_VERSION` v3 → v6。
- **无新 import**。这是"账户不是权限"这条判断落地的地方：`trusted_uids` 不动。
- 验证：`python -m unittest tests.test_ipc_disclosure_consequence -q` 不回归；
  新增断言 `IpcPolicy().service_account_roles == ()` 且 `trusted_uids` 与 v3 一致。

### U4 · `entry_index.py`：常量定义表 + 一跳实现体查找
- `ConstantDefinition` dataclass；`_constants` 表；`_record_constant`（只认 `const`/`constexpr`
  + 字面量初始化，链式定义不追）；`_record_macro(..., path=)` 补文件/行号。
- `define_constant(name, near_file)`：同文件优先；多定义**值不一致**时记 limitation 并返回 `None`
  （`None` = 未建立，不是"定义为空"）。
- `_literal_value_text` / `_literal_value` / `_scope_prefix`（`Ns::Class::NAME` 引用用）。
- `_Func.ref_params`：只收非 const 左值引用形参（`const` 出现在整个形参声明里就排除）。
- `one_hop_definition(owner, name)`：唯一实现体才返回；`Base` 自己也定义同名则记
  `One-hop callee is not unique` 并返回 `None`。
- `self.policy = merge_policy(policy)`（依赖 U2）。
- **`_parents` / `_text` / `_last_component` / `_last_identifier` 基线已有**，不需要迁。
- 验证：`tests.test_ipc_entry_index -q`；新增 `define_constant` / `one_hop_definition` 的正/负控制。

### U2 · `families/` 包（家族组合与校验）
- `Family` dataclass + `registry()` / `family_of_rule()` / `cwes()` / `merge_policy()` /
  `default_policy()`；import 时即校验。
- 严格校验：`RULES` 必须**恰好分割** `models.IMPACT_BY_RULE`（11 条）；
  家族 id/CWE 形状/fixture 目录名；**两个家族不得给同一 `IpcPolicy` 字段加同一个值**；
  `merge_policy` 幂等；标量字段不许家族追加。
- 六个家族模块：`auth01`（1 规则）、`auth02`（1 规则 + `POLICY.service_account_roles`）、
  `auth03`（5 规则）、`auth04`（1 规则）、`cap01`（1 规则）、`data01`（2 规则）= 11 条，与目录对齐。
- `__main__.py`：`python -m src.ohscanner.detectors.interface.families` 打印家族表 + 生效策略差异。
- **基线已满足分割前提**（6 家族 id + 11 规则的 `_CWE` 与 `IMPACT_BY_RULE` 已一致），
  所以这一单元是纯新增，不改任何规则行为。
- 验证：`tests/test_ipc_family_matrix.py`（248 行，从来源迁入，改名保持 `tests/test_ipc_*.py` 命名约束）。

### U3 · `detector.py`：CWE 表改由家族提供 + 策略合并 + 请求透传
- `_CWE = cwes()` + `assert set(_CWE) == {六家族}`（原来是一张手写字面量）。
- `version` `0.5.0` → `0.8.0`。
- `self.policy = merge_policy(policy)`（手搭 policy 也吃到家族事实）。
- `Interpreter(applicable, self.policy, context.request)`：`ScanContext.request` 基线**已有**，
  无共享面改动；用途只有一个 —— 让服务账户记账能写出 `repository@commit` 目标。
- `IpcInterfaceCompleteAstDetector` 不动。

### U5 · `analysis.py`：拆成 8 个互不依赖的小单元

| 单元 | 内容 | 依赖 | 断言方式 |
|---|---|---|---|
| U5a | 格式宏正则：加 `SCN…` 宽度族，并接受"字面量结尾"（`"…%{public}" PRIu32,`） | 无 | 三种形状 `parses_raw` 为假 → `parses_clean` 为真；四条对照原样返回 |
| U5b | 函数体内的 `#if/#ifdef/#elif/#else` 按臂展开，无 `#else` 保留"无臂"路径 | 无 | 五个 `helper_preproc_*` 夹具 |
| U5c | helper 返回摘要按返回值带事实（`_returns_true` / `_returned_fact`） | 无 | `helper_preproc_guard_fixed` 抑制、`helper_preproc_log_only_positive` 保留 |
| U5d | `_Suspended` + `lookahead()` 上下文管理器（前瞻期挂起 emit/limitations/权限记账） | 无 | `relay_lookahead_declaration_fixed`：无 `auth.missing`/`guard-coverage`，仍有 `relay.descriptor-boundary` |
| U5e | 一跳跨 TU 虚拟派发：`one_hop_dispatch` / `dispatch_guard` / `bind_result` / `_decisive` / `_where`；`action(guard=...)` 只扣 AUTH-02 与 CAP-01；索引的 `not unique` 拒绝上浮为 limitation | U4、U5d | `onehop_guard_fixed` + 4 条反向控制 + `onehop_not_unique_positive` |
| U5f | 服务账户角色：`State.service_account` 通道、`account_role` 三条件（调方 UID / 具名常量 / 源码绑定值）、`authorized` 按操作收口、`refine` 的 `account→service_account` 映射、记账与拒绝各一行 | U1、U2、U4 | `account_role_authorized_fixed` + 4 条控制（错值 / TokenID / 请求值 / 未列操作） |
| U5g | 评审过的调用方角色谓词按名生效，**仅在本文件未自行定义该名时**；`note_shadowed_role_predicate` 记录同名遮蔽（含定义行号） | U1、U4 | `role_predicate_shadowed_positive` + `helper_preproc_guard_fixed` 反侧 |
| U5h | `AsObject()` 透传持有值（仅 `call_result`），使 CAP-01 能与产生它的那次调用对齐 | 无 | `onehop_guard_fixed` 的抑制依赖它 |

`State` 增字段 `service_account`；`Function` 增 `ref_params` / `line`；这些随上述单元一起进。

### U6 · `audit.py`（组件审计驱动）
- 固定组件 → scope 规划、确定性分片、两遍（`complete-ast` / `all-files`）、覆盖表与候选渲染。
- 不改公共契约；产物出 Git。
- 来源的测试文件名 `tests/test_component_audit.py` **不在本线允许范围**（见 §5），
  迁入时改名为 `tests/test_ipc_component_audit.py` 以满足 `tests/test_ipc_*.py`。
- 依赖：U2/U3 之后的 detector；**不与 U1–U5 抢同一文件**，可最后做。

### U7 · 测试与夹具
- 差异：`tests/test_ipc_detector.py`（135→365）、`tests/test_ipc_entry_index.py`（515→606）
  **有改动**；`descriptor_identity` / `relay_guard` / `macros` / `disclosure_consequence`
  四者 sha256 与来源相同，不动。
- 新增夹具 19 个 `.cpp` + `manifest.json` 补 18 条（其中 `relay_lookahead_declaration_fixed.cpp`
  只在测试里按文件名引用，不入 manifest —— 来源如此，迁入时保持，并在交付里说明）。
- 基线 IPC 测试现状（迁入前实测）：`tests.test_ipc_detector` + `entry_index` +
  `descriptor_identity` + `relay_guard` + `macros` + `disclosure_consequence` = **98 项 OK**。

---

## 5. 明确不迁的部分（范围/所有权）

| 项 | 理由 |
|---|---|
| `src/ohscanner/detectors/catalog.py` | `shared_owner_only`。`ohscanner.interface.ipc` 已注册，六家族组合经 `m2_adapter` → `IpcInterfaceDetector` 自动生效，**无需改注册表** |
| `src/ohscanner/detectors/interface/m2_adapter.py` | 基线独有且是注册路径的一部分，**不删不改** |
| `contracts.py` / `runner.py` / `execution.py` | 负责人共享面。本次不需要改（§3 已说明基线更宽松） |
| `research/experiments/interface/ipc/review_*.py` | 不在 `lanes.ipc.allowed`（允许的是 `research/corpus/ipc`、`methods/interface`、`evidence/interface`、`poc/auth01_minimal_loop`、`deliveries/ipc`） |
| `tests/test_component_audit.py` | 不在允许 glob；改名迁入（见 U6） |
| `src/ohscanner/poc/**` | 不在允许范围；AUTH-01 的 PoC 框架归负责人/研究面 |

---

## 6. 六家族深度差（第二阶段的量化入口）

来源 `tests/fixtures/ipc/manifest.json` 按家族统计（`variant` = positive/fixed/safe）：

| 家族 | 规则数 | 夹具 | positive | fixed | safe | 未被任何夹具覆盖的规则 |
|---|---:|---:|---:|---:|---:|---|
| AUTH-01 | 1 | 23 | 17 | 6 | 0 | — |
| AUTH-02 | 1 | 18 | 12 | 4 | 2 | — |
| AUTH-03 | **5** | **7** | 4 | 3 | 0 | **`ipc.auth.caller-class`、`ipc.auth.identity-domain`** |
| AUTH-04 | 1 | 6 | 4 | 1 | 1 | — |
| CAP-01 | 1 | 9 | 6 | 2 | 1 | — |
| DATA-01 | **2** | **3** | 2 | 1 | 0 | **`ipc.parcel.position-underflow`** |

相对基线的增量也集中在这里：AUTH-02 +12、CAP-01 +6，**AUTH-03 / AUTH-04 / DATA-01 增量均为 0**。

"和子类一（AUTH-01）同等水平"在本清单里落成可检查的形态：

1. **每条规则至少有正/定/负三类控制**，而不是只有 positive；
2. **机制层有具名判定结果**（AUTH-01 的 `descriptor_identity ∈ {accepted, mismatch, unresolved}` 是样板），
   拒绝理由作为独立 EvidenceObligation 与 limitation 出门，而不是退化成"没有守卫"；
3. **两侧控制都要断言**（扣了什么 / 保住了什么）；
4. **真实组件实测**（AUTH-01 有 camera / imf / window 的固定提交测量），其余家族目前只有合成夹具；
5. 方法卡各一节。

`tests/test_ipc_family_matrix.py::FamilyFixtureMatrixTests.test_a_family_directory_holds_that_family_only`
已经预留了按家族目录 `tests/fixtures/ipc/<family>/manifest.json` 的入口 —— 补深度时用它，
不必往共享 manifest 里堆。

---

## 7. 迁入顺序与验收命令（从仓库根、精确 argv）

```bash
cd /home/audit/ohscanner/worktrees/parallel-ipc-20261017
.venv-web/bin/python -m unittest tests.test_ipc_detector tests.test_ipc_entry_index \
  tests.test_ipc_descriptor_identity tests.test_ipc_relay_guard tests.test_ipc_macros \
  tests.test_ipc_disclosure_consequence tests.test_ipc_family_matrix -q
.venv-web/bin/python -m unittest discover -s tests -q
.venv-web/bin/python -m scripts.check_change_scope \
  --base 6a41dc9b1aa030158e09be6241e2b14341f9256d --lane ipc
```

（`-I` 不用：验收要求不得借 `-I` 隐藏导入问题。）
