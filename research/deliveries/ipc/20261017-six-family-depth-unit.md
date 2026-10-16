# 交付项 2：六家族逐规则控制补齐（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **worktree**：`/home/audit/ohscanner/worktrees/parallel-ipc-20261017`
- **规则来源（只读固定）**：`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`，
  分支 `feat/interface-ipc-detector`，HEAD `635b3e0449c552f0ccc25118850d245962845568`
- **本文件对应的提交**：`research/methods/interface/IPC_METHOD_CARD.md` 的家族小节、
  `tests/test_ipc_family_depth.py`、`tests/fixtures/ipc/{auth01,auth03,data01}/`
- 第一交付（依赖清单）见 [20261017-v080-dependency-inventory.md](20261017-v080-dependency-inventory.md)

---

## 0. 一句话结论

11 条规则里有 **3 条从来没有正例控制**（`ipc.auth.caller-class`、`ipc.auth.identity-domain`、
`ipc.parcel.position-underflow`），3 个家族 **没有 safe 控制**（AUTH-01 / AUTH-03 / DATA-01）。
本次把这两处补齐，并把"逐规则控制"变成机器可检的不变量；过程中发现并发 import 把 AUTH-02 的
**一条负控制静默转成了正控制**（见 §5）。

## 1. 改动清单（只新增文件，不改任何检测逻辑）

| 文件 | 内容 |
|---|---|
| `tests/fixtures/ipc/auth03/manifest.json` + 5 个 `.cpp` | caller-class 正/定/safe 三例；identity-domain 正/定最小对 |
| `tests/fixtures/ipc/data01/manifest.json` + 3 个 `.cpp` | position-underflow 正/定/safe 三例 |
| `tests/fixtures/ipc/auth01/manifest.json` + 1 个 `.cpp` | AUTH-01 的 safe 控制 |
| `tests/test_ipc_family_depth.py` | 12 项测试：逐规则精确候选集、最小对、两个不变量、`variant` 契约 |

按家族目录归档，因此**被既有** `tests/test_ipc_family_matrix.py::FamilyFixtureMatrixTests`
**自动接管**（目录名即家族、null 期望即"零候选"、必须 `completed`），不需要新测试入口、
不需要改共享 `tests/fixtures/ipc/manifest.json`、不需要改 `analysis.py` / `models.py`。

## 2. 逐规则控制矩阵（本次前 → 后）

`positive` = 断言目标规则命中；`fixed` / `safe` = 断言**候选集为空**。

| 规则 | 家族 | 本次前 | 本次后 |
|---|---|---|---|
| `ipc.relay.descriptor-boundary` | AUTH-01 | 17 正 / 6 定 / **0 safe** | +1 safe |
| `ipc.auth.missing` | AUTH-02 | 12 正 / 4 定 / 2 safe | 不变 |
| `ipc.auth.caller-class` | AUTH-03 | **无任何控制** | 1 正 / 1 定 / 1 safe |
| `ipc.auth.identity-domain` | AUTH-03 | **无任何控制** | 1 正 / 1 定 |
| `ipc.auth.object-owner` | AUTH-03 | 1 正 | 不变 |
| `ipc.auth.service-identity` | AUTH-03 | 2 正 | 不变 |
| `ipc.auth.request-identity` | AUTH-03 | 1 正 | 不变 |
| `ipc.auth.guard-coverage` | AUTH-04 | 4 正 / 1 定 / 1 safe | 不变 |
| `ipc.capability.export` | CAP-01 | 6 正 / 2 定 / 1 safe | 不变 |
| `ipc.parcel.copy-range` | DATA-01 | 2 正 / 1 定 / **0 safe** | 不变 |
| `ipc.parcel.position-underflow` | DATA-01 | **无任何控制** | 1 正 / 1 定 / 1 safe |

AUTH-03 原本 5 条规则只覆盖 3 条、DATA-01 原本 2 条只覆盖 1 条；现在 11/11 都有正例。

## 3. 三条新控制的触发链（源码位置，pinned `635b3e0`）

**`ipc.auth.caller-class`** —— `models.py:167` 的 `caller_class_sensitive_calls` 是 6 个**具名**
调用（`GetPermissionUsedRecordsAsync`、`SetMutePolicy` 等）；交出一个 `caller_class` 事实的只有
`models.py:175-188` 的 `caller_role_guards`（`IsSystemAppCalling`、`IsSystemCalling`、
`IsNativeProcessCalling` …）。判定在 `analysis.py:1035`。正例只有权限检查、没有角色谓词；
定例只多一行 `if (!IPCSkeleton::IsSystemAppCalling()) return -1;`。

**`ipc.auth.identity-domain`** —— `result_permissions`（`models.py:158`）是
`{VerifyAccessToken, VerifyNativeToken}`；`analysis.py:1366-1369` 仅在实参是**调用方 UID**
（`caller_uid_calls` = `GetCallingUid` / `GetCallingUID`）时记 identity-issue。
注意一条**耦合**：同一段代码把 `subject` 改写成 `caller_uid`，于是 `analysis.py:1396` 的
"caller 授权谓词"分支不再成立 —— 也就是说**用错身份域的检查不会同时被当作授权**。
所以该正例产出 3 条候选（`guard-coverage` + `identity-domain` + `missing`）而不是 1 条；
这不是缺陷，这一点已固定进断言（`test_the_identity_domain_positive_also_loses_its_permission_credit`），
并且定例（`GetCallingUid()` → `GetCallingTokenID()`，仅此一行不同）降为 0 候选。

**`ipc.parcel.position-underflow`** —— `GetDataSize()` 在对 parcel 接收者上产出 `parcel_size`
（`analysis.py:1287-1288`）；只有 `RewindRead(<表达式>)` 会触发 `check_subtractions`
（`analysis.py:1289-1290`）；配对判据是 `size_lower` / `upper`（`analysis.py:1478`）。
正例 `RewindRead(data.GetDataSize() - pos)` 的下界对缺失 → 命中；定例加一行
`if (pos < 0 || data.GetDataSize() < pos) return -1;` → 0 候选；safe 例把同一个减法
当作**长度**用（`ReadBuffer(remaining)`）而不是读位置 → 0 候选，界定了规则的边界。

## 4. 最小对

三对都只在**程序体**上差一行（`#define Stub Fixture_<名>` 那行按约定必然不同，不计入）。
断言在 `MinimalPairTests`，逐对校验"差 N 行"与"定例 0 候选"。

## 5. 发现：`variant` 字段无人读，一条负控制被静默转成正控制

- **事实**：`tests/fixtures/ipc/manifest.json` 中 `account_role_authorized_fixed` 一行
  `variant: "fixed"` 但 `expected_rule: "ipc.auth.missing"`，`notes` 仍写着
  "so the three candidates are not raised"。实测该夹具在默认策略下**产出 3 条
  `ipc.auth.missing`**（行号 37 / 46 / 55）。
- **为什么没被发现**：`test_ipc_family_matrix.py::matrix()` 只按 `expected_rule` 分支 ——
  非 null 走 `assertIn`，null 走 `assertEqual(rules, set())`；**`variant` 在整个测试集里
  没有任何一处被读取**（已 grep 全 `tests/` 确认）。所以把 `expected_rule` 由 `null` 改成
  一个规则名，就把"必须零候选"的负控制换成了一条正控制，而矩阵测试照样通过。
- **本次处置**：把该行 `variant` 改为 `positive` 并把失效的 `notes` 补正 —— 这**不改变任何
  检测行为**（`variant` 不参与判定），只是让标签与该行实际断言的话一致；同时在
  `ManifestContractTests::test_variant_agrees_with_the_expectation` 里加上
  "positive ⟺ 非 null；fixed/safe ⟹ null" 的契约，使这个字段第一次有约束力。
- **留给负责人/import 作者的判断**：若这条要保留为**真正的负控制**（"审过的账户在这些操作上
  被正确credit"），需要让夹具走**显式 policy** 的测试路径 —— 该行自带的 `policy_context`
  已经指向这个方案（"explicit fixture policy tested separately"）。两种处置都合理，但必须
  二选一；现状是标签说一套、断言查另一套。

## 6. 验证（精确 argv，仓库根运行，不用 `-I`）

```bash
cd /home/audit/ohscanner/worktrees/parallel-ipc-20261017
.venv-web/bin/python -m unittest tests.test_ipc_family_depth tests.test_ipc_family_matrix -v
# Ran 25 tests ... OK

.venv-web/bin/python -m unittest tests.test_ipc_detector tests.test_ipc_entry_index \
  tests.test_ipc_descriptor_identity tests.test_ipc_relay_guard tests.test_ipc_macros \
  tests.test_ipc_disclosure_consequence tests.test_ipc_family_matrix tests.test_ipc_family_depth
# Ran 127 tests ... FAILED (failures=2)
```

**那 2 项失败不是本次引入的**，且与第一交付 §3.1 的预判完全一致：并发 import 把来源
`tests/test_ipc_detector.py` 的两处覆盖侧车断言照抄成 `'blocked'`，而本基线
`runner.py:119-131/250-255` 在没有 `file_outcomes` 时给出的是 `'partial'`：

```
tests/test_ipc_detector.py:61  AssertionError: 'partial' != 'blocked'
tests/test_ipc_detector.py:168 AssertionError: 'partial' != 'blocked'
```

本基线上应保留 `'partial'`。这是共享面演进，不是规则行为差异。

## 7. 与并行 import 的关系（依赖声明）

本次**依赖** worktree 里已存在的 v0.8.0 import（`families/` 包、`models.py` 的
`caller_class_sensitive_calls` / `caller_role_guards` / `result_permissions`、`analysis.py`
的 emit 点）。这些是 **2026-10-17 03:00 前后由另一个会话在同一 worktree 写入且尚未提交**
的状态；若该 import 被回退或改写，本单元的夹具与测试会随之失败 —— 这是**依赖**，
不是本单元自身的缺陷。夹具与 manifest 本身只依赖 `models.py` 的具名常量表，不依赖
import 的内部实现。

## 8. 未闭合

- **机制层的具名判定结果**（AUTH-01 的 `descriptor_identity ∈ {accepted, mismatch, unresolved}`
  那样的机制级结论，以及"拒绝理由作为独立 obligation / limitation 出门"）目前只有 AUTH-01 有。
  AUTH-02/03/04、CAP-01、DATA-01 的候选仍主要靠 `message` 文本区分，没有可断言的机制字段。
  这是"对齐子类一"里**尚未完成**的一半，需要改 `analysis.py` 与 `models.py`，属于与并发
  import 抢同一批文件的改动。
- **AUTH-02 的账户负控制**：见 §5。
- **真实组件实测**：见 [20261017-six-family-component-measurement.md](20261017-six-family-component-measurement.md)。
