# 交付项 12：家族目录补齐到六族齐备 + B_IPC.md 验收项 2 的引擎用例双侧覆盖（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **worktree**：`/home/audit/ohscanner/worktrees/parallel-ipc-20261017`
- **规则来源（只读固定）**：`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`，
  分支 `feat/interface-ipc-detector`，HEAD `635b3e0449c552f0ccc25118850d245962845568`
- **本文件对应的提交**：`tests/fixtures/ipc/{auth02,auth04,cap01}/`、
  `tests/test_ipc_family_depth.py`、`research/deliveries/ipc/family_dir_measurement.py`、
  `research/deliveries/ipc/engine_boundary_probe.py`、本文件、以及
  20261017-lane-delivery-record.md（文件引用：20261017-lane-delivery-record.md） /
  20261017-six-family-depth-unit.md（文件引用：20261017-six-family-depth-unit.md） 的相应更新
- **交付项 2**（六家族逐规则控制补齐）见
  20261017-six-family-depth-unit.md（文件引用：20261017-six-family-depth-unit.md）

---

## 0. 一句话结论

交付项 2 补的是**规则**缺口（11/11 有正例），但没有补**家族目录**缺口：`auth02/`、`auth04/`、
`cap01/` 三个家族没有自己的目录，于是"某个家族的 negative 证据可以由别的家族借"这件事只在
AUTH-01/03/DATA-01 被消掉。本次把这三个目录补齐（16 个夹具 / 16 行 manifest），并把
`B_IPC.md` 验收项 2 点名的五个引擎用例逐例做成**双侧**断言（显现侧 + 不显现侧）。过程中实测出
三条机制边界，其中两条已固化为夹具、一条**故意不固化**（§5，因为预期行为未定）。

## 1. 改动清单（只新增夹具与测试，不改任何检测逻辑）

| 文件 | 内容 |
|---|---|
| `tests/fixtures/ipc/auth02/` | 4 正 / 1 定 / 1 safe + `manifest.json` |
| `tests/fixtures/ipc/auth04/` | 1 正 / 1 定 / 1 safe + `manifest.json` |
| `tests/fixtures/ipc/cap01/` | 4 正 / 2 定 / 1 safe + `manifest.json` |
| `tests/test_ipc_family_depth.py` | 12 项 → **19 项**：12 条正例的精确 `(规则, 行号, 该行必须含的构造)` 三列 pin、10 个最小对 + 1 个不变量对、5 个点名用例 + 2 条边界用例（均双侧）、`variant` 契约 |
| `research/deliveries/ipc/family_dir_measurement.py` | 只读仪器：按深度单元自己的 helper 复现全部 pin（含 diff 预算） |
| `research/deliveries/ipc/engine_boundary_probe.py` | 只读仪器：§4/§5/§6 三条边界的逐差探针，一次只改一处 |

按既有约定归档在家族目录下，因此被 `tests/test_ipc_family_matrix.py::FamilyFixtureMatrixTests`
自动接管；**未改**共享 `tests/fixtures/ipc/manifest.json`、**未改** `analysis.py` / `models.py` /
`entry_index.py` / `detector.py`。

## 2. 家族目录矩阵（本次前 → 后）

| 家族 | 本次前 | 本次后（家族目录内） |
|---|---|---|
| AUTH-01 | safe 1 | 不变 |
| AUTH-02 | **无目录** | 4 正 / 1 定 / 1 safe |
| AUTH-03 | 2 正 / 1 定 / 1 safe | 不变 |
| AUTH-04 | **无目录** | 1 正 / 1 定 / 1 safe |
| CAP-01 | **无目录** | 4 正 / 2 定 / 1 safe |
| DATA-01 | 1 正 / 1 定 / 1 safe | 不变 |

`RuleControlCoverageTests.test_every_family_has_positive_fixed_and_safe_controls` 要求的是
**逐家族**的 positive+fixed+safe，此前 AUTH-02/04/CAP-01 三个家族只能从共享 manifest 里借到；
本次之后六个家族各自齐备。

## 3. `B_IPC.md` 验收项 2 的五个用例：逐例双侧

验收项 2 原文要求覆盖"const 引用、不唯一宿主方法、一跳拒绝 limitation 传播、本地同名 body
遮蔽与非零行号；两侧控制必须都断言"。逐例的**显现侧 / 不显现侧**与断言位置：

| 用例 | 显现侧（实测） | 不显现侧（实测） | 断言 |
|---|---|---|---|
| const 引用 | `auth02/entry_const_reference_positive.cpp` → `[('ipc.auth.missing', 6)]` | `auth02/entry_reference_positive.cpp` → 同一集合（去 const，diff=1） | `test_a_const_reference_entry_and_a_reference_entry_are_read_the_same`（相等 + 两侧都非空 + 预算 1） |
| 不唯一宿主方法 | `cap01/onehop_not_unique_positive.cpp` → 候选 + `One-hop callee is not unique (2 definitions) for FixtureOnehopStub::GetObject; the callee body was not read. The call site therefore stays a candidate.` | `cap01/onehop_ungated_positive.cpp`（唯一实现者）→ 同类候选，**无** not-unique 行 | `test_a_non_unique_host_method_is_refused_rather_than_chosen` |
| 一跳拒绝 limitation 传播 | 同上：拒绝句出现在 `run.limitations`，候选留在调用点 | `cap01/onehop_credited_fixed.cpp` → `[]` + `Cross-TU one-hop guard credited: …:27 dispatches to …:32, whose caller-role gate at …:33 admits <sa-caller>` + `Cross-TU one-hop dispatch: 1 implementer guard(s)…` | `test_a_refused_one_hop_limitation_propagates_into_the_run` |
| 本地同名 body 遮蔽 | `auth02/caller_role_shadowed_positive.cpp` → `[('ipc.auth.missing', 20)]` + 遮蔽 limitation | `…_fixed.cpp`（body 末行改成与**审过的服务账户**比较）→ `[]`；`…_unmodelled_safe.cpp`（改操作）→ `[]`；**三份都带同一条 limitation** | `test_a_locally_shadowed_reviewed_role_body_is_recorded_and_not_credited` |
| 非零行号 | 12 条 pin 的行号逐条回读该行、断言含指定构造；credit 句的三个引用行 `27/32/33` 同样逐条回读 | —（`contracts.py:125` 在构造时已拒绝 <1 的行号，故这里断言的是夹具侧：行号指向的**构造**对不对） | `test_each_pinned_line_is_the_construct_the_candidate_is_about` + `test_every_hop_citation_line_is_non_zero_and_names_its_construct` |

非零行号这一条值得单列一句口径：`DetectorFinding` 在 `contracts.py:125-126` 就会拒收
`line < 1`，所以"候选带非零行号"本身**不可能**被引擎违反；真正会被违反的是"这个非零行号指向
的构造"。pin 表因此每格是三元组 `(rule, line, token)`，`token` 必须出现在 `line` 行上——它同时
钉住"检测器按**文件**行号而不是预处理后的行号计数"这件事。

## 4. 发现一：对象宏命名的 stub 类让入口索引不绑定 dispatch（已固化）

同一段程序，只改类名怎么写：

| 探针候选 | 类名写法 | 实测 |
|---|---|---|
| `a_literal_credited` | 字面量 `FixtureOnehopCreditedStub` | `[]` + credit 行 |
| `a_literal_ungated` | 字面量（无 gate） | 候选 |
| `b_macro_stub_credited` | `#define Stub Fixture_b_macro_stub_credited` + `class Stub` | 候选 + `Dispatch handler not uniquely resolved: Stub::HandleGetObject; not used as an entry` |
| `c_macro_other_name_credited` | `#define OnehopStub …` + `class OnehopStub` | 候选 + 同一句（换成 `OnehopStub::`） |
| `d_literal_not_unique` | 字面量、两个实现者 | 候选 + not-unique 拒绝句 |
| `e_macro_stub_not_unique` | 宏 + 两个实现者 | 候选 + **dispatcher** 拒绝句（不是 not-unique） |

两条读数：**(a)** 宏的**名字**无关——`b` 与 `c` 同样失败，所以起作用的不是"叫 Stub"，而是
"类名来自对象宏"；**(b)** 后果是**精度损失**而不是漏报：被 gate 的程序本该抑制候选，却仍出候选。
这也正是本单元其余夹具沿用 `#define Stub <夹具名>` 约定时**测不到一跳**的原因。

处置：`cap01/onehop_{ungated_positive,credited_fixed,not_unique_positive}.cpp` 三个夹具把类名
**字面写出**（同一目录内共用 `FixtureOnehopStub` / `FixtureOnehopService`，因为每个夹具各自
解析），并在 `cap01/onehop_macro_renamed_stub_positive.cpp` 里**保留**宏形态作为控制：
`EngineCaseCoverageTests.test_a_macro_named_stub_class_is_not_bound_by_the_entry_index` 两侧
断言（字面量+gate ⇒ `[]`；宏+同一段 gate ⇒ 候选 + 拒绝句）。边界因此可被检出，不会悄悄移动。

## 5. 发现二：对象经**返回值**回来时，credit 记了，候选不撤（故意不固化）

同一段程序，只改对象怎么回来：

```text
a_literal_credited                 virtual int GetObject(int32_t id, RemoteObjectPtr &object);
   24  RemoteObjectPtr object;
   25  GetObject(id,object);
   26  reply.WriteRemoteObject(object);          → rules: []（credit 抵达并撤销候选）

a_by_value_pointer_return_credited virtual RemoteObjectPtr GetObject(int32_t id);
   24  RemoteObjectPtr object = GetObject(id);
   25  reply.WriteRemoteObject(object);          → rules: [('ipc.capability.export', 25)]
     L: Cross-TU one-hop guard credited: …:24 dispatches to …:29, gate at …:30
```

返回值形态下，**credit 行照记（且三处 file:line 引用都正确）**，但 reply 写出点的候选**没有**
被撤销；出参形态下同一段 gate 把候选撤干净了。检测器自己的 limitation 只写了
`Pointer out-parameters are not followed, so an object written back through one is not traced to
the call that produced it.`——**返回值形态不在该句覆盖范围内**。

- **成因未定**：从外部无法判定"credit 已记 ⇒ 该不该撤候选"，两者说的是两件事（实现者 body 的
  守卫 vs. 写出对象的来源链）。要判定需读 `analysis.py` / `bind_result`，属共享面。
- **因此故意不做成夹具**：把某一种输出写进 pin 表等于替引擎定行为；在成因未定之前固化它，
  就是把"当前实现"当成"正确实现"。这里只记录，并列为开放项（§10）。

## 6. 发现三：同名 reviewed 角色谓词——成员定义读 body，文件作用域定义直接拒名（已固化）

入口、调用点、谓词名、比较值全部相同，只改**谓词定义在哪**：

| 形态 | 实测 |
|---|---|
| 成员定义 `bool Stub::IsAccessTokenCalling() const` | `[('ipc.auth.missing', 20)]` + `Reviewed caller-role predicate IsAccessTokenCalling is also defined in the scanned sources at …:12 (Fixture_…::IsAccessTokenCalling); a call to it was read from that body, and the reviewed name itself was not credited for it.` |
| 文件作用域定义 `bool IsAccessTokenCalling()` | `[('ipc.auth.missing', 19)]` + `Local caller-role definition is unresolved: IsAccessTokenCalling at …:6; reviewed-name credit refused; caller authorization remains unknown.` |

成员形态**读了 body**，而 `_fixed` 夹具的抑制正是靠这个 body 里的比较（改成与审过的服务账户
比较即 0 候选）；文件作用域形态**直接拒名、body 完全不用**。也就是说同一段谓词文本会因为
"是不是入口自己类的成员"而被读或被丢。两份都固化为夹具（`caller_role_shadowed_positive.cpp`
与 `caller_role_shadowed_free_predicate_positive.cpp`），断言在
`test_a_member_predicate_body_is_read_and_a_file_scope_one_is_not`（两侧）。

> 记一条**过程**教训：本条探针的第一版用字符串拼接把成员定义塞进类体，产出了非法 C++，
> 于是引擎回 `status: blocked` + `Local caller-role definition is unresolved`——那是"源码没法解析"
> 的反应，不是遮蔽行为的结论。两版文本现在**逐字写死**在 `engine_boundary_probe.py` 里，
> 并在该文件 docstring 里写明此事。

## 7. 最小对与不变量（预算全部实测）

10 个最小对全部 `diff=1`（程序体，`#define` 行按约定不计），正例非空、控制侧 `[]`：

```text
auth03 caller_class_positive        vs caller_class_fixed           [caller-class@7] -> []
auth03 identity_domain_positive     vs identity_domain_fixed        [3 条] -> []
data01 position_underflow_positive  vs position_underflow_fixed     [position-underflow@7] -> []
auth02 caller_role_shadowed_positive vs caller_role_shadowed_fixed      [missing@20] -> []
auth02 caller_role_shadowed_positive vs …_unmodelled_safe               [missing@20] -> []
auth04 guard_fallthrough_positive   vs guard_fallthrough_fixed      [guard-coverage@7, missing@7] -> []
auth04 guard_fallthrough_positive   vs guard_fallthrough_unmodelled_safe  同上 -> []
cap01  export_positive              vs export_guarded_fixed         [export@6] -> []
cap01  export_positive              vs export_null_safe             [export@6] -> []
cap01  onehop_ungated_positive      vs onehop_credited_fixed        [export@28] -> []
```

不变量对（**不得**被抑制，两侧必须相等且集合非空）：

```text
auth02 entry_const_reference_positive == entry_reference_positive   diff=1  两侧均 [missing@6]
```

## 8. 验证（精确 argv，仓库根运行，不用 `-I`）

```bash
cd /home/audit/ohscanner/worktrees/parallel-ipc-20261017
.venv-web/bin/python -m unittest tests.test_ipc_family_depth
# Ran 19 tests ... OK

.venv-web/bin/python -m unittest discover -s tests -q
# Ran 574 tests in 26.4s ... FAILED (failures=2, skipped=4)

.venv-web/bin/python research/deliveries/ipc/family_dir_measurement.py      # 复现 §7 全表
.venv-web/bin/python research/deliveries/ipc/engine_boundary_probe.py       # 复现 §4/§5/§6

.venv-web/bin/python scripts/check_change_scope.py \
  --base 6a41dc9b1aa030158e09be6241e2b14341f9256d --lane ipc
# {"base": "6a41dc9b…", "lane": "ipc", "checked_paths": [...], "violations": []}   exit 0
```

那 2 项失败**不是本次引入的**，与交付项 2 §6 记的是同两处、同原因（并发 import 把
`tests/test_ipc_detector.py:61/168` 的侧车断言写成 `'blocked'`，而本基线 `runner.py` 在无
`file_outcomes` 时给 `'partial'`）：

```text
tests/test_ipc_detector.py:61  AssertionError: 'partial' != 'blocked'
tests/test_ipc_detector.py:168 AssertionError: 'partial' != 'blocked'
```

本基线上应保留 `'partial'`。两处都在**本线未提交**的并发 import 文件里。

## 9. 与并发 import 的关系（依赖声明，未变）

本单元的家族目录约定（`Family.fixture_dir`）、`families.registry()`、`family_of_rule()`、
`cwes()` 全部来自并发 import 的 **未跟踪** `src/ohscanner/detectors/interface/families/`；
`tests/test_ipc_family_matrix.py` 同样未跟踪。**集成顺序必须是 import 先落、本单元后落**，
或由集成人并入同一批——本提交仍**不可单独检出运行**（交付项 2 已实测该 ImportError，此处不重复）。

## 10. 未闭合

1. **§5 返回值形态的 credit/抑制不一致** —— 属共享面（`analysis.py` / `bind_result`），
   本线只测量与记录，未改检测器、未做夹具、未撤任何候选。需集成人另开请求。
2. **机制字段** —— AUTH-02/03/04、CAP-01、DATA-01 的候选仍只能靠 `message` 文本区分，
   没有 AUTH-01 `descriptor_identity` 那样可断言的机制字段（同交付项 2 §8）。
3. **共享 manifest 两行待集成人裁决** —— `account_role_authorized_fixed`（交付项 2 §5）与
   `denied_complement_positive`；本线未提交该文件。
4. **本交付只到静态候选与合成夹具**：无 PoC、无动态验证、`validated_vulnerability` 恒为 0、
   `confirmed` 候选 0 条。夹具把它自己的规则触发起来 ≠ 该规则在真实代码上会响，
   更 ≠ 发现漏洞。**（本条后半已由交付项 13 补上：五种模式在三条语料与 42 份已保存报告上
   复测完毕 —— 三种形状真实存在、S1 的 const 形式全语料 6 处且非入口形态、S4 与夹具同形的
   0 处；触及候选的只有 S1 可变形式与 S5，S3/S4 零触及。详见
   `20261017-engine-case-corpus-census.md`。）**

## 11. 本地提交；push / merge / Ready 需另有明确授权

- 只提交本线自有路径（家族目录、深度单元、两件只读仪器、三份 `research/deliveries/ipc/*.md`）；
  **不提交**并发 import 的 `src/**`、`tests/test_ipc_{detector,entry_index,family_matrix,integration_safety}.py`、
  `tests/fixtures/ipc/*.cpp`（`account_role_*` / `helper_preproc_*` / `onehop_*` /
  `relay_lookahead_*` / `role_predicate_*`）与共享 `tests/fixtures/ipc/manifest.json`。
- **未 push、未开 PR、未标 Draft Ready、未 merge。**
