# M2 修复：一跳同文件委托不是「无守卫边界」，除非被委托方就是守卫（2026-10-12）

- 输入：M1 报告 §6 留存候选里**明确归因到 M2 的那一条**——`window_window_manager`
  `screen_session_manager_stub.cpp:42`（AUTH-01）。
- 产出：**一处源码级修复 + 8 个正反例 + 五组件修复前后候选差异（唯一消失候选注明依据）**，不是新的漏洞结论。
- 三个数分开报：**测试 401 项 OK**（接口线分支，含组件审计；修复前 391）/ **候选 24 → 23 条** / **确认漏洞 0 条**。
- ~~未推送。~~ **（2026-10-16 更正）写作当时属实；该分支后已推到远端** ——
  `origin/feat/interface-m2-relay-guard` = `54a4d98`，修复提交 `642ae1c` 已随它到远端，
  并以 **Draft PR #11** 形式存在（base 为 `feat/interface-m1-descriptor-identity`）。
  **该 head 未查询到 PR workflow run / status / review，不得称「CI 已通过」**；§6 的 401 项是**本地回归**。
  分支与提交见 §9。

## 0. 一句话结论

原谓词在**入口函数自己的状态**上判断「这条路径有没有通过描述符校验」；当入口只是把请求原样转交给
**同文件另一个函数**（`OnRemoteRequest` → `OnRemoteRequestInner`）时，入口状态里当然还没有校验，
于是**守卫隔了一次调用**就被报成不存在。修复后：只有当被委托方**自己**在顶层、在分发之前比较
`ReadInterfaceToken()` 与一个**被接受的**描述符身份、且不匹配分支**真的离开**时，这一跳才被读成守卫；
五组件复跑 **1 条 AUTH-01 消失、0 条新增、0 条理由变化**，其余四组件逐条不变。

## 1. 缺陷与修复

### 1.1 缺陷

`src/ohscanner/detectors/interface/analysis.py` 的 `action()` 里，AUTH-01 的判定是：

```python
if self.root.name in self.policy.entry_names and name not in self.policy.entry_names and (...):
    parcel_keys = {v.key for v in state.env.values() if v.kind == "parcel"}
    if parcel_keys and not parcel_keys.intersection(state.descriptor):
        self.emit("AUTH-01", "ipc.relay.descriptor-boundary", ...)
```

`state.descriptor` 是**当前路径**已经确立的校验事实。真实形状是：

```cpp
int32_t ScreenSessionManagerStub::OnRemoteRequest(uint32_t code, MessageParcel& data, ...)
{
    DmUtils::HoldLock callbackLock;
    int32_t result = OnRemoteRequestInner(code, data, reply, option);   // :42  ← 候选报在这里
    return result;
}

int32_t ScreenSessionManagerStub::OnRemoteRequestInner(uint32_t code, MessageParcel& data, ...)
{
    TLOGD(WmsLogTag::DMS, "OnRemoteRequest code is %{public}u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {                 // :50  ← 真正的守卫
        TLOGE(WmsLogTag::DMS, "InterfaceToken check failed");
        return ERR_TRANSACTION_FAILED;                                  // :52
    }
    DisplayManagerMessage msgId = static_cast<DisplayManagerMessage>(code);
    switch (msgId) { ... }                                              // :54  ← 分发
}
```

`:42` 处 `state.descriptor` 为空是**事实**，但这不等于「这一跳没有守卫」——守卫在被委托方体内，
且**支配**了被委托方的分发。`_entry_roots()` 本来就把 `OnRemoteRequestInner`
（`endswith("Inner") and "Stub" in owner`）当成自己的 root，所以它的内部观测（`:738`、`:1778`）
**不依赖**这条候选存在；删掉 `:42` 不丢信息。

### 1.2 修复：把这一跳读成「守卫 / 看到比较但不成立 / 不成立」

新增 `relay_guard(fn, node, args, helper, state, depth)`，只在**五个条件同时满足**时返回
`("guarded", where)`：

| # | 条件 | 理由 |
|---|---|---|
| 1 | 被委托方**同文件**（`helper.file == fn.file`）且函数体可见 | 出了这个文件就是 M6 的范围，不做通用跨文件解析 |
| 2 | **实参全部是入口自己的形参**（`OnRemoteRequestInner(0, data, ...)` 不算） | 换掉实参就是换了一个事务，被委托方守的不是调用方到达的那个事务 |
| 3 | 被委托方**顶层语句**里存在 `ReadInterfaceToken()` 与描述符的**比较**（`if_statement`，非嵌套） | 嵌套比较可能根本不执行，不支配分发 |
| 4 | 比较的身份 subject ∈ `_DESCRIPTOR_ACCEPTED`（M1 的三档接受） | 身份不成立就不是守卫（M1 的结论原样继承） |
| 5 | 不匹配分支（`!=` 取 consequence、`==` 取 alternative）**顶层 `return`/`throw`**，且该比较**之前**于 `switch` | 「看到正确的 `GetDescriptor()` 调用 ≠ 校验成立」——不离开、或已分发就不算 |

三档返回：`("guarded", where)`（这一跳就是守卫，调用点不报）、
`("seen", issue)`（有比较但身份不被接受 → **保留候选**，报文写「present but not accepted」，
并把两侧身份按 M1 的 `descriptor_note()` 格式列出，义务 `descriptor_identity_mismatch` /
`descriptor_identity_unresolved`）、`None`（上述任一条件不满足 → 调用点照旧是候选）。

两处 AUTH-01 发射点都接了这个判定：`action()`（`parcel` 键存在且未通过校验的那条）与
`value()` 的委托分支（`helper` 可达且入口状态无校验的那条）。两处问的是同一个问题，
形状必须一致，否则同一行会产生两种说法。

### 1.3 顺带修正：被委托方的局部变量

`token = data.ReadInterfaceToken(); if (token != X::GetDescriptor())` 是真实代码里常见的写法。
`relay_guard` 在读到那个比较之前，**沿路绑定被委托方自己的 `init_declarator`**
（复用 `assign()`，与 `block()` 里既有语义一致），否则这一档会把真守卫读成 `unknown` 而继续报候选。

## 2. 度量方法（可复现）

- 基线 = `outputs/reports/m1_descriptor_identity/<component>.json`（**M1 之后**的正式平台产物，
  规则 `ohscanner.interface.ipc@0.4.0+oh-ipc-2026.10-v2`，五组件 24 条候选）。
- 修复后 = **项目正式执行路径**，逐组件一条命令（`--include` 用基线自己记录的显式路径集合）：

  ```
  .venv/bin/python -m src.cli ohscan-run \
    --repo-dir /home/audit/openharmony-audit/perf-corpus/security_access_token \
    --repository openharmony/security_access_token \
    --commit 17d88bfb36bea6c9370ba919ac41a22d16dd66b3 \
    --detector ohscanner.interface.ipc \
    --json-out outputs/reports/m2_relay_guard/security_access_token.json \
    --md-out  outputs/reports/m2_relay_guard/security_access_token.md \
    --include <基线记录的 550 条路径，逐条给出>
  ```

- **拓扑（必须写明）**：`src/ohscanner/detectors/catalog.py` 是**负责人维护的注册表**，所在集成分支的
  `interface/` 包是 M1 之前的快照。因此这次 CLI 跑在**该工作树的临时副本**
  （`/tmp/m2_platform`）上，把队友 B 的 `interface/` 包覆盖进去、并保留负责人的 `m2_adapter.py`
  （它只表达执行深度，不含规则逻辑），让注册的 detector id 解析到**被测代码**。
  这一步与 M1 那次相同，两个 before/after 因而可比。
- 比较键与项目自己的回归脚本一致：`(file, line, rule_id, source_sha256)`，**不含 `rule_version`**，
  所以规则版本从 0.4.0 走到 0.5.0 不会把「同一条候选」误报成变化；理由文本单独比较，**变化单列为 reworded**。
- 绑定核对（同一组件前后两次运行）：`commit` 与 `snapshot_sha256` **完全相同**，
  被移除候选所在文件的 `source_sha256` 也**完全相同**，唯一变化的是 `detector_version` 0.4.0 → 0.5.0。
- 环境：`python 3.10.12`（仓库虚拟环境 `.venv`）、`tree_sitter 0.26.0`、`tree_sitter_c 0.24.2`、
  `tree_sitter_cpp 0.23.4`、`profile_id = light-ast`。

### 2.1 产物与校验和

| 产物 | 内容 | sha256 |
|---|---|---|
| `outputs/reports/m2_relay_guard/m2_delta.json` | 五组件 before/after、逐条消失/新增/变化、命令与绑定信息 | `e5014e4a10347a51…`（全 64 位见文件） |
| `outputs/reports/m2_relay_guard/m2_record.json` | 实验记录（环境、拓扑、版本、产物哈希） | `5372c1eb188e287d…` |
| `outputs/reports/m2_relay_guard/<component>.json` | 修复后正式报告（5 份）+ `<component>.md` + `.terminal.txt` | 见 record 的 `artifacts` |
| `research/experiments/interface/ipc/m2_platform_delta.py` | 差异驱动（调用正式 CLI，入库） | 入库 |

产物按仓库既有惯例放在 `outputs/reports/` 下（`.gitignore` 加了一行
`outputs/reports/m2_relay_guard/`，与 `static_baselines/`、`m1_descriptor_identity/` 同格式）。
入库的只有测量脚本（复现工具，不是生成物）。

## 3. before / after（五组件，同 commit、同范围、同一条正式路径）

| 组件 | commit | 分析文件 | 候选 前 → 后 | 消失 | 新增 | 理由变化 | 确认漏洞 |
|---|---|---:|---:|---:|---:|---:|---:|
| `security_access_token` | `17d88bfb36be` | 550 | 3 → 3 | 0 | 0 | 0 | 0 |
| `window_window_manager` | `8b0d8fe1b973` | 1112 | **15 → 14** | **1** | 0 | 0 | 0 |
| `communication_dsoftbus` | `652f88e0261c` | 1656 | 4 → 4 | 0 | 0 | 0 | 0 |
| `update_updateservice` | `e4942a33cc5e` | 219 | 2 → 2 | 0 | 0 | 0 | 0 |
| `distributeddatamgr_kv_store` | `acfb22aac161` | 1446 | 0 → 0 | 0 | 0 | 0 | 0 |
| **合计** | | **4983** | **24 → 23** | **1** | **0** | **0** | **0** |

**变化是外科式的**：只有 `window_window_manager` 动了，另外四组件**逐条相同**。
这不是「为了凑一个数」——消失集合恰好等于 M1 报告 §6 归因到 M2 的那一条；其余 23 条
（含 13 条 CAP-01、4 条 AUTH-02、2 条 AUTH-04、3 条 AUTH-01）一条没动。

## 4. 唯一消失候选的依据

| 项 | 值 |
|---|---|
| 候选 | `window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp:42`，规则 AUTH-01，`source_sha256 = 404969d1…` |
| 入口 | `ScreenSessionManagerStub::OnRemoteRequest`（`:38`） |
| 这一跳 | `:42` `int32_t result = OnRemoteRequestInner(code, data, reply, option);` |
| 条件 1 同文件 | 被委托方与入口同在 `screen_session_manager_stub.cpp` |
| 条件 2 纯转交 | 四个实参 `code / data / reply / option` **逐字等于**入口的四个形参 |
| 条件 3 顶层比较 | 被委托方 `:50`（函数体第 2 条顶层语句，第 1 条是 `TLOGD` 日志）`if (data.ReadInterfaceToken() != GetDescriptor())` |
| 条件 4 身份被接受 | 比较式为**无限定** `GetDescriptor()` → M1 的 `unqualified` 档，∈ `_DESCRIPTOR_ACCEPTED` |
| 条件 5 离开且早于分发 | 不匹配分支 `:51-53` 顶层 `return ERR_TRANSACTION_FAILED;`（`:52`）；`switch (msgId)` 在 `:54`，**晚于**比较 |
| 不丢信息 | `:738`（AUTH-02 `GetDisplaySnapshot`）与 `:1778`（CAP-01 `WriteRemoteObject`）**仍在**（同文件仍报 2 次），因为 `OnRemoteRequestInner` 本来就是 `_entry_roots()` 认的 root，它的内部观测不依赖 `:42` |

## 5. 新增 0 条、理由变化 0 条——以及它意味着什么

诚实结论：**`("seen", …)` 这一档（有比较但身份不被接受）本次语料没有行使到**——
五组件里凡是隔一次调用的守卫，比较的身份都被接受。这一档目前**只有 fixture 的对照实验在支撑**（§7）。
同理，局部变量那一档（§1.3）在语料上**没有独立证据**：真实目标写的是直接比较。两者都**不能**据此
认为已在真实源码上验证过。

不做「消掉约 N 条」式的验收：本报告接受的是**每条消失都能指到守卫行**，而不是数量下降本身。

## 6. 幸存 23 条与各自的机制（M2 的能力边界）

M2 只动「入口同文件一次调用之外、被委托方体内的那一次顶层比较」。以下都**不在射程内**，原样保留：

| 机制 | 例子 | 属 |
|---|---|---|
| 授权谓词体未建模 | `token_sync_manager_stub.cpp:104/121/136`（授权在 `IsRootCalling` 里） | M3 |
| 常量域 / 权限常量语义 | 各处 `expected_permissions` 相关判定 | M4 |
| 支配性只按结构规则核对（未做有界支配证明） | `update_updateservice` 的 2 条 AUTH-04 | M5 |
| 间接分发（`dlsym`/函数指针表）、别名基类 | `bus_center_ex_obj_stub.cpp:56`、`trans_spec_object_stub.cpp:62` | M6 / unknown |
| 描述符之外的另一轴（权限、能力导出） | 13 条 CAP-01、4 条 AUTH-02 | 与本类无关 |

23 条**全部**带义务（`entry_reachability` / `callee_and_policy` / `consequence` / `security_impact`），
`validated_vulnerability` 五组件都是 0，`evidence_type = syntax`、`severity/confidence = unassessed` 未变。

## 7. 正反例对照（8 个 fixture）

`tests/fixtures/ipc/relay_inner_*.cpp`，全部进入 `manifest.json`（40 → 48 行，原有行未重排）：

| fixture | 期望 | 钉住哪一条 |
|---|---|---|
| `relay_inner_guard_fixed.cpp` | 零 finding | 条件 1–5 全满足：`!=` 直接比较 + 顶层 return + switch 在后 |
| `relay_inner_local_guard_fixed.cpp` | 零 finding | §1.3：token 先落在局部变量里，仍须被读成守卫 |
| `relay_inner_no_guard_positive.cpp` | AUTH-01 | 条件 3：被委托方**根本不比较** |
| `relay_inner_after_dispatch_positive.cpp` | AUTH-01 | 条件 5：比较在 `switch` **之后** |
| `relay_inner_no_reject_positive.cpp` | AUTH-01 | 条件 5：不匹配分支只 `LOG`，不离开事务 |
| `relay_inner_nested_positive.cpp` | AUTH-01 | 条件 3：比较**嵌套**在另一个 `if` 里，不支配分发 |
| `relay_inner_substituted_positive.cpp` | AUTH-01 | 条件 2：实参被换成字面量 `0`，不是转交 |
| `relay_inner_wrong_interface_positive.cpp` | AUTH-01（`mismatch` 档） | 条件 4：比较的是**另一个**接口 `IBar`，报文同时列出 `IBar declared at …` 与 `this class implements IFoo (stated at …)`，带 `descriptor_identity_mismatch` |

**对照实验（回归控制）**：把引擎换回 HEAD（M2 之前）后跑同一批 fixture，
`relay_inner_guard_fixed` / `relay_inner_local_guard_fixed` / `relay_inner_wrong_interface_positive`
**三项失败**（前两项报出候选，第三项报文不含「present but not accepted」），
五个纯正例**照旧通过**——说明这些 fixture 是**有区分度**的，不是恒绿。

测试：`tests/test_ipc_relay_guard.py` **10 项**（8 个语义用例 + 2 个 manifest 覆盖检查）。
分支总计：接口线分支 **401 项 OK**（修复前 391）。

## 8. M2 不做什么，以及已知限制

1. **不改 M1/M3～M6**：本次提交只含这一处判定（`analysis.py` 一个方法 + 两处调用点 +
   `detector.py`/`models.py` 的版本号 + fixtures + 测试 + 一篇文档 + 一行 `.gitignore`）。
2. **`seen` 档只有 fixture 证据**（§5），真实语料未行使。
3. **不做跨文件**：条件 1 硬性要求同文件。`DelayedSingleton<X>::GetInstance()->Method()` 那一跳
   （`delegated()`）与 M6 的范围**没有改动**。
4. **不证明支配性的一般情形**：条件是「顶层 + 早于 switch + 不匹配分支有 return/throw」，
   这是**结构规则**，不是有界支配证明（M5）。`goto`/异常/宏展开改变控制流的情形没有被覆盖。
5. **不校验「被委托方只被这一处调用」**：如果同一函数还被别的入口调用，本判定按**调用点**逐处判断，
   不推断被委托方的其它调用者。
6. **解析完整性**：五组件本次 `coverage status` 都是 `partial`，仍带 `parse_completeness_impact` 义务。
   「解析错误不在候选附近」不足以证明没有影响，本报告只写「**当前核查未发现直接关联**」。
7. **不是误报率**：本报告不给 Precision，因为没有独立标注集。
8. **守卫语义之外的前提仍在义务里**：`ReadInterfaceToken()` 的返回值是否可能为空、调用方能否控制
   token、是否存在别的入口绕过该函数——这一跳被读成守卫**不改变**这些。

## 9. 状态

- 修复提交：`ffa27d7`（`feat/interface-ipc-detector`）；本记录与其复现脚本：`1bff189`。
- ~~**未推送、未合并**~~；**（2026-10-16 更正）该判断已过期**：
  - `ffa27d7` 在 `feat/interface-ipc-detector` 上，该分支已在远端 → 该提交已推送；
  - 本记录的 `1bff189` 已在 `feat/interface-m2-relay-guard` 上（远端 = `54a4d98`），**Draft PR #11**。
  - **仍未合并**。「是否推送/开 PR/合并由项目负责人决定」这一原则**不变**。
- **远端 CI 状态（2026-10-16 独立审查口径）**：PR #11 的 head `54a4d98`
  **未返回 PR workflow run / status / review**，**不能称为 CI 已通过**。
  独立审查同时记录：该 head 虽不是 `main` 祖先，但**整个 interface 检测包、relay 测试及核对 fixture
  与 `main` 无差异**，因此**无需再整支合并**（该判断属负责人/main 侧决定，B 不据此行动）。
- 顺带一行：`.gitignore` 增加 `outputs/reports/m2_relay_guard/`。
- 观察（未处理）：工作区存在**未跟踪且未被忽略**的目录
  `research/experiments/interface/ipc/results/`（M1 报告已记录过），本次没有添加它；
  提交时注意别被 `git add -A` 带进去。
