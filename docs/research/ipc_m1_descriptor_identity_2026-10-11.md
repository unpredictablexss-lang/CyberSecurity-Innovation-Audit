# M1 修复：把描述符校验读成「接口身份」而不是「一次调用」（2026-10-11）

- 输入：`docs/research/ipc_candidate_review_2026-10-11.md` 的候选集——41 条候选中**被明确归因到 M1 的 17 条**。
- 产出：**一处源码级修复 + 11 个正反例 + 五组件修复前后候选差异（每条消失候选注明依据）**，不是新的漏洞结论。
- 三个数分开报：**测试 391 项 OK**（接口线分支，含组件审计）/ **候选 41 → 24 条** / **确认漏洞 0 条**。
- ~~未推送。~~ **（2026-10-16 更正）写作当时属实；该分支后已推到远端** ——
  `origin/feat/interface-m1-descriptor-identity` = `8464151`，修复提交 `3fe3537` 已随它到远端。
  **该分支的远端 CI 未经本线核验**，不得称「CI 已通过」。分支与提交见 §9。

## 0. 一句话结论

原谓词把 `X::GetDescriptor()` 当作「X 必须是当前类」的过滤器，于是**真实形状**
`FooStub : public IRemoteStub<IFoo>` 里那句 `descriptor != IFoo::GetDescriptor()` 被丢弃成 `unknown`，
handler 被报成「没有描述符校验」；修复后**身份来自类自己的基类子句**（永不来自类名），
并把比较读成**一致 / 明确不一致 / 无法判定**三档，五组件复跑后 **17 条 AUTH-01 消失、0 条新增、0 条理由变化**，
其余四组件逐条不变。

## 1. 缺陷与修复

### 1.1 缺陷

`src/ohscanner/detectors/interface/analysis.py` 原判定：

```python
if name == "GetDescriptor":
    if "::" in callee and callee.rsplit("::",1)[0] != fn.owner:
        return UNKNOWN          # 限定名不是本类 -> 整个校验作废
    return Value("descriptor_expected", fn.owner)
```

限定名被当成**过滤器**，它的身份被丢掉。OpenHarmony 的真实写法里，stub 类名与接口名**本来就不相等**
（`TokenSyncCallbackStub` 实现 `IRemoteStub<ITokenSyncCallback>`、`OnPermissionUsedRecordCallbackStub`
实现 `IRemoteStub<OnPermissionUsedRecordCallback>`——连 `I` 前缀都没有），因此这一条把真校验全部判成无效。

### 1.2 修复：身份来自基类子句，比较读成三档

- `entry_index.py`：新增 `InterfaceRef`；`ClassInfo` **加法式**增加 `base_specs`（保留 `direct_bases` 不动，
  所以入口发现路径不受影响）；`_template_argument` 取基类说明符的模板实参；`implemented_interfaces()`
  **沿间接基类递归**收集 `IRemoteStub<T>` 的 T，并同时带回「是哪一行这么声明的」。
- `analysis.py`：`descriptor_expectation()` 返回四类 subject，`_DESCRIPTOR_ACCEPTED = {unqualified, self, interface}`：

  | 情况 | subject | 结果 |
  |---|---|---|
  | 无限定名 `GetDescriptor()`；或者限定到本类/`IRemoteStub`/`IPCObjectStub` | `unqualified` / `self` | 接受为守卫 |
  | 基类子句给出的接口名 == 比较的接口名 | `interface` | 接受为守卫（**并注明双方出处**） |
  | 基类子句给出的是**另一个**接口 | `mismatch` | **保留候选**，报文注明「守卫校验的是另一个接口」并列出两侧来源 |
  | 源码未说明该类实现哪个接口（别名基类、声明不在本分片） | `unresolved` | 保持 `unknown`：**既不当作校验成立，也不当作明确不一致** |

- `refine()`：**未被接受的比较不记为守卫**，而是记进 `descriptor_issues`（在两侧分支都记），
  所以同一路径上「看到过 `GetDescriptor()` 但没成立」这件事不会丢失。
- `detector.py`：新增两条按观测级别的义务 `descriptor_identity_mismatch` / `descriptor_identity_unresolved`；
  `version = "0.4.0"`。`models.py`：`MODEL_VERSION = "oh-ipc-2026.10-v2"`。

### 1.3 「看到正确的 GetDescriptor() 调用 ≠ 校验成立」

身份一致只是**第一步**。候选是否消失，仍然由既有路径语义决定，修复没有放宽它们：

- 比较必须发生在**目标操作之前**（`descriptor_after_positive.cpp` 仍报）；
- 不匹配分支必须**真的离开**该事务（`descriptor_no_reject_positive.cpp` 仍报）；
- 必须**比较过**，只是取回来不算（`descriptor_call_only_positive.cpp` 仍报）；
- 只覆盖一个分支也不算**支配**（`descriptor_one_branch_positive.cpp`：被守卫的分支干净，另一分支仍报）。

## 2. 度量方法（可复现）

- 基线 = `outputs/reports/<component>.json`（组件审计驱动写下的**修复前**产物，规则
  `ohscanner.interface.ipc@0.3.0+oh-ipc-2026.10-v1`，41 条候选）。
- 修复后 = **项目正式执行路径**，逐组件一条命令（`--include` 用的是基线自己记录的显式路径集合，
  不引入新的范围启发式，也不隐式取 HEAD）：

  ```
  .venv/bin/python -m src.cli ohscan-run \
    --repo-dir /home/audit/openharmony-audit/perf-corpus/security_access_token \
    --repository openharmony/security_access_token \
    --commit 17d88bfb36bea6c9370ba919ac41a22d16dd66b3 \
    --detector ohscanner.interface.ipc \
    --json-out outputs/reports/m1_descriptor_identity/security_access_token.json \
    --md-out  outputs/reports/m1_descriptor_identity/security_access_token.md \
    --include <基线记录的 550 条路径，逐条给出>
  ```

- 比较键与项目自己的回归脚本一致：`(file, line, rule_id, source_sha256)`。
  **不含 `rule_version`**，所以规则版本从 0.3.0 走到 0.4.0 不会把「同一条候选」误报成变化；
  理由文本单独比较，**变化会单列为 reworded**，不会混进消失/新增。
- 环境：`python 3.10.12`（仓库虚拟环境 `.venv`）、`tree_sitter 0.26.0`、
  `tree_sitter_c` / `tree_sitter_cpp`（版本号未暴露，随 requirements 锁定）、
  `provenance = local_git_objects`，源码来自本地 `perf-corpus` 检出。

### 2.1 产物与校验和

| 产物 | 内容 | sha256 |
|---|---|---|
| `outputs/reports/m1_descriptor_identity/m1_delta.json` | 五组件 before/after、逐条消失/新增/变化、命令与报告哈希 | `bd89360893a8e7b4…`（全 64 位见文件） |
| `outputs/reports/m1_descriptor_identity/m1_removal_basis.json` | 17 条消失候选的**逐条依据**（守卫、两侧身份、范围、校验和） | `140b49b2862210de…` |
| `outputs/reports/m1_descriptor_identity/m1_record.json` | 实验记录（环境、命令、组件元数据、报告哈希） | `c240b56b25815620…` |
| `outputs/reports/m1_descriptor_identity/<component>.json` | 修复后正式报告（5 份） | `48e90651…`/`1ce71a58…`/`e18779e9…`/`980c42be…`/`d7606bc3…` |
| `research/experiments/interface/ipc/m1_platform_delta.py` | 差异驱动（调用正式 CLI） | 入库 |
| `research/experiments/interface/ipc/m1_removal_basis.py` | 逐条依据取证 | 入库 |
| `research/experiments/interface/ipc/m1_record.py` | 实验记录组装 | 入库 |

产物按仓库既有惯例放在 `outputs/reports/` 下（`.gitignore` 为每个实验目录各加一行，
本次加了一行 `outputs/reports/m1_descriptor_identity/`，与 `static_baselines/`、`owner_ipc_integration/` 同格式）。
入库的只有三个测量脚本（是复现工具，不是生成物）。

## 3. before / after（五组件，同 commit、同范围、同两遍驱动）

| 组件 | commit | 分析文件 | 候选 前 → 后 | 消失 | 新增 | 理由变化 | 义务齐全 | 确认漏洞 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `security_access_token` | `17d88bfb36be` | 550 | **20 → 3** | 17 | 0 | 0 | 3/3 | 0 |
| `window_window_manager` | `8b0d8fe1b973` | 1112 | 15 → 15 | 0 | 0 | 0 | 15/15 | 0 |
| `communication_dsoftbus` | `652f88e0261c` | 1656 | 4 → 4 | 0 | 0 | 0 | 4/4 | 0 |
| `update_updateservice` | `e4942a33cc5e` | 219 | 2 → 2 | 0 | 0 | 0 | 2/2 | 0 |
| `distributeddatamgr_kv_store` | `acfb22aac161` | 1446 | 0 → 0 | 0 | 0 | 0 | — | 0 |
| **合计** | | 4973 | **41 → 24** | **17** | **0** | **0** | 24/24 | **0** |

**变化是外科式的**：只有 `security_access_token` 动了，另外四组件**逐条相同**（含 13 条 CAP-01、2 条 AUTH-04）。
这不是「为了凑一个数」——消失集合恰好等于核查文档归因到 M1 的那 17 条 AUTH-01；剩下的
AUTH-01（3 条）与另外四组规则**一条没动**，它们的机制在 §6 里各自说明。

## 4. 17 条消失候选的逐条依据

全部 17 条的**共性**：入口是同一个函数、守卫在入口函数体内、守卫在候选行之前、不匹配分支 `return`。
下表逐条给出「是哪一行守卫、两侧身份各是什么、候选经什么调用被到达」。
所有行都验证了**绑定校验和**：磁盘字节的 sha256 == 该候选被绑定到的 `source_sha256`（17/17 通过）。

### 4.1 `interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp`

该文件有**两个** stub 类，各带自己的入口与守卫——守卫必须落在候选自己的入口里：

| 位置 | 内容 |
|---|---|
| 类声明（`…/include/accesstoken_callback_stubs.h:39`） | `class TokenSyncCallbackStub : public IRemoteStub<ITokenSyncCallback>` |
| 入口 | `TokenSyncCallbackStub::OnRemoteRequest`（`:65`，整体在 `#ifdef TOKEN_SYNC_ENABLE` 内） |
| 守卫 | `:70` `if (descriptor != ITokenSyncCallback::GetDescriptor()) {` → `:73 return ERROR_IPC_REQUEST_FAIL;` |
| （同文件另一类，与本组无关） | `PermissionStateChangeCallbackStub : IRemoteStub<IPermissionStateCallback>`，守卫在 `:43` |

| 候选行 | 规则 | 报的 handler | 到达方式 | 依据 |
|---|---|---|---|---|
| `:78` | AUTH-01 | `TokenSyncCallbackStub::GetRemoteHapTokenInfoInner` | 在入口内（switch case） | 守卫 `:70` < `:78`；身份两侧一致 |
| `:81` | AUTH-01 | `…::DeleteRemoteHapTokenInfoInner` | 同上 | 同上 |
| `:84` | AUTH-01 | `…::UpdateRemoteHapTokenInfoInner` | 同上 | 同上 |
| `:103` | AUTH-01 | `GetRemoteHapTokenInfoInner` 函数体 | 入口 `:78` 调用 | 守卫 `:70` → 调用 `:78` → 函数体 `:103` |
| `:116` | AUTH-01 | `DeleteRemoteHapTokenInfoInner` 函数体 | 入口 `:81` 调用 | 守卫 `:70` → 调用 `:81` → 函数体 `:116` |
| `:131` | AUTH-01 | `UpdateRemoteHapTokenInfoInner` 函数体 | 入口 `:84` 调用 | 守卫 `:70` → 调用 `:84` → 函数体 `:131` |

### 4.2 `interfaces/innerkits/privacy/src/on_permission_used_record_callback_stub.cpp`

| 位置 | 内容 |
|---|---|
| 类声明（`…/src/on_permission_used_record_callback_stub.h:27`） | `class OnPermissionUsedRecordCallbackStub : public IRemoteStub<OnPermissionUsedRecordCallback>`（**接口无 `I` 前缀**） |
| 守卫 | `:35` `if (descriptor != OnPermissionUsedRecordCallback::GetDescriptor()) {` → `:37 return ERROR_IPC_REQUEST_FAIL;` |
| 候选 | `:45`、`:54`（入口内的 `OnQueried(...)` 调用） |

依据：守卫 `:35` 在候选之前 → 身份两侧一致（基类子句写的接口名 == 守卫比较的接口名）。
这正是**「不靠类名约定猜接口」**的用例：类名带 `Stub`，接口名连 `I` 都没有。

### 4.3 `services/tokensyncmanager/src/service/token_sync_manager_stub.cpp`

| 位置 | 内容 |
|---|---|
| 类声明（`…/include/service/token_sync_manager_stub.h:26`） | `class TokenSyncManagerStub : public IRemoteStub<ITokenSyncManager>` |
| 守卫 | `:42` `if (descriptor != ITokenSyncManager::GetDescriptor()) {` → `:44 return ERROR_IPC_REQUEST_FAIL;` |
| 候选 | `:48/51/54`（入口内 switch 的三个 `*Inner` 调用）、`:83/110/127`（`IsRootCalling`）、`:104/121/136`（三个 handler 函数体） |
| 到达 | `:83/104` 经入口 `:48`；`:110/121` 经 `:51`；`:127/136` 经 `:54` |

全部 9 条的守卫都是 `:42`，都早于候选行。

### 4.4 一条必须单独说明的：`:83/110/127`

这三条在核查文档里被判为**「M3 机制」**（把授权谓词 `IsRootCalling` 当成了 handler），
但它们当时的**规则是 AUTH-01**，所以 M1 让它们一起消失了：

- M1 消掉的是「这条路径上缺描述符校验」这个**观测**，依据就是上面的守卫 `:42`；
- **「guard 函数被当成 handler」这件事本身，M1 没有修**。修复后 `IsRootCalling` 不再作为任何候选的
  symbol 出现，只是因为承载它的那条 AUTH-01 观测不存在了——**不能据此认为 M3 的缺陷消失了**。
  这一点留给 M3 复核时单独看。

## 5. 新增 0 条、理由变化 0 条——以及它意味着什么

- **新增 0**：修复没有引入任何新候选（含 `mismatch` / `unresolved` 两种本该新增或改写的观测）。
- **理由变化 0**：语料里**没有任何一条**候选的理由文本被改写。

诚实结论：**`mismatch` 与 `unresolved` 两条报文分支，本次语料没有行使到**——
五个组件里凡是出现 `GetDescriptor()` 比较的地方，两侧身份都一致。
这两档目前**只有 fixtures 的对照实验在支撑**（§7），没有真实语料证据。
不做「消掉约 20 条」式的验收：本报告接受的是**每条消失都能指到守卫行**，
而不是「数量下降」本身。

## 6. 存活的 24 条与各自的机制（M1 的能力边界）

| 组件 | 规则 | 条数 | 存活原因（已核实） |
|---|---|---:|---|
| `security_access_token` | AUTH-02 `ipc.auth.missing` | 3 | `token_sync_manager_stub.cpp:104/121/136`：授权在 `IsRootCalling`（`:83/110/127`）里，**入口→handler→授权谓词**多跳，且谓词体未被建模；属 M3 |
| `window_window_manager` | AUTH-01 | 1 | `screen_session_manager_stub.cpp:42`：实测 `OnRemoteRequest` **只转调** `OnRemoteRequestInner`（`:42`），真正的比较在 `:50` `if (data.ReadInterfaceToken() != GetDescriptor())`——**守卫隔了一次函数调用**（同文件跨函数），属 M2 |
| `window_window_manager` | AUTH-02 | 1 | `screen_session_manager_stub.cpp:738`：敏感调用 `GetDisplaySnapshot` 落在**描述符校验已通过**之后的路径上，但路径上没有可识别的**调用方授权**——AUTH-02 管的是权限这一轴，与接口身份无关 |
| `window_window_manager` | CAP-01 | 13 | `ipc.capability.export`，与描述符无关 |
| `communication_dsoftbus` | AUTH-01 | 2 | `core/bus_center/extend/src/bus_center_ex_obj_stub.cpp:56`、`core/transmission/broadcast/src/trans_spec_object_stub.cpp:62`：**这两个文件里根本没有 `GetDescriptor()` / `ReadInterfaceToken`**，分发经 `dlsym` 把 handler 从 dlopen 的 so 里取出来，且观测报在「取指针失败」的那条分支上；M1 的身份解析在这里没有可接受的对象，属跨模块/间接分发 |
| `communication_dsoftbus` | CAP-01 | 2 | 与描述符无关 |
| `update_updateservice` | AUTH-04 | 2 | `ipc.auth.guard-coverage`，守卫覆盖范围（支配性），属 M5 |
| `distributeddatamgr_kv_store` | — | 0 | 本就 0 条 |

24 条**全部**带义务（`entry_reachability` / `callee_and_policy` / `consequence` / `security_impact`，
部分带 `parse_completeness_impact`），`validated_vulnerability` 五个组件都是 0，
`evidence_type = syntax`、`severity/confidence = unassessed` 未变。

**结论**：M1 的边界是干净的——它只动「入口函数体内、支配候选的那一次比较的身份」；
**隔一次调用的守卫（M2）、谓词体未建模（M3）、常量域（M4）、支配性证明（M5）** 都不在它的射程内，
对应候选原样保留。

## 7. 正反例对照（11 个 fixture）

`tests/fixtures/ipc/descriptor_*.cpp`，全部进入 `manifest.json`（29 → 40 行，原有行未重排）：

| fixture | 期望 | 钉住什么 |
|---|---|---|
| `descriptor_interface_fixed.cpp` | 零 finding | 限定到本事务接口 → 接受 |
| `descriptor_no_prefix_fixed.cpp` | 零 finding | 接口名**无 `I` 前缀**（`OnPermissionUsedRecordCallback`）也接受，**不靠类名猜** |
| `descriptor_inherited_fixed.cpp` | 零 finding | 多级继承 `X : Mid : IRemoteStub<IFoo>` → 沿基类递归取到 `IFoo` |
| `descriptor_wrong_interface_positive.cpp` | AUTH-01，`mismatch` | 实现 `IFoo` 却比 `IBar` → 报文**同时列出** `IBar declared at …` 与 `this class implements IFoo (stated at …)`；带 `descriptor_identity_mismatch` |
| `descriptor_unrelated_positive.cpp` | AUTH-01，`mismatch` | 无关类里的**同名方法** `Unrelated::GetDescriptor()` → 不算本事务的守卫 |
| `descriptor_alias_positive.cpp` | AUTH-01，`unresolved` | `using AliasBase = IRemoteStub<IFoo>;` → **不猜**，报文说「not determined」，带 `descriptor_identity_unresolved` |
| `descriptor_unresolved_positive.cpp` | AUTH-01，`unresolved` | 类声明不在本分析单元 → unknown |
| `descriptor_call_only_positive.cpp` | AUTH-01，无 `mismatch` 义务 | 只取回没比较 |
| `descriptor_no_reject_positive.cpp` | AUTH-01，无 `mismatch` 义务 | 不匹配分支只记日志、不离开事务 |
| `descriptor_after_positive.cpp` | AUTH-01，行号 = `OnCallback()` 行 | 守卫在目标操作**之后** |
| `descriptor_one_branch_positive.cpp` | 被守卫分支零、另一分支 1 条 | 只覆盖一个分支 ≠ 支配 |

测试：`tests/test_ipc_descriptor_identity.py` **16 项**（身份来源 4 + 守卫判定 12 中含 4 个「有比较但不成守卫」）；
fixture 语义矩阵 `tests/test_ipc_detector.py` **17 项**。
分支总计：接口线分支 **391 项 OK**（修复前 375）；基于负责人集成分支的分支 **350 项 OK**。

## 8. M1 不做什么，以及已知限制

1. **不改 M2～M6**：本次提交只含描述符身份这一处（`analysis.py` / `detector.py` / `entry_index.py` /
   `models.py` 的加法式改动 + fixtures + 测试）。`m2_adapter.py`、支配性、常量域、跨文件委托都没碰。
2. **`mismatch` / `unresolved` 只有 fixture 证据**（§5），没有真实语料行使过。
3. **M3 的缺陷没有被修**（§4.4）：`IsRootCalling` 被当成 handler 只是不再承载 AUTH-01 观测。
4. **解析完整性**：五个组件在本次运行里 `coverage status` 都是 `partial`，
   仍带 `parse_completeness_impact` 义务。**「解析错误不在候选附近」不足以证明没有影响**——
   要排除影响需要「完整解析前后对比」或在关键样本上人工结构性确认；本报告没有做这件事，
   所以只写「**当前核查未发现直接关联**」，不写「无影响」。
5. **不是误报率**：核查文档里的 37 条 likely false positive **不是** Precision——
   没有独立标注集就不存在正式误报率，本报告不给出该数字。
6. **支配性只按同一套结构规则核对**：17 条都是「守卫在入口函数体内、早于候选、不匹配分支 return」，
   逐条读过钉住 commit 的源码；但**守卫语义之外的东西仍在义务里**（`ReadInterfaceToken` 的返回值是否可能为空、
   调用方能否控制 token、是否存在其它入口绕过该函数）。修复不改变这一点。
7. **未建模的额外守卫**：如 `accesstoken_callback_stubs.cpp:94-98` 的 `IsAccessTokenCalling()`
   没有进模型；本次消失**只**依据描述符守卫，不依据它。
8. 间接分发（`dlsym`/函数指针表）与别名基类仍然 `unknown`，保持候选不臆断。

## 9. 状态

- 修复提交：`3fe3537`（`feat/interface-m1-descriptor-identity`，**基于负责人已本地验证并推送的
  集成分支 `feat/owner-ipc-platform-integration` 的顶端 `86fbf99`**）。
- 同一份树改动在接口线上：`3d88ffc`（`feat/interface-ipc-detector`）。
- ~~两条**均未推送、未合并**~~；**（2026-10-16 更正）该判断已过期**：
  `feat/interface-m1-descriptor-identity` 已在远端（= `8464151`，含 `3fe3537`），
  接口线 `feat/interface-ipc-detector` 亦已在远端（其上的 `3d88ffc` 已随本分支推送）。
  **均仍未合并**。「是否推送/开 PR/合并由项目负责人决定」这一原则**不变**。
- **远端 CI 状态（2026-10-16 独立审查口径）**：M1/M2 分支的 head 未查询到 PR workflow run / status，
  **不得称其 CI 已通过**。它们的测试数是**本地回归**结果，不是远端 CI 结果。
- 顺带一行：`.gitignore` 增加 `outputs/reports/m1_descriptor_identity/`（与既有两条实验目录同格式）。
- 观察（未处理）：工作区有一个**未跟踪且未被忽略**的目录 `research/experiments/interface/ipc/results/`
  （内含 `evidence_manifest.json` / `synthetic.csv` / `historical.csv` 等），仓库里没有脚本会写它。
  本次没有添加它；提交时注意别被 `git add -A` 带进去。
