# 交付项 14：`caller-class` 的两类假阳性——一个可修点量到 −4，另一个不在规则层（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **worktree**：`/home/audit/ohscanner/worktrees/parallel-ipc-20261017`
- **规则来源（只读固定）**：`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`，
  分支 `feat/interface-ipc-detector`，HEAD `635b3e0449c552f0ccc25118850d245962845568`
  （`0.8.0` / `oh-ipc-2026.10-v6`）
- **前置**：交付项 9 测的是"补入口的覆盖上界"
  （[20261017-coverage-ceiling-measured.md](20261017-coverage-ceiling-measured.md)）；
  本项测的是同一批候选里**哪几条能由一条谓词规则修掉**，以及**哪一条根本不在规则层**。
- **证据**：`research/evidence/interface/ipc/caller_class_predicate_counterfactual_20261017/counterfactual.json`
- **本项不改检测器**：补丁只打在 `/home/audit/wtmp/` 下 pinned 树的**副本**上；pinned 树与
  本 worktree 的 `src/` 一行未动。

---

## 0. 一句话结论

交付项 9 §3.3 写的"两个成因，一个可修点"经实测应拆成两半：

- `security_access_token` 的 **4 条**能由**一条身份派生谓词规则**修掉：在同一仪器上复跑六个读数，
  **79 → 75，删除的正好是 4 条 `ipc.auth.caller-class`，新增 0**，其余逐条相同。
- `multimedia_camera_framework` 的 **1 条不在规则层**：它的守卫宏 `CHECK_RETURN_RET_ELOG`
  因定义体含 `##__VA_ARGS__` 且形参含 `...` 被宏展开器**拒绝**（`variadic_stringify_or_token_paste`），
  守卫从未进入被解释的程序。谓词建模、`do/while` 逃逸修复、两者合并，三档都改变不了这一条记录
  的**任何一个字段**。
- 因此这条谓词规则能拿到的精度收益是 **4 条（服务侧的 4/5）**，不是 5 条；把它说成"修掉
  camera 那条"会直接高估收益。

客户端 11 条在两档下**一条不变**，是负控制：规则没有无差别压掉候选。

## 1. 口径

沿用交付项 9 的 ceiling 探针（`research/deliveries/ipc/ceiling_probe_site/sitecustomize.py`），
两侧同仪器：

- 服务侧：`IPC_CEILING_MODE=strict SIDE=services OWNER=service`，5 个组件
  （`security_access_token`、`multimedia_camera_framework`、`multimedia_audio_framework`、
  `bundlemanager_bundle_framework`、`update_updateservice`）。
- 客户端侧：`SIDE=interfaces OWNER=any`，1 个组件（`security_access_token`）。
- 每个补丁副本从 `/home/audit/wtmp/detector-cf-*` 运行；基线是 pinned 树的只读运行
  `/home/audit/wtmp/ceiling-out-{services-service,interfaces-any}`。
- **仪器同一性由脚本强制**：对照脚本要求两侧 `snapshot_sha256`、`plan_sha256` 相同，且
  `(added_roots, skipped_by_side, skipped_by_owner, already_roots)` 相同，否则该行记为
  `scope_mismatch` / `roots_mismatch` 而不是"无变化"。本次六行全部通过。
- `ability_ability_runtime` 在这次复跑里**仍未跑完**（交付项 9 记录为超预算），证据里记为
  `not_run`，不是"无变化"。

补丁内容：

| 档 | 改动 | 文件 |
|---|---|---|
| tier 1 | 身份派生谓词：名字在已复核的位测试集合（`IsSystemApp` / `IsSystemAppByFullTokenID` / `IsSystemAppByTokenID` / `IsSystemAppByTokenId`），**且实参是调用者自己的 token**（`Value(kind="caller", subject="token")`，引擎已从 `GetCallingTokenID` / `GetCallingFullTokenID` 推出）→ `caller_class=system_app` | `cf_patch_pred.py 1` |
| tier 2 | tier 1 + 对两个"体在别的翻译单元、本次未读"的名字（`CheckSystemApp` / `CheckSystemAppByTokenID`）也记成同一事实 | `cf_patch_pred.py 2` |
| `dw` | `do_statement` 不再生成零次迭代逃逸（`analysis.py:1575` 的分叉只对其余循环保留） | `cf_patch_dw.py dw` |
| `dw+pred` | 两者合并 | `cf_patch_dw.py dw+pred` |

tier 1 的判别原则：**只读实参的来源，不假设被调函数体**。同一个名字若实参是 parcel 里读出的
token id 或进程自己的 token（`kind="self"`），不记该事实。

## 2. 六读数结果（候选身份 `(file, line, rule_id)`）

| 档 | 比较读数 | 基线 → 反事实 | 删除 | 新增 | 按规则删除 |
|---|---|---|---|---|---|
| tier 1 | 6 | 79 → **75** | 4 | **0** | `ipc.auth.caller-class` 4 |
| tier 2 | 6 | 79 → **75** | 4 | **0** | `ipc.auth.caller-class` 4 |
| `dw` | 6 | 79 → 79 | 0 | 0 | — |
| `dw+pred` | 6 | 79 → **75** | 4 | **0** | `ipc.auth.caller-class` 4 |

逐组件（基线 → 反事实）：

| 组件 | 读数 | 基线 | tier 1 / tier 2 | `dw` | `dw+pred` |
|---|---|---:|---:|---:|---:|
| `bundlemanager_bundle_framework` | services/service | 29 | 29 | 29 | 29 |
| `multimedia_audio_framework` | services/service | 6 | 6 | 6 | 6 |
| `multimedia_camera_framework` | services/service | 12 | 12 | 12 | 12 |
| `security_access_token` | services/service | 8 | **4** | 8 | **4** |
| `update_updateservice` | services/service | 2 | 2 | 2 | 2 |
| `security_access_token` | interfaces/any | 22 | 22 | 22 | 22 |
| `ability_ability_runtime` | services/service | — | `not_run` | `not_run` | `not_run` |

tier 2 与 tier 1 **逐读数完全相同**：`CheckSystemApp` 在这份语料里没有出现在任何被解释的
AST 中（原因见 §4），所以"多假定的两个名字"在本语料上价值为 0。这不表示这两个名字永远没用，
只表示它们在这批读数上没有增加任何一条收益。

表外还有一档 `dw+tier2`：它只在 camera 上定向复跑（`12 → 12`，`0 / 0`），其余六行在证据里
记为 `not_run`。这一档只用来证明 §4.1 的逐字段相同，不参与上面的总量。

## 3. 被删的 4 条：逐站点

四条都在服务侧，形态相同：**守卫就在源码里，只是引擎没把它记成 `caller_class`**。

| 站点 | 入口 | 源码里的守卫 |
|---|---|---|
| `accesstoken_manager_service.cpp:936` | `AccessTokenManagerService::GetReqPermissions` | `:926` `if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) return ERR_NOT_SYSTEM_APP;` |
| `privacy_manager_service.cpp:462` | `PrivacyManagerService::RemovePermissionUsedRecords` | `:453` 同一形状 |
| `privacy_manager_service.cpp:503` | `PrivacyManagerService::GetPermissionUsedRecordsAsync` | `:495` 同一形状 |
| `privacy_manager_service.cpp:633` | `PrivacyManagerService::IsAllowedUsingPermission` | `:625` 同一形状 |

`IsSystemAppCalling()` 是**本文件里的成员函数**（`accesstoken_manager_service.cpp:2813-2817`、
`privacy_manager_service.cpp:877-881`），体是：

```cpp
bool AccessTokenManagerService::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIDAttributes::IsSystemApp(fullTokenId);
}
```

`TokenIDAttributes::IsSystemApp` 的体在另一个翻译单元，引擎不读；所以包装函数被解释后，
内层调用只留下"名字 + 实参"。tier 1 规则匹配的正是这一步：**实参 `fullTokenId` 来自
`GetCallingFullTokenID()`，是调用者自己的 token**，于是返回值作为 `caller_class=system_app`
透出，守卫被记账，候选消失。

这四条在基线里的 `path=` 已经写着 `IsSystemAppCalling() => True`，而 `state.caller_class`
仍是空的——这正是交付项 9 §5 说的"`path=` 不是已入账"的一个实例。

**这四条是模型的假阳性，不是"发现了四个漏洞"。** 源码里既有类别判定，也有权限判定；
候选报的"缺少 caller-class 边界"在这四个入口上不成立。

## 4. camera 那条为什么三档都不动

### 4.1 记录逐字段相同

`hcamera_service.cpp:2621` 的 `ipc.auth.caller-class` 记录，在基线、tier 1、tier 2、`dw`、
`dw+pred`、`dw+tier2` 六个副本中**全字段相同**
（`research/deliveries/ipc/caller_class_record_identity.py`，逐字段比较，`differing=[]`）。
它的状态字段是：

```
file_analysis_status = not_analyzed
file_parse_status    = partial
file_analysis_reason = incomplete_ast:partial
passes               = ['all-files']
source_binding       = bound
path                 = ()
```

`path=()` 不是"守卫已入账"，也不是"守卫不存在"，而是**走查没有看到守卫**。

### 4.2 守卫宏没有被展开

`hcamera_service.cpp:2607` 的守卫是：

```cpp
CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
```

宏定义（`common/utils/camera_log.h:163-169`）：

```cpp
#define CHECK_RETURN_RET_ELOG(cond, ret, fmt, ...) \
    do {                                           \
        if (CAMERA_UNLIKELY(cond)) {               \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);     \
            return ret;                            \
        }                                          \
    } while (0)
```

展开器（pinned `cpp_macros.py:235-237`）在这个形状上直接拒绝：

```python
if "#" in body or (params is not None and "..." in params):
    refused.append((token, "variadic_stringify_or_token_paste"))
```

定义体含 `##`、形参含 `...`，两个条件同时命中。用真实计划、真实预算复现
（`catalog_for_units(units, 400, 6_000_000)` 后对真实 blob 调 `expand_with_catalog`）：

```
catalogue: sources=400 bytes=2013515 truncated=True
expansion: expansions=105 refused=842 fatal=[]
refusal reasons for this file: {'variadic_stringify_or_token_paste': 842}
=== expanded lines 2605..2634 of the target function
 2607|     CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");
```

`camera_log.h` 本身**在**目录里（预算内 index 22），所以这不是"头文件没被编目"的问题；
拒绝发生在"定义体不可安全展开"这一步。走查于是看到一条普通调用，守卫不可见，`path=()` 是必然结果。

### 4.3 由此得到的边界

- **谓词建模救不了它**：`CheckSystemApp()` 从未作为调用进入 AST，tier 2 的名字表没有匹配对象。
  这也解释了为什么 tier 2 与 tier 1 逐读数相同。
- **`do/while` 修复救不了它**：宏没展开，循环根本不存在。
- 若要让这条进入规则层，改动点在**展开器的拒绝策略**（或对该宏的特例接受），不在 `models.py`
  的谓词表；这是一个比"补个名字"大得多的决定，本项**没有**尝试，也不建议在没有独立语料
  核对前尝试。

## 5. 负控制：客户端 11 条不变

`interfaces/any` 的 `security_access_token` 在基线是 22 条（`caller-class` 11 + `auth.missing` 11），
tier 1、tier 2、`dw`、`dw+pred` 全是 22，逐条相同。客户端 kit/proxy 侧没有 `IsSystemApp(调用者token)`
这种谓词，规则也就没有可记的事实——补丁不会把"没有守卫"的地方当成"有守卫"。

这 11 条仍按交付项 9 §4 的结论处理：kit 运行在调用者自己的进程里，是发起方，没有"调用者类别"
可判；它们的去向是规则适用范围（是否应在客户端侧关闭），不是补一个谓词。

## 6. `dw` 的副作用：候选不变，但 pass 归属变了

这是本项新量到的、必须单列的一点。`dw` 在**候选身份**上六个读数全 0 变化，但 camera 的
**per-pass 诊断数**变了：

| 副本 | `complete-ast` 诊断 | `all-files` 诊断 |
|---|---:|---:|
| 基线 | 7 | 12 |
| `dw` / `dw+pred` | 7 | **5** |

少掉的 7 条都是 `ipc.relay.descriptor-boundary`（三个 callback stub 里的 7 个站点，
如 `hstream_capture_photo_callback_stub.cpp:32`），它们只剩 `complete-ast` 一个来源，
候选本身**没有丢**。其余五个读数（`bundlemanager`、`audio`、`security_access_token` 两侧、
`update`）在 `dw` 下 per-pass 数字完全不变。

机制没有完全定位：这些站点所在的文件里没有字面 `do {`，受影响的应当是
`CHECK_RETURN_RET`（`do { if (cond) { return ret; } } while (0)`）展开后的逃逸路径；
`dw` 去掉这条不可能路径后，`all-files` 不再产出这 7 条诊断，而 `complete-ast` 仍然产出
（同一个 `diagnostic_id`）。可以确定的是**方向**：这条修复在 `all-files` 上去掉的是
"跳过守卫"的假路径，没有让任何候选消失；但"只被 `all-files` 看到、`complete-ast` 看不到"
的站点在其他语料上会不会因此丢失，本次没有测。**因此本项不建议单独采纳 `dw`**：它没有
达成目标（camera 的 caller-class 不变），却带来了一个未完全定位的 pass 级行为变化。

证据 JSON 的每一行都带 `pass_runs_changed`（基线/反事实两边的 `status`、`analyzed_files`、
`diagnostics`），这一节不需要从候选数反推。四个档里被标出的行分别是：
tier 1 / tier 2 → `security_access_token` 服务侧（是 4 条被删的直接结果）；
`dw` → 只有 `multimedia_camera_framework`；`dw+pred` → 上述两者。

## 7. 回归控制

用 pinned 树**自己的** `tests/`（487 项）对五个副本各跑一遍，并与未打补丁的
`detector-cf-base` 对照：

| 副本 | 结果 | 失败 id 集合 |
|---|---|---|
| `detector-cf-base`（未打补丁） | 6 failures + 8 errors | 14 项 |
| tier 1 / tier 2 / `dw` / `dw+pred` | 6 failures + 8 errors | 与 base **逐行相同**（`failures.txt` md5 全为 `f10c7b93…`） |

失败 id 的差集为空，说明这些编辑对既有测试**不可见**。同时要说清两点：

- 早期用 **本 lane 的 `tests/`** 跑 pinned 0.8.0 会得到 46 failures + 19 errors，那是
  测试与源码版本不匹配，**不是**补丁效应；该次结果不作为控制，只作为"为什么改用 pinned
  自己的 tests"的理由。
- lane 现有夹具没有覆盖 `IsSystemApp(fullTokenId)` 这一形状（`auth03/caller_class_fixed.cpp`
  提的是 `IPCSkeleton::IsSystemAppCalling()`，不在新的名字集合里），所以"测试全绿"不能当作
  新规则有正例控制的证据；正例就是本项 §3 的四个真实站点。

`dw+tier2` 副本（`detector-cf-pred2dw`）只做了 camera 的定向复跑，没有重跑整套测试；
tier 2 在六个读数上与 tier 1 完全相同，`dw+pred` 的整套测试已覆盖同一组合。

## 8. 复现

```console
# 1) 建副本并打补丁（pinned 树只读；副本放在 /home/audit/wtmp 下）
cp -r <pinned>/src /home/audit/wtmp/detector-cf-pred1/src
python3 -I research/deliveries/ipc/cf_patch_pred.py \
    /home/audit/wtmp/detector-cf-pred1/src/ohscanner/detectors/interface/analysis.py 1
# tier 2 / dw / dw+pred / dw+tier2 同理，换 cf_patch_dw.py 的 mode

# 2) 同一 ceiling 仪器复跑六读数（仪器与输出根沿用交付项 9）
IPC_CEILING_MODE=strict IPC_CEILING_SIDE=services IPC_CEILING_OWNER=service \
PYTHONPATH=research/deliveries/ipc/ceiling_probe_site <venv>/python -m ohscanner... \
    --component security_access_token ...   # 输出根：ceiling-pred-<副本>-services-service

# 3) 对照（强制两侧哈希与 roots 相同，并写证据 JSON）
python3 -I research/deliveries/ipc/cf_compare_pred.py

# 4) camera 记录在六个副本中的逐字段比对
python3 -I research/deliveries/ipc/caller_class_record_identity.py

# 5) 宏展开的定向复现
python3 -I research/deliveries/ipc/macro_expand_probe.py
python3 -I research/deliveries/ipc/macro_budget.py <report.json> <corpus> <path>...
```

第 2 步的具体调用封装在 `/home/audit/wtmp/ceiling_pred.sh`（本机运行位置，未随仓库交付）；
它与交付项 9 的 `ceiling_run.sh` 只差 `cwd` 指向补丁副本。

证据 JSON 由 `cf_compare_pred.py` 写入
`research/evidence/interface/ipc/caller_class_predicate_counterfactual_20261017/counterfactual.json`，
其中 `tier_runs` 含每一档的逐组件行、删除/新增清单和 `not_compared`。

## 9. 对 0.8.0 的具体建议

1. **采纳 tier 1 的谓词规则**：按"实参是调用者 token + 名字在位测试集合"记账，不按名字猜体。
   本语料收益 4 条，全部是假阳性；不新增候选。
2. **不要把 tier 2 当作已证收益**：它对这份语料贡献 0；若采纳，必须标注"名字级假定"，
   并等有 `CheckSystemApp` 真实出现在完整 AST 的语料再量。
3. **不要为 camera 那条改谓词表**：它被宏展开器挡在门外；改动点在展开器拒绝策略。
4. **不要单独采纳 `dw`**：候选零收益，且 `all-files` pass 的 AUTH-01 诊断 12 → 5（候选仍在），
   这个变化的机制未完全定位。
5. 上述结论都是**模型层**的：删除的是假阳性，不是确认漏洞；`validated_vulnerability` 仍为 0，
   `confirmed` 仍为 0。
