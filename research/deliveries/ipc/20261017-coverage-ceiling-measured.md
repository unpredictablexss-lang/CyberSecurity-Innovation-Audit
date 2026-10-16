# 交付项 9：覆盖收益上界实测——补上入口能拿到候选，但没有一条是这条规则的成绩（2026-10-17）

lane `lanes.ipc`，branch `work/ipc-20261017`，base `6a41dc9b`。检测器**一行未改**
（`0.8.0` / `oh-ipc-2026.10-v6`，pinned 只读树 `635b3e0449c552f0ccc25118850d245962845568`）。
证据：`research/evidence/interface/ipc/ceiling_20261017/ceiling_yield.json`
与同目录 `roots/*.json`（仪器自己记录的每一条被补上的入口根）。
仪器：`research/deliveries/ipc/ceiling_probe_site/sitecustomize.py`，
sha256 `54ff14ab39f8dcd48703cb9aa32978408429aac015f7e796bebf329826378a5c`（全批次同一份）。

## 0. 一句话结论

交付项 4/5/7/8 把三条静默规则的成因定为**覆盖**，并说"补上入口建模**可能**多出候选"，
但那个收益**当时没有量**。本项量了。按最紧的入口口径（只把 `*Service` / `*Stub` 类里命中
策略名的方法补成入口根）在 5 个组件上跑同一个检测器：

```text
46 → 57  候选 +11，其中 ipc.auth.caller-class +5
```

然后逐条读源码：**这 5 条 `caller-class` 全部落在已经做过后缀检查的处理器内部**，
而被建模成"敏感调用"的那次调用，在这 5 条里**没有一条是本处理器对外暴露的那个操作**——
4 条是同进程 manager 调用，1 条是**跨服务**的客户端 kit 调用。

所以 `caller-class` 的 0 **既不是**"没有缺口"、**也不是**"补上入口就够了"：
两处必须同时改——**入口建模** 与 **守卫入账**。只补入口，多出来的主要不是召回。

## 1. 一件仪器，四档口径

`ceiling_probe_site` 只做一件事：`_entry_roots()` 包一层，在检测器自己算出的入口根之后，
把"命中了策略名、但这次走查永远走不到"的函数**追加**成入口根；其余（含 `analysis.py:1036`
的敏感效应前置）一律不动，报告由真检测器产出。因此每个数都是"**同一个检测器**在一个放宽的
可达性假设下会产出什么"，是**上界**，不是检测器行为，更不是"这些候选是真的"。

四档口径，差异只在补哪些根：

| 口径 | 环境变量 | 补进来的根 |
|---|---|---|
| 宽松 | `MODE=strict SIDE=all OWNER=any` | 任何体内出现策略名的函数 |
| 服务侧 | `SIDE=services OWNER=any` | 其中路径含 `services/` 的 |
| **最紧（本项主口径）** | `SIDE=services OWNER=service` | 且 owner 类名以 `Service` / `Stub` 结尾 |
| 客户端 | `SIDE=interfaces OWNER=any` | 路径含 `interfaces/` 或 `frameworks/` 的 |

`MODE=strict` 给补进来的根绑 `params=()`：调用变得可达，**参数不会变成请求派生值**。
不这样做的话，一个非入口函数的形参会按 `run()` 的默认绑成 `request`，
那就把"可达性"和"形参建模"两件事混在一个数里了。

口径的**服务侧 / 客户端**之分不是分类癖：OH 的客户端 proxy 与 kit 是**在树内**且**与它调用的
服务方法同名**的，而子系统**主服务分发器**由 IDL 生成、不在源码树里（回调 stub 是手写的、
在树内，所以基线里 `security_access_token` 的 27 个入口根全在 `interfaces/` 的 `*_stubs.cpp` 上）。
两个桶混在一起报，就把这件事盖掉了。

## 2. 实测

主口径（`services` / `service`），5 个组件：

| 组件 | 基线候选 | 上界候选 | Δ `caller-class` | 补进的根 |
|---|---|---|---|---|
| `security_access_token` | 0 | **8** | **+4** | 214 |
| `multimedia_camera_framework` | 9 | 12 | **+1** | 27 |
| `multimedia_audio_framework` | 6 | 6 | 0 | 78 |
| `bundlemanager_bundle_framework` | 29 | 29 | 0 | **0** |
| `update_updateservice`（冒烟） | 2 | 2 | 0 | 2 |
| **合计** | **46** | **57** | **+5** | 321 |

逐规则：`caller-class` **+5**、`guard-coverage` +3、`auth.missing` +3，其余四条规则 **0**。

两个"零"是不同类型的零，都有信息：

- `bundlemanager_bundle_framework` 的 `*Service`/`*Stub` 方法里命中策略名的**一个都没被补**
  （`0` 条），因为它有 311 个基线入口根——回调 stub 在树内，这批形状**基线本来就覆盖**。
- `multimedia_audio_framework` 补进 78 个根，候选数**一动不动**：形状够得着了，
  但都过不了敏感效应前置。

客户端口径只跑了 `security_access_token`（83 个调用点里 58 个在它身上）：

| 口径 | 组件 | 基线 | 上界 | Δ |
|---|---|---|---|---|
| `interfaces` / `any` | `security_access_token` | 0 | **22** | `caller-class` +11、`auth.missing` +11 |

**没跑到的部分，明写**：`ability_ability_runtime`（83 个调用点里的 1 个）在 `services/service`
主口径下跑超预算——基线 125 s，实测 17 min 仍未结束，被中止——所以**不在上表里**。
客户端口径只覆盖 1 个组件，不是 5 个。这两处都是覆盖缺口，不是"没变化"。

## 3. 服务侧 5 条：逐条读源码

### 3.1 `security_access_token` 的 4 条是同一形态

`services/privacymanager/src/service/privacy_manager_service.cpp`：

```cpp
int32_t PrivacyManagerService::RemovePermissionUsedRecords(AccessTokenID tokenId, const std::string& enhancedIdentity)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return PrivacyError::ERR_NOT_SYSTEM_APP;                          // 453-455
    }
    if (!VerifyPermission(PERMISSION_USED_STATS) &&
        !VerifyPermission(REMOVE_PERMISSION_USED_RECORD)) {
        return PrivacyError::ERR_PERMISSION_DENIED;                       // 456-459
    }
    ...
    return PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId, enhancedIdentity);  // 462 ★
}
```

`:503`、`:633` 形态完全相同；`accesstoken_manager_service.cpp:936` 是同一形态的另一个实例
（守卫在 `926-928` / `929-933`，敏感名落在 `936` 的
`PermissionManager::GetInstance().GetReqPermissions(...)` 上）。

★ 那一行是**同进程的 manager 调用**，不是对外暴露的那个操作。对外暴露的
`PrivacyManagerService::RemovePermissionUsedRecords` 是**这个函数本身**，而它在 453 与 456
两处都做了检查。候选说的"lacks a caller-class/system-application boundary"，
读源码读不出来。

这条候选的 `message` 里 `path=` 是：

```text
((453, 'AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP => True'),
 (453, 'IsSystemAppCalling() => True'),
 (456, 'VerifyPermission(PERMISSION_USED_STATS) => True'))
```

**同一个站点上 `ipc.auth.missing` 没有发**（`:462` 只有 `caller-class` 一条）。
AUTH-02 的条件是 `not self.authorized(state, name)`（`analysis.py:1031`），它不响
⇒ `authorized()` 为真 ⇒ 那条权限守卫**已经入账**；而 AUTH-03 的条件是
`not state.caller_class`（`analysis.py:1037`），它响了 ⇒ `state.caller_class` 是空的。
**两条 emit 条件的差就是这一条的完整证明**，不需要再补别的证据。也就是说：
同一条路径上，权限事实进了状态而角色事实没进，而规则只问角色。

角色事实为什么没进？`IsSystemAppCalling` 在 `models.py:179` 的 `caller_role_guards` 里**是有的**，
但那条表有一条明确策略（`models.py:171-175`）：*"Read only for a call this file does not itself
define"*。而 `privacy_manager_service.cpp:877` 与 `accesstoken_manager_service.cpp:2813`
**各自定义了一个同名的**：

```cpp
bool PrivacyManagerService::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIDAttributes::IsSystemApp(fullTokenId);      // frameworks/common/src/tokenid_attributes.cpp:80
}
```

`TokenIDAttributes::IsSystemApp` 的体是 `(id & SYSTEM_APP_MASK) == SYSTEM_APP_MASK`——
**没被建模**，于是本地包装求值成 `unknown`，`caller_class` 推不出来。

### 3.2 `multimedia_camera_framework` 那条是**另一种**成因

`services/camera_service/src/hcamera_service.cpp`：

```cpp
int32_t HCameraService::MuteCameraPersist(PolicyType policyType, bool isMute)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HCameraService::CheckSystemApp fail");  // 2609
    ...
    int32_t ret = CheckPermission(OHOS_PERMISSION_CAMERA_CONTROL, callerToken);                            // 2612
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "CheckPermission arguments failed!");                     // 2613
    ...
    ret = Security::AccessToken::PrivacyKit::SetMutePolicy(secPolicyType, secCaller, isMute, callerToken); // 2621 ★
```

这里谓词**根本没被命名**：`CheckSystemApp` 在 `models.py` 与 `analysis.py` 里**一次都没出现过**。
它是 `camera_util.cpp:463` 的自由函数：

```cpp
bool CheckSystemApp()
{
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    CHECK_RETURN_RET_DLOG(tokenType != TOKEN_HAP, true, "Caller is not a application.");
    uint64_t accessTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApplication = TokenIdKit::IsSystemAppByFullTokenID(accessTokenId);
    return isSystemApplication;
}
```

而 ★ 那一行更彻底：`PrivacyKit::SetMutePolicy` 是**客户端 kit**，调用它的是 camera 服务自己，
敏感操作属于 privacy 服务。**camera 服务在这条语句上不是被检查方，是发起方。**

### 3.3 两个成因，一个可修点

| 组件 | 谓词 | 为什么没入账 |
|---|---|---|
| `security_access_token` | `IsSystemAppCalling`（**已命名**，`models.py:179`） | 同名本地定义把它**遮蔽**了，策略故意改为"解释其体"，体终止于未建模的 `TokenIDAttributes::IsSystemApp` |
| `multimedia_camera_framework` | `CheckSystemApp`（**未命名**） | `models.py` / `analysis.py` 里没有这个名字；体终止于未建模的 `TokenIdKit::IsSystemAppByFullTokenID` |

两者都终止于**"拿调用者的 full token id 做一次位测试"**这一个未建模的身份派生谓词。
所以可修点是**一个**：把这类谓词（按"实参是调用者 token"识别）建模成 `caller_class` 事实，
并让"体内只剩它"的同名包装（无论成员函数还是自由函数）把返回值透出来。
这落在 `models.py` + `analysis.py` 的谓词推导里——并发 import 正在写的文件，本线只测不改。

**但"往 `caller_role_guards` 里加两个名字"这条廉价修法是空的**，这是控制流事实、不是猜测
（pinned 树 B `analysis.py:1300-1319`）：

```python
helper = self.resolve(fn, callee)          # 1300  先在同文件里找定义
if helper is not None:
    self.note_shadowed_role_predicate(helper)   # 1304  记下"这个名字被本地体顶替了"
implementation = guard = None
if helper is None:                          # 1306  ← 已命名谓词表只在这个分支里被查
    ...
    for role_name, role_kind, role_label in self.policy.caller_role_guards:   # 1317
        if role_name == name:
            return Value("predicate", predicate=(role_kind, role_label, True))
```

即 `caller_role_guards` **只在调用无法在本文件内解析时**才被查；文件自己定义了同名函数，
就**永远不会**走到那张表。所以对 `IsSystemAppCalling` 这类被遮蔽的名字加表项是**无操作**
——"补个名字就好"这条预期在本语料上不成立。

**位测试本身也不是字面量。** `SYSTEM_APP_MASK` 要跨两级 constexpr 才落到值：

```cpp
// frameworks/common/src/tokenid_attributes.cpp
static constexpr uint32_t TOKEN_ID_LOW_BITS = 32;                              // :22
static constexpr uint32_t SYSTEM_APP_ATTR_INDEX = 0;                           // :23
static constexpr uint64_t GetFullTokenAttrMask(uint32_t attrIndex)             // :26-29
{ return static_cast<uint64_t>(1) << (TOKEN_ID_LOW_BITS + attrIndex); }
static constexpr uint64_t SYSTEM_APP_MASK = GetFullTokenAttrMask(SYSTEM_APP_ATTR_INDEX);  // :36
bool TokenIDAttributes::IsSystemApp(uint64_t id)                               // :80-83
{ return (id & SYSTEM_APP_MASK) == SYSTEM_APP_MASK; }
```

结论：语义上就是 **full token id 的第 32 位**（`test/fuzztest` 里的独立写法
`static const uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);` 可作旁证），
但源码里这一步是"常量折叠 + 跨 TU 调用"，不是 `id & 0x100000000`。
所以请求不是"补两个名字"，而是**新增一条评审过的身份派生**：
"`(调用者 full token id & M) == M`，M 折叠为第 32 位 ⇒ `system_app`"，
外加让同文件同名包装的返回值透出来。

## 4. 客户端 11 条：名字相同，边界不在这一侧

`interfaces/` 那 11 条 `caller-class`，owner 全是客户端：

```text
AccessTokenKit::GetReqPermissions            accesstoken_kit.cpp:561
AccessTokenManagerClient::GetReqPermissions  accesstoken_manager_client.cpp:353
PrivacyKit::RemovePermissionUsedRecords      privacy_kit.cpp:220
PrivacyManagerClient::StartUsingPermission   privacy_manager_client.cpp:368
PrivacyManagerClient::RemovePermissionUsedRecords / GetPermissionUsedRecords / SetMutePolicy / ...
```

`accesstoken_kit.cpp:552-561` 是完整形态：

```cpp
int AccessTokenKit::GetReqPermissions(AccessTokenID tokenID, ...)
{
    if (tokenID == INVALID_TOKENID) { return AccessTokenError::ERR_PARAM_INVALID; }
    return AccessTokenManagerClient::GetInstance().GetReqPermissions(tokenID, reqPermList, isSystemGrant);  // 561 ★
}
```

★ 是**跨进服务**的那一步（proxy 调用）。kit 运行在**调用者自己的进程里**，
它就是发起方，没有"调用者类别"可判。候选报的"缺少 caller-class 边界"在这一侧不成立。

**这 11 条一行代码都不能当成绩**。它们和 3.1/3.2 是同一件事的两个方向：
策略按**名字**认敏感调用，而同一个名字同时被"服务里的处理器""服务里的同进程 manager"
"客户端 kit / proxy"三种角色使用。

## 5. `path=` 不是"守卫已入账"的证据

第 3.1 节的 `path=` 里写着 `IsSystemAppCalling() => True`，但那一行的
`state.caller_class` 是**空的**。两者不矛盾：`refine()` 的兜底分支
（`analysis.py:1552-1553`）**无条件**追加 trace，无论有没有推出 `predicate`：

```python
out.trace=(out.trace+((node.start_point[0]+1,fn.text(node)+" => "+str(truth)),))[-20:]
```

所以 `path=` 记录的是"**走查判定了这个条件为真**"，不是"**这个守卫被 credit 成了事实**"。
读候选时不能把前者当后者——本项的三条实例都踩在这个区别上。

## 6. 诚实分开：AUTH-02 那 3 条是 plausible，不是误报

`:1249` / `:1274`（`GrantPermission` / `RevokePermission`）与 camera `:2621` 上
**三条规则同时发了**（`caller-class` + `guard-coverage` + `auth.missing`）。
`:1249` 的 `path=` 是：

```text
(1233, 'ret != RET_SUCCESS => False')
(1237, 'this->GetTokenType(callingTokenID) == TOKEN_HAP => False')
(1241, 'IsPrivilegedCalling() => False')
(1242, 'VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED => True')
(1243, 'IsShellCallingForDebugHap(tokenID) => True')
```

即 `X && Y && Z` 里 Z 为假（shell-debug 逃生口成立）⇒ 守卫不返回 ⇒ 落到 `:1249`。
这是一条**源码里真实存在的路径**：非 HAP、非特权、权限校验失败的调用者，
只靠 `IsShellCallingForDebugHap` 放行。`state.auth` 里自然没有事实，
所以 `authorized()` 为假、AUTH-02 发声**没有说错**。

**本项的判定**：`caller-class` 那 5 条是**精度损失**（源码在同路径上做了它说没有的检查，可逐条指出）；
这 3 条 AUTH-02/AUTH-04 **不是**误报，是带着 review obligation 的 `candidate`——
通向它的路径在源码里，是否可达、逃生口是否过宽，是**没做的事**。
两类必须分开报，混在一起会把 8 条说成同一件事。

（`guard-coverage` 的来源也要说清：`analysis.py:1696-1703` 的修订趟把已有的
`ipc.auth.missing` 观察**再追加一条** AUTH-04，原观察保留。所以同一站点上
AUTH-02 与 AUTH-04 成对出现，AUTH-04 不是独立检测。）

## 7. 复现

```bash
# 仪器（本项新增，只读测量）：research/deliveries/ipc/ceiling_probe_site/sitecustomize.py
# 驱动树是 pinned 只读树 B（cwd 必须是它）
cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b   # HEAD 635b3e0
IPC_CEILING_LOG=<out>/<component>/ceiling.json \
IPC_CEILING_MODE=strict IPC_CEILING_SIDE=services IPC_CEILING_OWNER=service \
PYTHONPATH=<worktree>/research/deliveries/ipc/ceiling_probe_site \
  .venv/bin/python -m src.ohscanner.detectors.interface.audit \
    --repo-dir <corpus>/<component> --repository <name> --commit <sha> \
    --out-dir <out>/<component> --json-out <out>/<component>/report.json \
    --md-out <out>/<component>/report.md

# 汇总（必须在仓库根跑，工具按相对路径哈希自己的仪器）
.venv-web/bin/python research/deliveries/ipc/ceiling_yield.py \
  --baseline-root <reports> \
  --reading services=<services-out> --reading interfaces=<interfaces-out> \
  --instrument research/deliveries/ipc/ceiling_probe_site/sitecustomize.py \
  --out research/evidence/interface/ipc/ceiling_20261017/ceiling_yield.json
```

汇总工具**按每个 reading 实际覆盖的组件**取基线，不拿整个基线比一个子集——
否则没跑到的组件会被算成"减少了候选"。同仪器同 argv 复跑一次，数字逐字相同
（`security_access_token` 客户端口径在冻结仪器前后两次都是 22）。

## 8. 这些数字**不**说明什么

- 它们是**上界**，且是"我把这些函数当入口根"的上界。真做 IDL 入口建模时，
  哪些函数真的会成为入口根由分发器决定，不会正好是这 321 个。
- `ability_ability_runtime` 没跑完、客户端口径只覆盖 1 个组件——两处都是**覆盖缺口**。
- 上界里**没有一条**做过可达性、攻击者控制或 CIA 影响的验证；`confidence` 全是 `unassessed`。
  **零候选不等于组件安全。**
- 逐条读源码判定的"精度损失"是**本线对 5 处的阅读**，不是对这 5 条候选的最终裁定；
  它们仍然是 `candidate`，撤销与否属集成人的裁定面。
- 没有改任何规则、没有动 `trusted_uids`、没有加白名单。候选集在基线侧仍是 **166** 条。

## 9. 对集成人请求的修订（取代交付项 4 的对应段落）

交付项 4/5/8 把 `caller-class` / `service-identity` / `position-underflow` 的修法写成
"跨 TU 一跳 + IDL 入口建模"。本项测下来，**这个修法单独做会降精度**，请求改成两条一起：

1. **入口建模**（原请求，保留）：让 IDL 生成的分发器对应的处理器成为入口根。
   收益上界本项已量：5 个组件 `+11`，`caller-class` `+5`。
2. **身份派生谓词建模**（本项新增，必须同时做）：把"实参是调用者 token 的
   system-app 位测试"（`TokenIDAttributes::IsSystemApp`、
   `TokenIdKit::IsSystemAppByFullTokenID`，以及体内只剩它们的同名包装
   `IsSystemAppCalling` / `CheckSystemApp`）建模成 `caller_class` 事实。
   不做这一条，第 1 条新增的 5 条 `caller-class` 全部是精度损失。
   **这条请求的形状要说准**（§3.3 有代码依据），它不是"往 `caller_role_guards`
   里加两个名字"：
   - `caller_role_guards` 只在 `helper is None`（`analysis.py:1306`）时被查，
     同文件定义了同名函数就永远走不到它 —— 加表项对本语料**无操作**；
   - 要新增的是一条**评审过的身份派生**："`(调用者 full token id & M) == M`，
     `M` 折叠为第 32 位 ⇒ `system_app`"，`M` 需跨两级 constexpr
     （`tokenid_attributes.cpp:22/:23/:26-29/:36`）折叠，不是字面量；
   - 另需让"体内只剩这条派生的同文件同名包装"把返回值透出来（成员函数与自由函数两种形态）。
3. `caller-class` 的 emit 条件是否应当读 `state.auth`（`analysis.py:1037`）
   ——这是**规则语义**问题，不是覆盖问题：一条被权限检查守住的路径是否也算
   "缺少 caller-class 边界"。本项只把两侧证据摆出来（§3.1 的两条 emit 条件之差），
   改法由集成人定。
