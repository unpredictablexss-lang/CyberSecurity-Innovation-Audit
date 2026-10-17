# 交付项 4：六条静默规则的形状普查（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **语料**：交付项 3 的同一批 18 个组件、同一批**已扫描文件**（从各报告
  `scope.shards[].paths` 取出，共 10,413 个），同一批 pinned commit
- 相关：[交付项 3 实测](20261017-six-family-component-measurement.md)、
  [交付项 2 控制](20261017-six-family-depth-unit.md)

---

## 0. 一句话结论

交付项 3 说"11 条规则只有 5 条命中过"。这次回答了**为什么**：四条是**语料里根本没有
那个形状**（规则未被行使，不是规则坏了）；`caller-class` 一条是**可达它的分发器
由 IDL 在构建期生成、不在源码树里**（覆盖问题）；`copy-range` 一条是**形状大量存在但
几乎都不在入口处理函数里**（待逐条核）。另外 `object-owner` 的**形状数 2 与候选数 2
精确吻合**，是这条规则按设计工作的正面证据。

## 1. 方法

形状来自 `models.py@635b3e0` 的 `IpcPolicy` 常量表（**规则实际读的那张表**，
不是我猜的词表）：

| 规则 | 形状常量 |
|---|---|
| `caller-class` | `caller_class_sensitive_calls` = `GetReqPermissions` / `StartUsingPermissionCallback` / `RemovePermissionUsedRecords` / `GetPermissionUsedRecordsAsync` / `IsAllowedUsingPermission` / `SetMutePolicy` |
| `identity-domain` | `result_permissions` = `{VerifyAccessToken, VerifyNativeToken}` 且实参为 `caller_uid_calls` = `{GetCallingUid, GetCallingUID}` |
| `position-underflow` | `RewindRead(<表达式含减号>)` |
| `copy-range` | `copy_calls` = `{memcpy, memmove, memcpy_s, memmove_s, ReadRawData, ReadBuffer}` |
| `object-owner` | `owner_calls` = `{GetOwnerUid, GetOwnerUID, GetResourceOwnerUid}` |

统计在**报告声明的已扫描路径**上做（不是全仓库），因此与候选数同一口径。
脚本放在 `research/deliveries/ipc/`（本线允许面内；`research/experiments/` 不是），
形状直接读 `IpcPolicy` 常量，不是重打的词表：

```console
$ cd <repo root>
$ .venv-web/bin/python research/deliveries/ipc/silent_rule_shape_census.py \
    --audit-root <每组件 report.json 的目录> \
    --corpus-root <corpus root> [--corpus-root <corpus root>]
components measured: 18
```

脚本会跳过 `shard_errors` 非空或 `repository` 不含 `/` 的报告（失败运行同样是 0 候选，
见交付项 3 §5.2），因此它只统计真正跑过的 18 个组件。

## 2. 结果

| 形状 | 语料中出现 | 命中规则 | 判定 |
|---|---|---|---|
| `RewindRead(<含减号>)` | **0**（`RewindRead(` 本身 19 次，分布 comm_ipc 18 / imf 1） | 0 | **未被行使** |
| `Verify*Token(...GetCallingUid...)` | **0**（`Verify*Token(` 本身 190 次、14 个组件；`GetCallingUid` 1130 次、18 个组件，但**两者从不组合**） | 0 | **未被行使** |
| 6 个 caller-class 具名调用 | **70**（`security_access_token` 59、camera 6、audio 3、bundle 2） | 0 | **覆盖问题**，见 §3 |
| `memcpy`/`ReadBuffer` 等 | **665**（15 个组件） | 0 | **待逐条核**，见 §4 |
| `GetOwnerUid` 等 | **2**（仅 `resourceschedule_background_task_mgr`） | **2**（同一组件同一规则） | **精确吻合** |

普查脚本：`/home/audit/wtmp/shape_census.py`、`/home/audit/wtmp/shape_where.py`
（只读打开文件做正则匹配，不写任何产物）。

## 3. `caller-class` 的 70 次：可达它的分发器不在源码里

59 次落在 `security_access_token`，逐文件：

```text
  9  services/privacymanager/src/service/privacy_manager_service.cpp
  9  interfaces/innerkits/privacy/src/privacy_manager_client.cpp      <- 客户端 proxy
  6  interfaces/innerkits/privacy/src/privacy_kit.cpp                 <- 公开 kit
  5  services/privacymanager/include/service/privacy_manager_service.h
  4  services/accesstokenmanager/main/cpp/src/service/accesstoken_manager_service.cpp
  ...
```

两组要分开看：

- **声明与调用方**（`privacy_kit.h/.cpp`、`privacy_manager_client.cpp`、
  `accesstoken_manager_client.cpp`）：那是**客户端接口面**，不是入口路径。规则要求
  该调用出现在**从 IPC 入口可达的路径**上，客户端 proxy 自然不满足。
- **服务实现**（`privacy_manager_service.cpp` 9 次、
  `accesstoken_manager_service.cpp` 4 次）：这一组才是应该命中的。它没有，原因是
  **分发器不在源码树里**：
  - `services/privacymanager/idl/IPrivacyManager.idl` **在**（声明接口
    `OHOS.Security.AccessToken.IPrivacyManager`）；
  - `privacy_manager_stub.cpp` / `PrivacyManagerStub::OnRemoteRequest` **不在**仓库内
    （`git ls-files` 只有 `privacy_manager_client.cpp` 与 `privacy_manager_service.cpp`；
    `privacy_manager.gni` 的 `sources` 也不含 stub）；
  - 同理 `services/accesstokenmanager/idl/IAccessTokenManager.idl`。
  - 也就是说 **stub 由 IDL 在构建期生成**，被扫描的源码里**没有那个入口**，
    于是"入口 → 敏感调用"的路径不存在，规则无候选可出。

  这与既有的 IDL 覆盖缺口结论一致（IDL 生成分发器的组件"0 候选"只是**覆盖陈述**）。
  **要修的是覆盖，不是规则**：把 IDL 纳入入口建模，或在报告里把
  "该组件的入口由 IDL 生成、不在扫描范围"显式写成一条 limitation，而不是留一个 0。

- camera 那 6 次（`camera_privacy.cpp` 等）不在入口处理函数上（camera 的入口
  `HCameraService` 确实被建模，同一文件上 AUTH-02 命中过 1 条），所以不构成反例。

## 4. `copy-range` 的 665 次：几乎都不在入口处理函数里

`communication_ipc` 的 116 次分布：

```text
 16  ipc/native/c/manager/src/serializer.c          <- 传输层序列化
 10  interfaces/innerkits/cj/src/ipc_ffi.cpp        <- 客户端 FFI
  9  ipc/native/src/core/framework/source/buffer_object.cpp
  8  ipc/native/c/rpc/src/dbinder_invoker.c         <- 传输层
  6  dbinder/c/src/dbinder_service.c
  5  dbinder/dbinder_service/src/dbinder_service_stub.cpp   <- 这条是入口
```

绝大多数落在**序列化/传输层**，不是 `OnRemoteRequest` 处理函数。规则要求的是
"拷贝长度与 parcel 取出的长度**配对**"的形态，传输层的 memcpy 不构成这个形态。
`dbinder_service_stub.cpp` 的 5 次是入口内的，值得逐条核**为什么没配对上**
——本次**未做**，列在 §5。

## 5. 这条普查支持什么、不支持什么

**支持：**

- `identity-domain` 与 `position-underflow` 的静默**不是规则缺陷**：它们的形状在
  1.53M 行 / 18 个组件里出现 0 次。要行使它们，需要**换语料**（找真正做身份域判断或
  parcel 位置回退的组件），或**合成语料**（交付项 2 的夹具已经证明规则能响）。
- `caller-class` 的静默**主因是覆盖**：IDL 生成的 stub 不在源码树，入口根本不可见。
  这条**可以直接改进**，且改的不是规则。
- `object-owner` 的形状数 = 候选数 = 2，**规则按设计工作**；这是本次唯一一条
  "形状与命中精确对应"的规则，可作为其它规则的标尺。

**不支持：**

- 不能说这四条规则"没用"。它们的形状在本语料里没有出现，这是**语料性质**，
  不是规则性质。
- 不能反过来说"形状出现就一定该命中"：`copy-range` 的 665 次里绝大多数明确不在
  入口路径上，逐条核过之前不能算漏报。
- 正则统计的是**文本出现次数**，不等于解释器认定的**路径上的敏感调用**；
  两者的差正是 §3/§4 在解释的东西。

## 6. 未做 / 下一步

1. `copy-range`：把 `dbinder_service_stub.cpp` 等**入口内**的拷贝逐条核到
   "长度是否来自 parcel、目的地上界是否被检查"，判定是漏报还是正确静默。
2. `caller-class`：把 IDL 入口纳入建模（`services/*/idl/*.idl` 已有 6 个），
   或在报告 limitation 里显式声明该组件的入口在生成代码里。
3. 换语料行使 `identity-domain` / `position-underflow`：按形状（而非按组件名）
   挑选目标仓库。
4. 普查脚本已入库（`research/deliveries/ipc/silent_rule_shape_census.py`），
   但**本次普查的数字未作为产物入库**：它依赖 `/home/audit/wtmp/ipc-audit` 下不入 Git 的
   `report.json`（驱动规定生成物在 Git 之外），与本报告的数字一致。
   若要长期复现，需先重跑交付项 3 的 18 次审计。
