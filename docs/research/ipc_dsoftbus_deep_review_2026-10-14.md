# communication_dsoftbus 四条候选深审：守卫证据与外部实现缺口（2026-10-14）

- 输入：当前检测器（`ohscanner.interface.ipc@0.5.0+oh-ipc-2026.10-v3`）对
  `openharmony/communication_dsoftbus` 的 **4 条候选**。
- 产出：每条候选的**调用路径、守卫证据、跨 TU/外部缺口**；**不是**新的漏洞结论。
- 判定分布：**likely false positive 2 条**（守卫在派发层且支配）、**external gap 2 条**（实现不在本仓库，本仓库无法判定）。
- `validated_vulnerability` 仍为 **0**。

## 0. 一句话结论

本组 4 条没有一条能走到证据门。两条 CAP-01 的守卫**就在同一个函数里、支配派发点**，判定为 FP 且理由可复核；
另两条 AUTH-01 报的是 **dlopen 转发桩**——桩确实不校验描述符，但真正的派发在
`libdsoftbus_server_plugin.z.so` 里，**该插件在任何本地源码树中都不存在、也没有本仓库的构建目标**，
所以这两条的上限是 `plausible but unproven`，且这个上限**不是**分析深度不够，而是证据边界。

## 1. 版本绑定（先做这一步，否则行号会指错地方）

| 项 | 值 |
|---|---|
| 审计声明并使用的 commit | `652f88e0261ce4d0610f73cc451c26b84d2597af` |
| 本地工作树 HEAD | `9f922677e147b939d6db899bde181d609d64711b`（`refs/remotes/origin/master`） |
| 两者关系 | `merge-base --is-ancestor` → **NO**；89 个文件不同 |

工作树**不是**被审计的版本，两者还不是祖先关系（都是 "merge master into master" 的合并提交）。
第一次按工作树读 `softbus_server_stub.cpp` 时行号整体偏移 7 行（`ReadInterfaceToken` 读到 384，实为 391），
就是这个原因。**判定依据是候选自带的 `source_sha256`**：

| 候选文件 | 报告记录的 sha256 | 工作树 | `652f88e0` | 归属 |
|---|---|---|---|---|
| `softbus_server_stub.cpp` | `00b57796d6…` | `d1180ab352…` | `00b57796d6…` | **DECL** |
| `bus_center_ex_obj_stub.cpp` | `ab27bd3035…` | 同 | 同 | 两版一致 |
| `trans_spec_object_stub.cpp` | `6e9e129881…` | 同 | 同 | 两版一致 |

工具侧是干净的，已核对实现：`audit.py:336` 用 `git ls-tree -r -z -l <commit>` 建计划、
`:921` 用 `cat-file blob <oid>` 取原文，`git_source.py:67` 先 `rev-parse --verify <commit>^{commit}`。
**文件选择、大小、解析、摘录、候选哈希全部绑在声明 commit 上，工作树不参与。**
本轮所有引文因此一律 `git -C <repo> show 652f88e0:<path>`，不读工作树。

> 通用规则（写进方法卡）：复核本仓库的任何候选，源码必须按候选自带的 `source_sha256` 定位；
> 工作树可能停在另一个 revision，且不保证是祖先。

## 2. 逐条判定

### 2.1 CAP-01 `softbus_server_stub.cpp:2174` / `:2191` → likely false positive

两条候选锚点正是 `GetSoftbusSpecObjectInner` / `GetBusCenterExObjInner` 里的 `reply.WriteRemoteObject(object)`。

**调用路径**（均在 `core/frame/standard/init/src/softbus_server_stub.cpp`，pinned）：

```text
client transact(code)
 └─ SoftBusServerStub::OnRemoteRequest            :387
     :391  if (data.ReadInterfaceToken() != GetDescriptor()) return SOFTBUS_IPC_ERR;   ← 描述符闸门
     :396  if (!GetServerIsInit()) return SOFTBUS_IPC_ERR;
     :403  ret = CheckPermission(code);  if (ret != SOFTBUS_OK) return ret;            ← 权限闸门
     :407  ret = CheckAccountConstraint(code); if (ret != SOFTBUS_OK) return ret;
     :416  memberFuncMap_.find(code) → (this->*memberFunc)(data, reply)                ← 唯一派发点
           └─ GetSoftbusSpecObjectInner :2165 → :2174  reply.WriteRemoteObject(object)
           └─ GetBusCenterExObjInner    :2182 → :2191  reply.WriteRemoteObject(object)
```

**守卫证据**：

| 位置 | 内容 |
|---|---|
| `:221-224` | `memberFuncMap_` 把 `SERVER_GET_SOFTBUS_SPEC_OBJECT` / `SERVER_GET_BUS_CENTER_EX_OBJ` / `SERVER_GET_DATASYNC_EX_OBJ` / `SERVER_GET_DM_EX_OBJ` 绑到这两个实现 |
| `:294-297` | 四个 code 在 `memberPermissionMap_` 里**全部**登记了权限：`DISTRIBUTED_DATASYNC` / `DISTRIBUTED_SOFTBUS_CENTER` / `DISTRIBUTED_DATASYNC` / `ACCESS_SERVICE_DM` |
| `:346-369` | `CheckPermission(code)` 取 `IPCSkeleton::GetCallingTokenID()` → `SoftBusCheckIsAccessAndRecordAccessToken`，失败返回 `SOFTBUS_ACCESS_TOKEN_DENIED` 并上报告警 |
| `adapter/.../softbus_access_token_adapter.cpp:126-146` | 该函数体是 `AccessTokenKit::VerifyAccessToken(tokenId, permission)`，**真实校验**；此文件工作树与 pinned **逐字节相同** |

**支配性**：`:403` 与 `:416` 在同一函数、同一基本块序列，`:403` 失败即 `return`，
不存在绕过 `:416` 的旁路分支（`switch` 贯穿、`goto`、异常都没有）。
→ **判定 FP**，机制 **M4**（`CheckPermission(code)` 在词表内，但调用点写 `ret != SOFTBUS_OK`，
成功常量 `SOFTBUS_OK` 在其他 TU 的枚举里，未产生 auth 谓词 → 导出行 CAP-01）。
这条是对 2026-10-11 评审 §2.3 的**独立复核确认**，并补齐了 pinned 行号与支配性论证。

`sptr<IRemoteObject> object` 的构造侧也无鉴权（`softbus_server.cpp:449` / `:464`，pinned 与工作树此处同构），
但**不需要**：调用者能不能走到这两个函数，由上面的 `:403` 决定，而不是由实现体决定。

### 2.2 AUTH-01 `bus_center_ex_obj_stub.cpp:56` / `trans_spec_object_stub.cpp:62` → external gap（本仓库无法判定）

两条候选都是 `descriptor-boundary`：桩覆写了 `OnRemoteRequest`，**不比对任何描述符**，直接把整个
`MessageParcel` 转交出去。

```cpp
// core/bus_center/extend/src/bus_center_ex_obj_stub.cpp:46-67  (pinned == worktree)
int32_t BusCenterExObjStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (onRemoteRequestFunc_ != nullptr) { return onRemoteRequestFunc_(code, data, reply, option); }
    if (!OpenSoftbusPluginSo()) { return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLOPEN_FAILED; }
    onRemoteRequestFunc_ = (OnRemoteRequestFunc)dlsym(soHandle_, "OnRemoteRequestByDlsym");
    if (onRemoteRequestFunc_ == nullptr) { return SOFTBUS_BUS_CENTER_EX_OBJ_PROXY_DLSYM_FAILED; }
    return onRemoteRequestFunc_(code, data, reply, option);
}
```

`trans_spec_object_stub.cpp:54-73` 同形，符号为 `TransOnRemoteRequestByDlsym`（日志文案误写成
`dlsym AuthGetDeviceUuid fail`，纯文案缺陷）。

**缺口证据（四条，均可复核）**：

1. **框架不兜底**。`communication_ipc` @ `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`：
   `ipc_object_stub.cpp:393-409` 的 `SendRequestInner` 直接调 `OnRemoteRequest`，无任何 token 校验；
   `IPCObjectStub::OnRemoteRequest:132` 对未知 code 只返回 `IPC_STUB_UNKNOW_TRANS_ERR`。
   即**描述符校验是各 stub 自己的事**，覆写后框架不会补上。
2. **符号实现不在本仓库**。`grep -rn OnRemoteRequestByDlsym / TransOnRemoteRequestByDlsym` 全树
   只命中这两处 `dlsym` **查找点**，无实现。
3. **也没有本仓库的构建目标**。`grep -rn dsoftbus_server_plugin` 命中的全是路径常量
   （`bus_center_ex_obj_stub.cpp:24/26`、`trans_spec_object_stub.cpp:26/28`、`bus_center_ex_obj.cpp:24/26`、
   `softbus_init_common.c`、各 `*_init.c`）与测试；**任何 `.gn/.gni` 都不构建 `libdsoftbus_server_plugin.z.so`**。
4. **本仓库内的对象实现是空壳**。`TransSpecObject`（`core/transmission/broadcast/src/trans_spec_object.cpp`）
   的 **16 个接口方法全部 `return SOFTBUS_NOT_IMPLEMENT`**，且未覆写 `OnRemoteRequest`——
   所以本仓库构建出的 `TransSpecObject` 对 IPC 来说什么都不做；`BusCenterExObj`
   （`core/bus_center/extend/src/bus_center_ex_obj.cpp`）的 11 个方法则**逐个** `dlsym(...ForDlsym)` 转发。

**可达性由导出侧界定**：调用者要先通过 §2.1 论证过的权限闸门才能拿到这些对象句柄
（"取句柄时授权一次"），此后对象自身不再校验。这个模型是否安全，**取决于插件是否逐调用校验**，
而插件源码与镜像在本机都不存在 → **本仓库无法证明，也无法否证**。

→ **判定 external gap，状态 `plausible but unproven`**。这不是"分析做得不够"，
而是证据边界；两条候选**保留**（不删除），并把缺口写进报告的 limitations。

## 3. 对检测器/流程的建议

1. **新增义务类型 `implementation_outside_scope`**：当入口的实现体是
   `dlopen`/`dlsym` 转发、且目标符号在本仓库无实现、无构建目标时，由检测器**直接记录该事实**
   （而不是留 `guard_effectiveness: unknown`）。本轮两条就能自动带上可复核的缺口说明。
   判据可复用已有的入口索引，不需要新的解析能力。
2. **误报与证据边界要分列**：本组 2 条候选**不是**检测器误报，是**证据边界**；
   把二者混在一个计数里会低估准确率，也会把改进方向指向错误的地方。建议报告把
   `false_positive` 与 `unresolved_external_dependency` **分开计数**。
3. **复核流程固化**（本轮踩到的坑）：候选 → 用其 `source_sha256` 在 pinned commit 上定位文件 →
   `git show <commit>:<path>` 读原文 → 再谈行号。工作树不可作为证据来源。

## 4. 复现命令

```bash
R=/home/audit/openharmony-targets/communication_dsoftbus
C=652f88e0261ce4d0610f73cc451c26b84d2597af

# 版本绑定：工作树 HEAD 与声明 commit 不同且非祖先
git -C $R rev-parse HEAD                      # 9f922677e147b939d6db899bde181d609d64711b
git -C $R merge-base --is-ancestor $C HEAD; echo $?   # 1

# 守卫链（全部行号来自 pinned）
git -C $R show $C:core/frame/standard/init/src/softbus_server_stub.cpp | sed -n '387,421p'
git -C $R show $C:core/frame/standard/init/src/softbus_server_stub.cpp | sed -n '294,297p'
git -C $R show $C:core/frame/standard/init/src/softbus_server_stub.cpp | sed -n '346,369p'
git -C $R show $C:adapter/common/security/access_token/common/softbus_access_token_adapter.cpp | sed -n '126,146p'

# 外部实现缺口
git -C $R show $C:core/transmission/broadcast/src/trans_spec_object.cpp   # 16× SOFTBUS_NOT_IMPLEMENT
git -C $R grep -n "ForDlsym\|ByDlsym" $C -- '*.cpp' '*.h'
git -C $R grep -n "dsoftbus_server_plugin" $C -- '*.gn' '*.gni'   # 无输出

# 框架不兜底
git -C /home/audit/openharmony-audit/perf-corpus/communication_ipc show \
    bbb92dbb2f52aca54ab268307c9476ac1802f3ff:ipc/native/src/core/framework/source/ipc_object_stub.cpp | sed -n '132,150p;393,412p'
```

## 5. 本报告明确没做的事

- **没有修改任何检测器规则**：本文只给证据与建议。§3.1 的义务类型是新契约，须单独落地并带正/反例。
- **没有升级任何候选**：4 条仍是 `evidence_type=syntax`、`validated_vulnerability=0`；
  两条 external gap **没有**被写成漏洞。
- **没有拿到插件**：`libdsoftbus_server_plugin.z.so` 的源码/镜像在本机不存在；
  两条 AUTH-01 要推进只能靠外部实现或运行时观测（`tests/core/frame/fuzztest/softbusserverstub_fuzzer`、
  `tests/core/transmission/fuzztest/transbroadcast_fuzzer` 是本仓库可用的观测面）。
- **没有跑动态验证**：本组结论全部是静态的。
