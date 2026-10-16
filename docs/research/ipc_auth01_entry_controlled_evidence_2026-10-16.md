# AUTH-01：`entry_controlled` 缺什么 —— 以及对本页上一版结论的更正（2026-10-16）

- 对象：AUTH-01 / `CVE-2023-0036` / `openharmony/inputmethod_imf` @
  `e663b47013d534a56165ab7467fbb3e14bf7172b`（harness manifest 钉住的 vulnerable 提交）。
- 问题：**谁能把事务发到 `PlatformCallbackStub::OnRemoteRequest`** —— 即证据门的 `entry_controlled`。
- **本页已修订一次。** 上一版（提交 `6d99e44`）的结论「所需证据 34 个 blob、本地 0 个，
  需 owner 授权取数」**是错的**，只对 `ipc-research` 那一份偏克隆成立。更正见 §0。
- 修订后的结论：**证据已在盘上、已读完；`entry_controlled` 的剩余问题不是「取不到数据」，
  而是「答案不在这个仓库里」——它是一个跨仓库问题。**

## 0. 更正：34 个 blob 其实都在本地

**上一版说了什么**：在 `ipc-research/repos/inputmethod_imf` 上统计出 74 个源码文件里 31 个不可读，
把需要补的证据整理成 34 个 blob 的清单，并写明「本地 0 个」，据此请 owner 决定是否授权显式取数。

**错在哪**：那只说明**那一份克隆**没有这些 blob。`ipc-research` 用的是 `blob:none` 偏克隆，
而本机另有一份 **`/home/audit/openharmony-targets/inputmethod_imf`**：

| 属性 | 值 |
|---|---|
| 类型 | **浅克隆但非 blob 过滤**（`--is-shallow-repository = true`；无 `partialclonefilter`、无 `promisor`） |
| HEAD | `09a9da45055831e81be6cb8d0ca3d9bfa12f79d9`（2025-09-13） |
| 对象库 | in-pack **54,344** 对象，11.7 MB |
| 钉住提交 | `cat-file -t e663b470…` → **`commit`**，且 `ls-tree` 可列出全部 95 个路径 |
| **那 34 个 blob** | **可读 34 / 缺失 0** |
| **全树源码** | **可读 74 / 74** |

**因为无 promisor，读它是惰性抓取安全的**（全部读取仍经 `src/ohscanner/git_source.py:_git`）。

**教训**：上一版把「这一份克隆没有」直接写成了「本地没有」，并据此发起了一次网络取数申请。
差一步就让 owner 去授权取已经在盘上的对象。**判断「本地有没有」必须扫盘，不能只问一个对象库。**

### 0.1 fixture 自检（在读任何结论之前）

按 harness manifest 钉住的两份 sha256 现场重算，在 **targets 克隆**上：

| 修订 | blob | 重算 sha256 | 结论 |
|---|---|---|---|
| vulnerable | `e90a4e77e9be` | `59c980bf…e043` | **MATCH** |
| fixed | `0f9ed2f660ec` | `b6d7f66a…c444` | **MATCH** |

且 targets 克隆给出的 vulnerable blob oid `e90a4e77e9be` 与 `ipc-research` 克隆**完全相同**
（该克隆上此文件也是可读的）—— 两个对象库在此文件上一致，
所以从 targets 读到的确实是钉住版本的内容，不是近似版本。

## 1. 读到的正面证据

### 1.1 SA 声明：`profile/3703.xml`（blob `d7736f4d42c9`，982 B）

```xml
<info>
    <process>inputmethod_service</process>
    <systemability>
        <name>3703</name>
        <libpath>libinputmethod_service.z.so</libpath>
        <run-on-create>true</run-on-create>
        <distributed>false</distributed>
        <dump-level>1</dump-level>
    </systemability>
</info>
```

**这份声明里没有 `<permission>` 元素，也没有 `exported` / `allow-update` 之类的字段。**
它只描述 SA 叫什么、加载哪个库、是否随创建启动、是否分布式、dump 级别。

**边界（不能过度解读）**：OpenHarmony 的 SA profile 本来就不是放调用者权限闸的地方 ——
权限判断通常写在实现里。所以「profile 无 permission 字段」**不等于**「该 SA 无权限控制」，
它只说明**这条路取不到 `entry_controlled` 的证据**（见 §4：更版格式同样无此字段）。

### 1.2 进程与启动方式

`etc/init/inputmethodservice.cfg`：

```json
"services" : [{
        "name" : "inputmethod_service",
        "path" : ["/system/bin/sa_main", "/system/profile/inputmethod_service.xml"],
        "uid" : "system",
        "gid" : ["system", "shell"],
        "caps" : ["SYS_TIME"]
    }]
```

`etc/init/inputmethodservice.rc` 同样内容（`user system` / `group system shell` /
`capabilities SYS_TIME` / `seclabel u:r:time_service:s0` / `class z_core`）。

即 **imf SA 以 `uid system` 运行**，随 boot 启动。
（`seclabel` 的值按原文照录，本页不对它作解释。）

### 1.3 `bundle.json`

`subsystem: miscservices`，`syscap: ["SystemCapability.MiscServices.InputMethod"]`，
`adapted_system_type: ["standard"]`，`repository: https://gitee.com/openharmony/miscservices_inputmethod`
（该仓库即后来的 `inputmethod_imf`）。

## 2. 关键结论升级：现在可以定论「本仓库没有调用方」

上一版只能说「**可读子集里**没有 `SetPlatform` 调用方」（因为 31 个文件读不到）。

**现在 74/74 全可读，那个 caveat 被清除了。** 在钉住提交的**整棵树**里：

```text
services/include/i_platform_api.h   32  class IPlatformApi : public IRemoteBroker {
services/include/i_platform_api.h   46  DECLARE_INTERFACE_DESCRIPTOR(u"ohos.miscservices.inputmethod.IPlatformApi");
services/include/i_platform_api.h   48  virtual int32_t registerCallback(const sptr<IPlatformCallback>& cb) = 0;
services/include/platform.h         34  void SetPlatform(const sptr<IPlatformApi>& platformApi);
services/include/platform.h         55  sptr<IPlatformApi> platformApi;
services/src/platform.cpp           22  void Platform::SetPlatform(const sptr < IPlatformApi >& platformApi)
services/src/platform.cpp           26  this->platformApi->registerCallback(cb);
services/src/platform_api_proxy.cpp 32  class PlatformApiProxy : public IRemoteProxy<IPlatformApi> {
services/src/platform_api_proxy.cpp 42  int32_t registerCallback(const sptr<IPlatformCallback>& cb)
```

- **`SetPlatform` 只有声明与定义，没有任何调用方** —— 这次是**全树**结论，不是子集结论。
- **`IPlatformApi` 在本仓库只有 proxy（`PlatformApiProxy`），没有 stub 实现**
  —— 没有任何类 `: public IPlatformApi` 且不是 proxy 的。

**合起来**：`Platform` 把一个 callback stub 的句柄经 `registerCallback` 交给**注入进来的**
`IPlatformApi` 实现，而**那个实现在本仓库之外**。

## 3. 因此 `entry_controlled` 的剩余问题是跨仓库的

要回答「谁能到达这个回调」，必须知道**哪个组件实现了 `IPlatformApi`**。
本仓库没有答案，于是扫盘找：

| 搜索范围 | 结果 |
|---|---|
| `IPlatformApi` 的实现（排除 inputmethod_imf 自身） | **无** |
| `SetPlatform` 的调用方（排除 inputmethod_imf 自身） | **无** |
| 搜索盘 | `/home/audit/openharmony-targets/`、`/home/audit/openharmony-audit/perf-corpus/` |

即**盘上没有实现 `IPlatformApi` 的组件**。

**所以这一格的形态变了**：不是「本地缺 34 个 blob，请授权取数」，
而是「**需要另一个仓库** ——实现 `ohos.miscservices.inputmethod.IPlatformApi` 的那个组件，
它在本地不存在」，并且**需要先确定它是哪一个**。

## 4. 该接口在后续版本被整体移除（旁证，非钉住版本的证据）

targets 克隆的 HEAD（`09a9da45`，2025-09-13）上：

- `services/src/platform.cpp` **不存在**，`services/src/` 已换成完全不同的文件集
  （`ime_state_manager.cpp` / `client_group.cpp` / `notify_service_impl.cpp` / `user_session_manager.cpp` …）；
- `IPlatformApi` / `SetPlatform` / `PlatformCallback` 在整个 `services/` 树里**零命中**；
- SA 声明已从 `profile/3703.xml` 改为 `profile/3703.json` + `3703_ondemand.json`。

而**新版 `3703.json` 同样没有权限字段**（字段为
`process` / `systemability[{name, libpath, run-on-create, distributed, dump_level, extension}]`）。

**含义**：无论钉住版本还是后续版本，**SA profile 这条路都取不到 `entry_controlled`**；
而对钉住版本，唯一的路是外部 `IPlatformApi` 实现者。

**这条是旁证不是证据**：它绑定的是 `09a9da45`，**不能**用来推断钉住提交的行为，
也不构成「该设计有缺陷所以被删」——本页不作该推断。

## 5. 一个必须一起记的对照

该 SA **自己的事务入口确实检查调用者**：

```
services/src/input_method_system_ability.cpp       208/227/251/279/307/335   int32_t uid = IPCSkeleton::GetCallingUid();
services/src/input_method_system_ability_stub.cpp  177/178/202/221/239/258   int32_t pid/uid = IPCSkeleton::GetCallingPid()/GetCallingUid();
```

共 11 处 `IPCSkeleton::GetCallingUid()`。而回调路径的特点是：
**它的句柄是被 `registerCallback` 交给对端的**，因此落到 `OnRemoteRequest` 的调用者
不经过这些入口检查。

**这句是机制描述，不是可达性证明**：它说明「为什么缺少描述符校验会被视为防线缺失」，
但**不**说明攻击者能拿到那个句柄 —— 那仍然是 §3 的跨仓库问题。

## 6. 门状态（未因本页移动）

| 门字段 | 状态 |
|---|---|
| `target_bound` | 真 |
| `entry_controlled` | **仍未建立**（答案为跨仓库，见 §3） |
| `reachable_sensitive_operation` | 半 |
| `exploitation_conditions` | 半 |
| `security_impact` | 未建立 |
| `dynamic_reproduced` | 真（PoC 已跑） |

`poc_state = stable_reproduced` 与 `patch_revalidation = passed` **不变**；
`validated_vulnerability` 仍为 **0**；**没有任何门字段**因本页置真。

## 7. 现在的决定项（已替换上一版的取数申请）

- **不需要**为那 34 个 blob 申请取数 —— 它们已在 `openharmony-targets/inputmethod_imf` 里，已读完。
- **需要**确定并取得**实现 `IPlatformApi` 的组件**。可用的线索只有接口描述符
  `ohos.miscservices.inputmethod.IPlatformApi` 与它在钉住版本的调用点
  （`services/src/platform.cpp:26`）。**该线索不足以定位仓库**，需要队伍判断或检索上游。
- 在此之前，AUTH-01 到不了 `reportable`；CAP-01 的对应缺口是它那 3 个 `sa_profile` blob
  （同样应先在盘上扫，再谈取数 —— 见 §0 的教训）。

## 8. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
cd "$B"
.venv/bin/python /home/audit/wtmp/w170.py   # targets 克隆上那 34 个 blob 的可得性（34/34）
.venv/bin/python /home/audit/wtmp/w171.py   # SA 声明 / 启动配置 / 全树关键词命中（74/74 可读）
.venv/bin/python /home/audit/wtmp/w172.py   # fixture 自检：两份 sha256 重算
```

脚本在 `/home/audit/wtmp/`，**不入库**。

## 9. 版本绑定

| 项 | 值 |
|---|---|
| 目标 | `openharmony/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| 读取所用的对象库 | `~/openharmony-targets/inputmethod_imf`（浅克隆、非 blob 过滤） |
| 内容一致性 | vulnerable/fixed 两份 sha256 重算 **MATCH**；blob oid 与 `ipc-research` 克隆一致 |
| 证据可得性 | 34/34 blob 可读；74/74 源码可读 |
| `SetPlatform` 调用方 | **全树无**（74/74 覆盖，非子集） |
| `IPlatformApi` stub 实现 | **本仓库无；盘上亦无** |
| SA 声明 | `profile/3703.xml`（无 `<permission>` 元素）；进程 `uid system` |
| 门字段 | `entry_controlled` **仍未建立**；`validated_vulnerability` 仍为 **0** |
