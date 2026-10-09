# OpenHarmony Interface Attack Surface Inventory

## 1. 文档目的

本文档用于记录队友 B 对 OpenHarmony Web / ArkTS / IPC 接口安全攻击面的调查结果。

当前阶段的目标不是寻找或声明漏洞，而是从真实 OpenHarmony 源码中识别：

- Entry：外部请求进入系统的位置
- Source：外部调用者可能控制的数据
- Guard：权限、身份或来源检查
- Sink：受到保护的重要操作或资源
- Call Path：Entry、Guard 与 Sink 之间的调用关系

只有能够从源码、官方文档或可复现证据中确认的信息，才记录为 confirmed。

无法确认的信息统一标记为 pending 或 unknown。

# 2. Case 001 — Multimodal Input Service

## 2.1 基本信息

研究状态：Investigation

项目：

OpenHarmony `multimodalinput_input`

研究组件：

MMIService / Multimodal Input Service

主要语言：

C++

固定源码版本：

```
2468d204d3f276c373841e057af35985296c8421
```

研究方向：

IPC / Permission / Caller Trust Boundary

## 2.2 为什么选择这个组件

MMIService 是 OpenHarmony 中的系统服务组件。

目前已经确认 `MMIService` 与 `SystemAbility` 以及 `MultimodalInputConnectStub` 存在继承关系，因此它适合作为 IPC / 系统服务信任边界的第一批研究对象。

当前研究重点不是判断该组件是否存在漏洞，而是理解：

外部客户端如何通过 IPC 接口进入 MMIService，以及服务在执行后续操作前如何进行权限或身份检查。

# 3. 当前观察到的接口路径

目前正在调查的路径为：

```
External Client
      |
      | IPC Request
      v
MultimodalInputConnectStub
      |
      v
StubHandleAllocSocketFd
      |
      v
AllocSocketFd
      |
      v
AccessTokenKit::VerifyAccessToken
      |
      v
Session / Client FD related operations
```

注意：

该路径目前仍处于调查阶段。

其中部分关系已经获得源码或运行日志证据，但尚未完成完整的源码级控制流验证。

因此当前不能把整条路径标记为完全 confirmed。

# 4. Entry 调查

候选 Entry：

```
StubHandleAllocSocketFd
```

候选 Entry 类型：

IPC / RPC Stub Handler

当前状态：

```
pending
```

需要继续确认：

1. 该函数是否直接处理外部 IPC 请求。
2. 它由哪个 Stub 分发逻辑调用。
3. 对应的 transaction / request code 是什么。
4. 哪些参数来自客户端。
5. 调用失败时如何返回。

在这些问题确认之前，不把它标记为完全 confirmed 的 Entry。

# 5. Source 调查

当前观察到与连接建立相关的参数包括：

- `programName`
- `moduleType`
- Client / Session related information

当前状态：

```
pending
```

需要继续确认：

1. 哪些参数直接来自 IPC MessageParcel。
2. 哪些参数可以由外部客户端控制。
3. 是否存在服务端重新生成或覆盖的字段。
4. 参数在后续调用中的传播方式。

因此目前不把上述参数全部直接标记为 attacker-controlled。

# 6. Guard 调查

当前观察到的权限检查机制：

```
AccessTokenKit::VerifyAccessToken
```

运行证据显示该路径涉及：

```
ohos.permission.INPUT_MONITORING
```

候选 Guard 类型：

Permission Guard

当前状态：

```
pending
```

下一步需要通过源码确认：

1. VerifyAccessToken 的输入 token 从哪里获得。
2. token 是否对应当前 IPC caller。
3. 权限检查失败后的程序行为。
4. 权限检查失败是否能够阻止后续敏感操作。
5. 是否存在绕过该 Guard 到达后续操作的控制流路径。

只有完成上述验证后，才能判断该 Guard 是否真正保护后续操作。

# 7. Sink 调查

当前观察到权限检查之后可能发生：

- Session 创建或注册
- Client FD 分配或返回
- Client connection establishment

当前状态：

```
pending
```

目前尚未决定这些操作在 OHScanner 中应该被建模为什么类型的 Sensitive Sink。

需要进一步研究：

1. 这些资源具有什么安全意义。
2. 无权限调用者获得这些资源可能产生什么影响。
3. 是否存在官方权限设计或接口文档说明。
4. 哪个具体函数最适合作为 Sink。

因此当前不把 `AddSession` 或 FD 分配直接认定为漏洞相关 Sink。

# 8. 当前假设路径

当前工作假设：

```
IPC Entry
    |
    v
Caller-controlled parameters
    |
    v
Permission / Caller Guard
    |
    v
Session / FD related operation
```

这是研究假设，而不是最终检测模型。

# 9. 当前能够确认与不能确认的内容

## 已有较强证据

- MMIService 是真实 OpenHarmony 系统服务研究对象。
- MMIService 与 IPC Stub / SystemAbility 结构有关。
- 研究路径中存在 `AllocSocketFd`。
- 运行证据中存在 `AccessTokenKit::VerifyAccessToken`。
- 运行证据中涉及 `ohos.permission.INPUT_MONITORING`。
- 权限检查后存在 Session / Client FD 相关行为。

## 尚未完全确认

- `StubHandleAllocSocketFd` 是否应作为最终 Entry。
- 哪些参数能够被外部调用者直接控制。
- caller token 的具体来源。
- Guard 对 Sink 的完整控制关系。
- 最合适的 Sensitive Sink。
- 是否存在一跳或多跳调用关系。
- 是否存在绕过 Guard 的其他路径。

# 10. 安全结论

当前没有证据表明该路径构成 OpenHarmony 漏洞。

本 Case 当前用途是：

**真实 IPC / Permission 安全结构研究样本。**

在完成源码级 Entry、Source、Guard、Sink 和控制流验证之前，不生成 vulnerability claim。

当前：

```
validated_vulnerability = 0
```

# 11. 下一步

下一阶段只完成一件事情：

**确认真实 IPC Entry。**

具体需要找到：

```
IPC transaction
        |
        v
Stub dispatch
        |
        v
StubHandleAllocSocketFd
        |
        v
AllocSocketFd
```

并记录对应：

- source file
- class
- function
- request / transaction code
- MessageParcel 参数读取
- 调用关系
- 固定 commit

完成后再把 Entry 状态从：

```
pending
```

升级为：

```
confirmed
```

# 12. 2026-10-09 本地源码核验补充

保留以上原始调查记录。最新核验见同目录 `mmi_entry_verification.md`：Entry 的 map 分发和 Parcel 字段读取已核验；INPUT_MONITORING 见另一条 StubAddInputHandler 路径，不能合入 AllocSocketFd 权限链。原文提到的运行日志未提供，当前仍 runtime_validation=not_run、validated_vulnerability=0。
