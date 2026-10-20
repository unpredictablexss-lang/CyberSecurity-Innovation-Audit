# AAFWK 最后四条完整解析候选复核

复核日期：2026-10-19
固定组件：`openharmony/aafwk_standard` @ `834a566b1372268c7bbb0c40362322f812ca6efc`
Git tree：`c3744c8c230573a4bcdb76bf49493a1ea61c72d1`
检测器：B 线 `ohscanner.interface.ipc` 0.12.12
候选来自：`20261019-eight-component-candidate-triage-v0.12.12/candidate_triage.csv`
范围：只核对四条由成员函数指针语法归一化后转为 complete 的观察；不修改扫描器和原始报告。

## 判定摘要

| 候选 ID | 规则/锚点 | 本次复核结论 | 理由 |
|---|---|---|---|
| `1cdc4e40e45d20ee` | AUTH-01，`ReverseContinuationSchedulerPrimaryStub::OnRemoteRequest` | **协议描述符不一致；作为“缺少边界校验”候选为 likely false positive，另记产品可达性 unknown** | Stub 在派发前比较描述符并拒绝不匹配；但其 `DESCRIPTOR` 与接口声明、官方 Proxy 实际写入的 token 不同。源码能证明正常 Proxy 请求无法通过该闸门，不能据此证明攻击者可利用不同 token 绕过。 |
| `620a1827d71f4327` | AUTH-02，`AbilitySchedulerStub::OpenFileInner` | **candidate/unassessed；检测器把回调端当成普通服务端入口，授权语义需沿 AcquireDataAbility 路径验证** | 该对象是 `AbilityThread` 实现的应用侧回调接口，`OpenFile` 以调用者持有的 `IAbilityScheduler` 对象调用应用自己的 DataAbility。此函数没有 app-level caller 检查，但 URI 授权、对象分发与调用者是否只能获得授权对象尚需闭环。 |
| `a127712922342613` | CAP-01，同一 `OpenFileInner` 的文件描述符返回 | **candidate/unassessed；不据 `WriteFileDescriptor` 单点升级** | FD 被返回给本次事务调用者；其来源是当前 Ability 对 URI 的 `OpenFile` 结果。需要证明未授权调用者能取得/滥用该 AbilityScheduler 对象，或 URI 访问控制失效。候选与上一条共享同一条路径，应根因关联，不能当两个独立漏洞。 |
| `5b4a8942585774e1` | CAP-01，`AbilitySchedulerStub::CallRequestInner` | **candidate/unassessed；与上述回调对象边界同类，证据不足** | 函数把本地 `CallRequest()` 返回的 remote object 交给本次 IPC 调用者。该 Stub 是应用侧 `AbilityThread`；对象交付能否越过系统服务建立的绑定/调用者授权，需要验证 `CallRequest` 的调用路径和返回对象权限。单看写 reply 不是越权证明。 |

本次复核将四条拆成：1 条源码上明确存在描述符校验但协议常量不匹配；3 条属于应用侧回调端和能力对象交付，不能把“没有传统 caller permission check”直接解释成未授权服务端。**本轮没有确认任何漏洞，也没有改变 B 报告中的 `validated_vulnerability`。**

## 关键源码链

### 1. ReverseContinuation 描述符

固定源码中：

- `reverse_continuation_scheduler_primary_stub.cpp:24-25` 把 `DESCRIPTOR` 定义为 `ohos.abilityshell.ReverseContinuationSchedulerMaster`。
- `:52-57` 读取接口 token，`descriptor != token` 时立即 `return -1`；`:59-63` 的成员函数指针派发在该检查之后。
- `reverse_continuation_scheduler_primary_interface.h:24-26` 声明接口描述符 `ohos.appexecfwk.ReverseContinuationSchedulerPrimary`。
- `reverse_continuation_scheduler_primary_proxy.cpp:37`、`:66` 通过 `GetDescriptor()` 写入接口 token。

因此这里不是“没有描述符闸门”，而是**接口、Proxy 和 Stub 常量不一致**。它会造成预期 Proxy 调用被拒绝；是否存在另一个合法 Master 调用者、产品中如何实例化该 Stub、拒绝造成的用户可见影响，尚未由本次静态复核证明。AUTH-01 这条结果应保留为历史候选并标注此复核结论，不把协议缺陷冒充授权绕过。

### 2. AbilityScheduler 回调与对象所有权

固定源码中：

- `services/abilitymgr/include/ability_scheduler_stub.h:32` 显示 `AbilitySchedulerStub : IRemoteStub<IAbilityScheduler>`。
- `frameworks/kits/ability/native/include/ability_thread.h:42` 显示 `AbilityThread : AbilitySchedulerStub`；这是应用进程实现的回调 Stub。
- `ability_scheduler_stub.cpp:73-91` 在分派前仍校验 `IAbilityScheduler` 接口描述符，但不做常规调用者权限判定。
- `:196-217` 的 `OpenFileInner` 读取 URI/mode，调用虚函数 `OpenFile`，并把得到的 FD 写回事务 reply。
- `:613-635` 的 `CallRequestInner` 调用本地虚函数 `CallRequest()`，把返回的 remote object 写回 reply。
- `AbilityManagerProxy::AcquireDataAbility`（`ability_manager_proxy.cpp:477-503`）从系统 Ability Manager 请求 DataAbility Scheduler 并接收 remote object；release 路径在 `:505-528`。

这支持将其理解为**受系统服务编排的应用回调/对象能力接口**。但源码片段本身还不足以证明具体产品中谁能取得该 remote object、URI 权限如何验证、对象存活和转交规则，以及 `CallRequest()` 返回对象的下游授权。所以三条观察保留为待核查候选，不升级也不误报式删除。

## 固定证据绑定

固定 SHA 均来自候选记录的完整组件提交。原始 candidate CSV 中的源 blob 与源 hash：

| 文件 | 候选记录中的 Git blob | 源 SHA-256 |
|---|---|---|
| `frameworks/kits/ability/native/src/continuation/distributed/reverse_continuation_scheduler_primary_stub.cpp` | `2325ec4623fca550d7bc1c76624997a55bbd5979` | `185021995fa87a1b38eb80d3d47f6158c43ffc07d1f82208c108d349fb2768a4` |
| `frameworks/kits/ability/native/include/continuation/distributed/reverse_continuation_scheduler_primary_interface.h` | 本表仅作旁证；其内容取自同一固定 commit | `a4f2bd89fbdcd1c03bb9aa5dc1e224d44d31300cf4194a668dbc336d5b8a5c6b` |
| `frameworks/kits/ability/native/src/continuation/distributed/reverse_continuation_scheduler_primary_proxy.cpp` | 本表仅作旁证；其内容取自同一固定 commit | `3702321f9ab25f798d40f646f88af15bf369a91033d05c217cdf92c5d7f1bd24` |
| `services/abilitymgr/src/ability_scheduler_stub.cpp` | `9bf0339c2b17d1d27665daa491f376da448638a4` | `7d57447bdce60b3252d44b8757b8f72b4557981b5bde972d20c46a5d2909d9a1` |
| `services/abilitymgr/include/ability_scheduler_stub.h` | 本表仅作旁证；其内容取自同一固定 commit | `30005e92cc026d9b712f0812ee01e438d6497e85f8c3102a32b0fcb5c35b7287` |

正文引用按 `git show 834a566b1372268c7bbb0c40362322f812ca6efc:<path>` 读取；目标仓当前工作目录存在本地修改，因此**没有把工作树文件当成证据**。候选身份、原始状态及 parse-status 仍以固定报告包中的 JSON/CSV 为准。

## 已验证 / 未验证 / unknown

**已验证**
- 1 条 ReverseContinuation 候选前有描述符比较和拒绝分支；实现常量与接口声明/Proxy 使用值不一致。
- AbilitySchedulerStub 是 `AbilityThread` 的基类，OpenFile 与 CallRequest 是应用侧回调实现入口；对应函数把本地结果返回当前 Binder 调用者。
- 原始候选记录中四个源文件已经由本轮归一化标为 `complete`；complete 只说明该文件语法树状态，不等于跨服务授权证明。

**未验证**
- ReverseContinuation Stub 在目标产品中的实例化/持有者、Master token 的合法调用方及描述符不一致造成的实际影响。
- DataAbility 的 URI 授权、AbilityScheduler 句柄对外分发和请求 UID 约束是否形成完整且正确的授权闭环。
- CallRequest 返回对象的能力范围、其获取条件及下游方法的独立授权。

**unknown**
- 普通应用能否构造并到达上述具体 Binder 事务，以及部署配置、签名、系统服务策略对可达性的影响。
- 本次源码静态检查无法覆盖的跨仓服务策略、设备运行时行为和实际安全影响。

## 建议的规则改进

1. IPC 分析增加 endpoint role：区分 system service、app callback、proxy/helper、external plugin；没有 endpoint 方向证据时输出 `unknown`，不要把所有 `OnRemoteRequest` 套同一默认威胁模型。
2. descriptor 规则分别记录 `descriptor_check_present`、`expected_interface_descriptor`、`stub_descriptor`、`proxy_written_descriptor`，将“缺失校验”和“常量不一致”分开建模。
3. CAP-01 对 reply 写出能力对象/Fd 时，追踪对象所有者、句柄的取得/转交、获取门与下游权限；只检测到 `WriteRemoteObject` 或 `WriteFileDescriptor` 不足以构成越权结论。
4. 三条 AbilityScheduler 观察应按候选根因关联；在把 handle acquisition、URI policy 与下游权限连起来前，不把它们当三个已确认或互相独立的漏洞。

本报告只补充人工复核；没有改 detector、target 源码、候选原始报告或 confirmed 状态。没有运行设备验证或完整组件构建。
