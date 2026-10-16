# AUTH-01：被交出去的那个对象能做什么 —— `IPlatformCallback` 的能力面（2026-10-16）

- 对象：AUTH-01 / `CVE-2023-0036` / `openharmony/inputmethod_imf` @
  `e663b47013d534a56165ab7467fbb3e14bf7172b`（harness manifest 钉住的 vulnerable 提交）。
- 问题：`PlatformCallbackStub` 的句柄被交给外部之后，**对端拿到它究竟能做什么** ——
  即证据门的 `reachable_sensitive_operation` 与 `security_impact` 两格。
- **本文不解 `entry_controlled`**。那一格的形态见
  `docs/research/ipc_auth01_entry_controlled_evidence_2026-10-16.md` §3：答案为跨仓库。

## 0. 一句话结论

`IPlatformCallback` 只有**一个事务**：`NOTIFY_EVENT` → `notifyEvent(eventId, userId, eventContent)`。
该方法把 `eventId` 映射成 7 种内部消息之一并投进服务自己的消息队列，最终落到
`InputMethodSystemAbility` 的
`OnUserStarted` / `OnUserStopped` / `OnUserUnlocked` / `OnUserLocked` /
`OnPackageAdded` / `OnPackageRemoved` / `OnSettingChanged` ——
**用户生命周期、包安装卸载、输入法设置变更**三类状态机。
**但「谁能持有这个句柄」仍未证**，所以本文**不**把任何门字段置真。

## 1. 两端的接口（原文，钉住提交）

### 1.1 `services/include/i_platform_api.h`（blob `1c7066c50728`，63 行）

```cpp
class IPlatformApi : public IRemoteBroker {
public:
    enum {
        REGISTER_CALLBACK = FIRST_CALL_TRANSACTION,
        BIND_IMS,
        UNBIND_IMS,
        CREATE_WINDOW_TOKEN,
        DESTROY_WINDOW_TOKEN,
        LIST_INPUT_METHOD,
        GET_INPUT_METHOD_PROPERTY,
        GET_INPUT_METHOD_SETTING,
        SET_INPUT_METHOD_SETTING,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.miscservices.inputmethod.IPlatformApi");

    virtual int32_t registerCallback(const sptr<IPlatformCallback>& cb) = 0;
    virtual sptr<IInputMethodCore> bindInputMethodService(const std::u16string& packageName,
                                                          const std::u16string& intention, int userId) = 0;
    virtual int32_t unbindInputMethodService(int userId, const std::u16string& packageName) = 0;
    virtual sptr<IRemoteObject> createWindowToken(int userId, int displayId, const std::u16string& packageName) = 0;
    virtual int32_t destroyWindowToken(int userId, const std::u16string& packageName) = 0;
    virtual int32_t listInputMethod(int userId, std::vector<InputMethodProperty*> *properties) = 0;
    virtual int32_t getInputMethodProperty(int userId, const std::u16string& packageName,
                                            InputMethodProperty *inputMethodProperty) = 0;
    virtual int32_t getInputMethodSetting(int userId, InputMethodSetting *inputMethodSetting) = 0;
    virtual int32_t setInputMethodSetting(int userId, const InputMethodSetting& inputMethodSetting) = 0;
};
```

**本仓库只有它的 proxy**（`services/src/platform_api_proxy.cpp`），**没有 stub 实现** ——
所以「谁实现了它」= 「谁收到 `registerCallback` 交出去的句柄」，仍是
`entry_controlled` 文档 §3 里那个**未定位**的组件。
不过这张方法表给了它一份**能力画像**（见 §5）。

### 1.2 `services/include/i_platform_callback.h`（blob `e45548666deb`，39 行）

```cpp
class IPlatformCallback : public IRemoteBroker {
    public:
        enum {
            NOTIFY_EVENT = OHOS::FIRST_CALL_TRANSACTION,
        };

        DECLARE_INTERFACE_DESCRIPTOR(u"ohos.miscservices.inputmethod.IPlatformCallback");

        virtual void notifyEvent(int eventId, int userId, const std::vector<std::u16string>& eventContent) = 0;
};
```

**只有一个事务。** 与之相对，`IPlatformApi` 有 9 个 —— 交出去的这一侧是**窄**的。

## 2. `PlatformCallbackStub::OnRemoteRequest`（blob `e90a4e77e9be`，104 行）

manifest 钉住的两份 sha256 现场重算 **MATCH**（vulnerable `59c980bf…e043` /
fixed `b6d7f66a…c444`），所以下面读的确实是钉住版本。

```cpp
34  int PlatformCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
35                                            MessageOption& option)
36  {
37      switch (code) {
38          case NOTIFY_EVENT: {
39              int eventId = data.ReadInt32();
40              int userId = data.ReadInt32();
41              std::vector < std::u16string > eventContent;
42              int size = data.ReadInt32();
43              for (int i = 0; i < size; i++) {
44                  eventContent.push_back(data.ReadString16());
45              }
46              notifyEvent(eventId, userId, eventContent);
47              break;
48          }
49          default: {
50              return IRemoteStub::OnRemoteRequest(code, data, reply, option);
51          }
52      }
53      return NO_ERROR;
54  }
```

**三件事同时缺席**（这正是缺陷本体）：

1. **没有 `ReadInterfaceToken()` / `GetDescriptor()` 比对** —— 修复版加的正是这 4 行；
2. **没有 `IPCSkeleton::GetCallingUid()` 之类的调用者检查** —— 服务端**无法分辨**发消息的是谁；
3. **`size` 被直接当循环上界**，没有任何边界校验（见 §4，**独立于 1、2**）。

## 3. `notifyEvent` 的能力面（原文，`services/src/platform_callback_stub.cpp:56-102`）

```cpp
56  void PlatformCallbackStub::notifyEvent(int eventId, int userId, const std::vector<std::u16string>& eventContent)
57  {
58      int msgId = 0;
59      switch (eventId) {
60          case CommonEvent::COMMON_EVENT_USER_STARTED:      msgId = MSG_ID_USER_START;      break;
64          case CommonEvent::COMMON_EVENT_USER_STOPPED:      msgId = MSG_ID_USER_STOP;       break;
68          case CommonEvent::COMMON_EVENT_USER_UNLOCKED:     msgId = MSG_ID_USER_UNLOCK;     break;
72          case CommonEvent::COMMON_EVENT_USER_LOCKED:       msgId = MSG_ID_USER_LOCK;       break;
76          case CommonEvent::COMMON_EVENT_SETTING_CHANGED:   msgId = MSG_ID_SETTING_CHANGED; break;
80          case CommonEvent::COMMON_EVENT_PACKAGE_ADDED:     msgId = MSG_ID_PACKAGE_ADDED;   break;
84          case CommonEvent::COMMON_EVENT_PACKAGE_REMOVED:   msgId = MSG_ID_PACKAGE_REMOVED; break;
88          default:                                          return;
91      }
93      MessageParcel *parcel = new MessageParcel();
94      parcel->WriteInt32(userId);
95      int size = eventContent.size();
96      parcel->WriteInt32(size);
97      for (int i = 0; i < size; i++) {
98          parcel->WriteString16(eventContent[i]);
99      }
100     Message *msg = new Message(msgId, parcel);
101     MessageHandler::Instance()->SendMessage(msg);
102 }
```

（上表把 7 个 `case` 压缩成一行一个，原文每个 `case` 占 3 行；引用的都是原文语句，
**没有改写任何逻辑**。`eventId` 用 `CommonEvent::` 枚举，`msgId` 用 `MessageID::` 枚举。）

### 3.1 这些消息被谁消费（全树 grep，74/74 可读）

`services/src/input_method_system_ability.cpp:376-408` 的 `WorkThread()`：

```cpp
376  void InputMethodSystemAbility::WorkThread()
377  {
378      while (1) {
379          Message *msg = MessageHandler::Instance()->GetMessage();
380          switch (msg->msgId_) {
381              case MSG_ID_USER_START :   { OnUserStarted(msg);      break; }
385              case MSG_ID_USER_STOP:     { OnUserStopped(msg);      break; }
389              case MSG_ID_USER_UNLOCK:   { OnUserUnlocked(msg);     break; }
393              case MSG_ID_USER_LOCK :    { OnUserLocked(msg);       break; }
397              case MSG_ID_PACKAGE_ADDED: { OnPackageAdded(msg);     break; }
401              case MSG_ID_PACKAGE_REMOVED: { OnPackageRemoved(msg); break; }
405              case MSG_ID_SETTING_CHANGED: { OnSettingChanged(msg); break; }
```

（同样只做了排版压缩，语句照原文。）

**因此 `reachable_sensitive_operation` 现在能写实**：一次 `NOTIFY_EVENT` 事务可以把
**用户启动/停止/解锁/锁定、包安装/卸载、输入法设置变更**这七类事件之一，
连同**调用方自选的 `userId` 与 `eventContent`**，投进 `InputMethodSystemAbility`
的**串行工作线程**。

### 3.2 一个必须写明的边界（不越界）

- `notifyEvent` 投给的是 `MessageHandler::Instance()`，而 `WorkThread()` 读的也是
  同一个 `Instance()`；**per-user 会话另有 `msgHandler`**（`PerUserSession::WorkThread()`，
  `peruser_session.cpp:123`）。**本页没有追**这两个是不是同一实例，也没有逐条追
  每个 `On*` 方法内部改了什么状态。**所以「注入成功」到「状态被改」之间还有一段未读**。
- **`userId` 是调用方自选的**，本页**没有**证明服务会对它做属主校验。
- **不构成「任意应用可达」**：`entry_controlled` 未证，见 §0。

## 4. 一处独立缺陷：`size` 没有边界校验（**静态分析，未动态验证**）

`OnRemoteRequest` 第 42-45 行：

```cpp
42              int size = data.ReadInt32();
43              for (int i = 0; i < size; i++) {
44                  eventContent.push_back(data.ReadString16());
45              }
```

- `size` 直接当循环上界；parcel 读空之后 `ReadString16()` 返回空串，**循环不会停**。
- 因此 `size = INT_MAX` 时，`eventContent` 要装约 **2³¹** 个空 `std::u16string`。
  按 libstdc++ 里 `sizeof(std::u16string)` ≈ 32 B 估算，量级是**几十 GiB**
  → `std::bad_alloc` → 未捕获 → **SA 进程终止（可用性）**。
- **钉住的 `fixed` 修订并没有修它**：`vulnerable → fixed` 的差异**只有那 4 行描述符校验**。
  反倒是 §50 读到的那 4 个变体 blob（`022e5d44f76f` / `7d45b1f09d98` / `866c0b6a5825` /
  `14a849f73d0e`）**带了** `if (size < 0) return …BAD_VALUE;` 与
  `size > data.GetReadableBytes()` 两条校验。**这三者是分开的事实，不要合并成一句话。**

**这是一段静态推理，不是验证结果。** 本页**没有**跑过任何东西：
`std::u16string` 的实际大小、`MessageParcel::ReadString16()` 在 parcel 耗尽时的确切行为、
以及 `bad_alloc` 是否真的终止进程，**都没有实测**。按 `AGENTS.md`，
「AI 推测不是验证」，所以它**不进任何门字段**，只作为**待验证线索**记在这里。

## 5. 这份接口画像对「定位实现者」有什么用

`IPlatformApi` 的 9 个方法说明实现者要能做：**绑定/解绑 IME 服务**（返回 `IInputMethodCore`）、
**创建/销毁 window token**、**列举/读写输入法属性与设置**、**接收回调**。
在 `inputmethod_imf` 内部，这些都经 `Platform::Instance()->…` 转发
（全树普查：`peruser_session.cpp` **6 处**、`peruser_setting.cpp` **8 处**，另 `platform.cpp` 为定义）。

这**把候选范围收窄**，但**仍不足以定位仓库**：盘上（`~/openharmony-targets/`、
`perf-corpus/`、`ipc-research/repos/`）没有实现者，也没有 `SetPlatform` 的调用方。
**决定项不变**：需要确定**实现 `ohos.miscservices.inputmethod.IPlatformApi` 的组件**，
仍需队伍判断或上游检索。

## 6. 门状态（**未因本文移动**）

| 门字段 | 本文之后 |
|---|---|
| `target_bound` | 真（未变） |
| `entry_controlled` | **仍未建立** —— 本文不涉及 |
| `reachable_sensitive_operation` | **仍是「半」**，但**半在哪变清楚了**：从「操作可达已证、敏感未证」变成「**敏感操作已具名**（7 个 `On*` 入口），**但仍未证**它确实是安全边界上的敏感动作（`On*` 内部未读，§3.2）」 |
| `exploitation_conditions` | 仍是「半」（**仍需先持有句柄**） |
| `security_impact` | **仍未建立**。本文给了**可写实的 C/I/A 素材**（完整性与可用性两个方向），但按 `AGENTS.md`，**素材不等于证据**：既没有动态验证，也没有证明 `On*` 的实际后果 |
| `dynamic_reproduced` | 真（PoC 已跑，未变） |

`poc_state = stable_reproduced` 与 `patch_revalidation = passed` **不变**；
`validated_vulnerability` 仍为 **0**；**没有任何门字段**因本文置真。

## 7. 没有证明的事

- **没有**证明谁能持有 `PlatformCallbackStub` 的句柄 —— `entry_controlled` 不动。
- **没有**读每个 `On*`（`OnUserStarted` / `OnPackageAdded` / `OnSettingChanged` …）的内部，
  因此**没有**证明注入成功之后状态真的被改、改成什么。
- **没有**追 `MessageHandler::Instance()` 与 `PerUserSession::msgHandler` 是否同一实例。
- **没有**做任何动态验证（§4 的 DoS 推理**没有实测**）。
- **没有**改 `version_impact.py`、PoC harness、检测规则或任何共享面。
- **没有**把本文读成「该缺陷影响很大所以应当升级」——
  **影响面写实与可达性未证是两件事**。

## 8. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
cd "$B"
# 全部经 _git（禁 promisor / lazy fetch / transport），离线可复现
.venv/bin/python /home/audit/wtmp/w180.py   # IPlatformApi / platform.h / IPlatformCallback / platform.cpp 原文
.venv/bin/python /home/audit/wtmp/w181.py   # PlatformCallbackStub 全文 + 全树调用点普查（74/74）
.venv/bin/python /home/audit/wtmp/w182.py   # 可注入 message id 的消费者
.venv/bin/python /home/audit/wtmp/w183.py   # WorkThread / OnUserLocked / PerUserSession 原文
```

脚本在 `/home/audit/wtmp/`，**不入库**。

## 9. 版本绑定

| 项 | 值 |
|---|---|
| 目标 | `openharmony/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| 读取所用的对象库 | `~/openharmony-targets/inputmethod_imf`（浅克隆、非 blob 过滤） |
| 回调 stub blob | `e90a4e77e9be`（104 行，sha256 `59c980bf…e043` **MATCH**） |
| 回调接口 blob | `e45548666deb`（`i_platform_callback.h`，39 行） |
| 回调 stub 头 blob | `504f1d6a57b9`（`platform_callback_stub.h`，39 行） |
| API 接口 blob | `1c7066c50728`（`i_platform_api.h`，63 行，9 个事务） |
| `Platform` 头 blob | `15c64ca0006d`（`platform.h`，65 行） |
| 全树调用点普查 | **74/74 可读**；`SetPlatform` 全树**无调用方**；`IPlatformApi` **无 stub 实现** |
| 事务面 | `IPlatformCallback` **1 个**（`NOTIFY_EVENT`）；`IPlatformApi` **9 个** |
| 可注入的内部消息 | `MSG_ID_USER_START/STOP/UNLOCK/LOCK`、`MSG_ID_PACKAGE_ADDED/REMOVED`、`MSG_ID_SETTING_CHANGED` |
| 门字段 | 全部**未变**；`validated_vulnerability` 仍为 **0** |
