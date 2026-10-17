# PoC 记录：AUTH-01 SA relay / confused deputy

> 由 `src/ohscanner/poc` 生成。这是一个**本地隔离执行**记录：目标组件的两个固定修订被原样编译并运行。
> `validated_vulnerability` 恒为 0；**入口可达性没有被证明**，仍是 EvidenceObligation。

## 0. 结论

- 根因实例：`cve-2023-0036`（openharmony/inputmethod_imf，[PR](https://gitee.com/openharmony/inputmethod_imf/pulls/228)）
- 家族：`AUTH-01` SA relay / confused deputy，候选 CWE `CWE-441`
- 记录符号：`PlatformCallbackStub::OnRemoteRequest`
- 生命周期状态：**stable_reproduced**；证据等级：**stable_reproduced**

## 1. 环境指纹

| 项 | 值 |
|---|---|
| 编译器 | `clang++` Ubuntu clang version 14.0.0-1ubuntu1.1 |
| sanitizer | address, undefined |
| 平台 | Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.35 |
| Python | 3.10.12 |
| 源码来源 | local git object store: ~/openharmony-audit/ipc-research/repos/inputmethod_imf |

## 2. 逐修订结果

| 修订 | 固定提交 | 编译 | 状态 | 重放 |
|---|---|---|---|---|
| vulnerable | `e663b47013d5` | 成功 | stable_reproduced | stable_reproduced (3/3) |
| fixed | `5eaddcab19bc` | 成功 | run_success | stable_rejected (3/9) |

### vulnerable (`e663b47013d5`)

编译命令：

```sh
clang++ -std=c++17 -g -O1 -fno-omit-frame-pointer -no-pie -fsanitize=address,undefined -include /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/poc_compat.h -I /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub -I /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass -I /work/out/component/vulnerable/services/include -I /work/cutils/base/include -I /work/cutils/base/src /work/out/component/vulnerable/services/src/platform_callback_stub.cpp /work/cutils/base/src/parcel.cpp /work/cutils/base/src/refbase.cpp /work/cutils/base/src/string_ex.cpp /work/cutils/base/src/unicode_ex.cpp /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stubs.cpp /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/harness.cpp -o /work/out/bin/poc_vulnerable
```

| 用例 | 角色 | 参数 | 观测 | 判定 | 符合预期 |
|---|---|---|---|---|---|
| no_token | attack | `notoken` | contentBytes=96 contentCount=2 messages_sent=1 msgId=5 ret=0 userId=4242 | trigger | 是 |
| correct_token | control | `token` | messages_sent=0 ret=0 | no_trigger | 是 |
| foreign_token | attack | `wrongtoken` | messages_sent=0 ret=0 | no_trigger | 是 |

### fixed (`5eaddcab19bc`)

编译命令：

```sh
clang++ -std=c++17 -g -O1 -fno-omit-frame-pointer -no-pie -fsanitize=address,undefined -include /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/poc_compat.h -I /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub -I /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass -I /work/out/component/fixed/services/include -I /work/cutils/base/include -I /work/cutils/base/src /work/out/component/fixed/services/src/platform_callback_stub.cpp /work/cutils/base/src/parcel.cpp /work/cutils/base/src/refbase.cpp /work/cutils/base/src/string_ex.cpp /work/cutils/base/src/unicode_ex.cpp /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stubs.cpp /work/repo/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/harness.cpp -o /work/out/bin/poc_fixed
```

| 用例 | 角色 | 参数 | 观测 | 判定 | 符合预期 |
|---|---|---|---|---|---|
| no_token | attack | `notoken` | messages_sent=0 ret=-74 | no_trigger | 是 |
| correct_token | control | `token` | contentBytes=96 contentCount=2 messages_sent=1 msgId=5 ret=0 userId=4242 | trigger | 是 |
| foreign_token | attack | `wrongtoken` | messages_sent=0 ret=-74 | no_trigger | 是 |

## 可达性证据

- 状态：**partial**
- The service exports the stub itself: Platform::SetPlatform constructs it and passes it as the argument of IPlatformApi::registerCallback, a pure virtual on an IRemoteBroker interface whose proxy marshals the object with WriteRemoteObject. A peer that holds that handle reaches OnRemoteRequest with a caller-chosen transaction code and payload, which is why an interface-descriptor check is the relevant defence. Whether an unprivileged or unrelated process can obtain the handle, and what identity the peer has, is NOT established here.

### `stub_is_constructed_in_the_service` — `services/src/platform.cpp:25`

```cpp
sptr < IPlatformCallback > cb = new PlatformCallbackStub();
```

- 固定提交：`e663b47013d534a56165ab7467fbb3e14bf7172b`（sha256 `7ebe67fc4bc2`）
- **证明了**：the service process constructs the very stub object this PoC calls, so the target is a real product object rather than a test double
- **没有证明**：that any process other than the service can obtain it

### `stub_is_passed_to_a_remote_interface_call` — `services/src/platform.cpp:26`

```cpp
this->platformApi->registerCallback(cb);
```

- 固定提交：`e663b47013d534a56165ab7467fbb3e14bf7172b`（sha256 `7ebe67fc4bc2`）
- **证明了**：the stub is handed to a call on IPlatformApi, an interface the service talks to over IPC, rather than kept local
- **没有证明**：which process implements IPlatformApi at this call site, nor the permission or registration gate on that call

### `register_callback_is_an_ipc_transaction` — `services/include/i_platform_api.h:48`

```cpp
virtual int32_t registerCallback(const sptr<IPlatformCallback>& cb) = 0;
```

- 固定提交：`e663b47013d534a56165ab7467fbb3e14bf7172b`（sha256 `c2985b3853e0`）
- **证明了**：registerCallback is a pure virtual on an IRemoteBroker interface, so passing the stub to it crosses a process boundary
- **没有证明**：the identity, privilege or category of the peer that receives the callback

### `callback_is_marshalled_to_the_peer` — `services/src/platform_api_proxy.cpp:47`

```cpp
data.WriteRemoteObject(cb->AsObject());
```

- 固定提交：`e663b47013d534a56165ab7467fbb3e14bf7172b`（sha256 `8fc23c916124`）
- **证明了**：the proxy writes the callback object into a Parcel, so the peer receives a usable remote handle to this stub and can send transactions to it
- **没有证明**：whether that peer forwards the handle onward, which is the scenario the missing interface-descriptor check would otherwise constrain


## 4. 没有证明的事

- Not reachability: the harness calls the stub directly. That a remote caller can reach this stub over real IPC, and under which ability registration and permission state, is not established here and stays an EvidenceObligation.
- The interface token methods are supplied by a shim over the real Parcel; the shim forwards to WriteString16/ReadString16 and adds no policy.
- MessageHandler::SendMessage records the call instead of dispatching it; the recording is the observable.
- poc_compat.h supplies the using-directive for ErrorCode enumerators, which the historical header set does not expose unqualified; it changes no behaviour.

