# AUTH-01：`entry_controlled` 到底缺哪些证据（2026-10-16）

- 对象：AUTH-01 / `CVE-2023-0036` / `openharmony/inputmethod_imf` @
  `e663b47013d534a56165ab7467fbb3e14bf7172b`（harness manifest 钉住的 vulnerable 提交）。
- 问题：**谁能把事务发到 `PlatformCallbackStub::OnRemoteRequest`** —— 即证据门的 `entry_controlled`。
- 方法：全离线，全部 git 调用经 `src/ohscanner/git_source.py:_git`
  （promisor / lazy fetch / 全部 transport 关闭），**零 fetch**、**零写操作**。
- **结论：这一格缺的证据不是「还没找」，而是「已定位到具体 blob、但内容不在本地对象库」。**
  需要 **34 个 blob，本地有 0 个**。清单见 §4。

## 0. 为什么打这一格

`reportable` 需要三个条件同时成立：

| 条件 | 现状 |
|---|---|
| `poc_state == "stable_reproduced"` | **已满足**（replay 3/3 触发） |
| `patch_revalidation == "passed"` | **已满足**（`patches/auth01-descriptor-guard-v1`，三例全对，含正向对照） |
| 六个证据门字段全为 True | **不满足**：目前只有 `target_bound` + `dynamic_reproduced` |

前两项已经付清且记录在 `outputs/reports/poc_auth01_descriptor_bypass.json` 里。
**卡住 `reportable` 的只剩证据门，而证据门的瓶颈是 `entry_controlled`。**
本页就是去查：这一格到底还差什么，差的东西能不能离线拿到。

## 1. 可达路径的第一个事实：对端是「被注入」的

`services/src/platform.cpp`（LOCAL，blob `046a6a570cc1`，189 行）：

```cpp
22      void Platform::SetPlatform(const sptr < IPlatformApi >& platformApi)
23      {
24          this->platformApi = platformApi;
25          sptr < IPlatformCallback > cb = new PlatformCallbackStub();
26          this->platformApi->registerCallback(cb);
```

即：`Platform`（imf 服务侧）**不自己找** `IPlatformApi`，是**别人把实现注进来**；然后
`Platform` 把 `PlatformCallbackStub` 的句柄通过 `registerCallback` **交给注入方**。
`IPlatformApi` 的 proxy 在本仓库（`services/src/platform_api_proxy.cpp:42`），
stub 实现不在本仓库。

**所以「谁持有回调句柄」= 「谁调用 `SetPlatform` 把 `IPlatformApi` 注进来」。**

## 2. 本次能读到的，与读不到的

`ls-tree`：该提交下共 **95 个文件**，其中源码 74 个 → **可读 43 / 不可读 31**。

在**可读的 43 个**里，`SetPlatform` / `registerCallback` 的每一处出现只有 5 行：

```text
services/include/i_platform_api.h   48  virtual int32_t registerCallback(const sptr<IPlatformCallback>& cb) = 0;
services/include/platform.h         34  void SetPlatform(const sptr<IPlatformApi>& platformApi);
services/src/platform.cpp           22  void Platform::SetPlatform(const sptr < IPlatformApi >& platformApi)
services/src/platform.cpp           26  this->platformApi->registerCallback(cb);
services/src/platform_api_proxy.cpp 42  int32_t registerCallback(const sptr<IPlatformCallback>& cb)
```

**必须说清的边界**：这只说明「可读子集里没有调用方」。**不能**说「本仓库没有调用方」——
因为有 31 个源码文件读不到，调用方可能就在其中。

而那 31 个不可读的文件，**分布不是随机的**：

| 目录 | 不可读源码数 | 这一层是干什么的 |
|---|---:|---|
| `frameworks/inputmethod_controller/**` | 13（另有 `BUILD.gn` 1 个） | **app 侧入口层**：应用经此与 imf 服务交互 |
| `frameworks/inputmethod_ability/**` | 14（另有 `BUILD.gn` 1 个） | IME ability 层，注入 `IPlatformApi` 的一侧 |
| `unitest/**` | 2 | 测试 |
| `interfaces/kits/js/napi/js_input_method_engine.cpp` | 1 | JS 入口 |
| 其余 | 0 | — |

**要回答「谁能到达这个回调」的那一层，恰恰就是这个偏克隆没有的那一层。**

此外，三份与「服务暴露面 / 进程怎么被拉起」直接相关的文件也都不在本地：

- `profile/3703.xml` —— SA 声明（SA id **3703**），权限与暴露面应当写在这里
- `etc/init/inputmethodservice.cfg`、`etc/init/inputmethodservice.rc` —— 进程拉起方式
- `bundle.json` —— 组件声明

## 3. 这一格为什么不能靠推理补上

`AGENTS.md` 明令禁止把「存在 `OnRemoteRequest`」等同于「任意应用可达」。
本页的证据形态让它更明确：**「不可读」既不是可达的证据，也不是不可达的证据。**

harness manifest 自己已经写了这条边界（`known_limitations` 第一条、`reachability.status = "partial"`）：
> Not reachability: the harness calls the stub directly. That a remote caller can reach this stub
> over real IPC, and under which ability registration and permission state, is not established here.

本页做的是把「not established」拆成**逐 blob 的点名清单**，好让它成为一个可决定的事项。

## 4. 取数清单（34 个 blob，本地 0 个）

全部位于 `openharmony/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b`。
按用途分三组：

### A. 服务暴露面 / 拉起方式（4 个）—— 最直接、也最该先看

| blob | 路径 |
|---|---|
| `8fad871480ce49d225f2058fd5faac291a157909` | `bundle.json` |
| `d7736f4d42c90153c75937772039c8a71fe1d64a` | `profile/3703.xml`（SA id 3703） |
| `9f9a783ed26bfb66ae328099f8a6f1930ad3d799` | `etc/init/inputmethodservice.cfg` |
| `fbfbcc447b5c3012cbad11eacf296ba9e6e61762` | `etc/init/inputmethodservice.rc` |

### B. app 侧入口层 `frameworks/inputmethod_controller/**`（15 个）——「调用者怎么到这里」

```text
71457b1784d173ec8ccfd012ecfeeae9a8763f86  BUILD.gn
0a984c419ad94e34d5c3aa7afd3d986f5ae81335  include/i_input_client.h
39e0a4fc734d2637fa9480dbf7d7cc89d1c7702f  include/i_input_data_channel.h
a6324edf847d0dc46371f6c09ec09f289d4da39a  include/input_client_proxy.h
08fa114acb709b7edbf296f65c9d92821eceeaca  include/input_client_stub.h
23c695129331650a00e8a3d95be22d948e9167f6  include/input_data_channel_proxy.h
c0a7b9eeb5a84db0380163f1f11f74e1ebadbb73  include/input_data_channel_stub.h
f1ec5d6c5ae9e735717227a440e2045ec7861c05  include/input_method_controller.h
2bda76ed189c2aee8ff77d5478fc31457c605748  include/input_method_system_ability_proxy.h
c4185f6c8b9a3102f56c47155d51623813ad6dc7  src/input_client_proxy.cpp
b2764d5d39ca249e72324789a1965bd6c63af5e7  src/input_client_stub.cpp
9026e96c4231fe82be411b606ab3c148ebf6039c  src/input_data_channel_proxy.cpp
9c91dad865909779cd21c4eb65d96698954bdbcc  src/input_data_channel_stub.cpp
5aac6ce82b855203e2e5d5811eee3493e34e7743  src/input_method_controller.cpp
3ae9c12a797af7641830f25f2e1de17397fd7ee9  src/input_method_system_ability_proxy.cpp
```

### C. IME ability 层 `frameworks/inputmethod_ability/**`（15 个）—— 注入 `IPlatformApi` 的一侧

```text
79032a1149604957ce8f611cfbf0dee1e7cfa91b  BUILD.gn
afd0c49248d0e9a3902cc980759bcfb03d83a338  include/event_target.h
e9eb80a8172e0595869e129e69d5d176554aa9fa  include/i_input_method_agent.h
eb73f9cc4b83b1c56b577e1052e9cdab9f1e0b72  include/i_input_method_core.h
01bfd5357178505127bcb94cdc9c795bc3cfca59  include/input_method_ability.h
038f3abae221c25b175398158311e953da674e09  include/input_method_agent_proxy.h
c26922a011b3bd606b70e4b77e512b562c3fb4dc  include/input_method_agent_stub.h
be50db285e23fc6e09157fb85dda31bd6574c886  include/input_method_core_proxy.h
72dea34e58f8d89172d9989e937789ff439cf8d2  include/input_method_core_stub.h
4c6f1b032f04058bf1d970829101b6c5b40eb1f8  src/event_target.cpp
c14fd5ff083bae4e7634b44ef7aab4f755bcc780  src/input_method_ability.cpp
1e06f7e0fee51d11551dde38f4d2beb030e6038d  src/input_method_agent_proxy.cpp
f562d973ce734018c7fd50635748afb59dfc547b  src/input_method_agent_stub.cpp
58dc01ac53609eddf0cd0a056c23aff6ae7d0ff6  src/input_method_core_proxy.cpp
8e114cc4f0558c68153b91e7f41c38a18c19418e  src/input_method_core_stub.cpp
```

## 5. 为什么是「按 blob 取」而不是「拉仓库」

- 在共享研究克隆上做显式 fetch 会改动别的会话依赖的对象库（github 不通、gitcode 通），
  **属 owner 决定，B 不单方面做**（与 §45 同一条）。
- 但把请求收窄到 **34 个 blob / 1 个已钉住的提交**，远比「把仓库拉全」更容易被批准，
  也更容易在事后核对「读到的确实是钉住的那个版本」——每个 blob 都有 OID 可复核。
- 拿到这 34 个 blob **也不等于** `entry_controlled` 就能置真：还要在其中读出
  「哪一类调用者、在什么权限或注册状态下能走到注入点」，并把该结论写成带行号与原文的关系条目。
  这一步是**必要不充分**。

## 6. 本页明确没有主张的事

- **没有**主张这个 SA 不可达，也**没有**主张它可达。「读不到」两个方向都不支持。
- **没有**把「可读子集里没有 `SetPlatform` 调用方」写成「本仓库没有调用方」（31 个文件读不到）。
- **没有**改动任何 PoC 结论：`stable_reproduced` 与 `patch_revalidation = passed` 不变，
  `validated_vulnerability` 仍为 **0**，六门字段**一个都没有**因为本页而置真。
- **没有**改 `version_impact.py` 或任何共享面文件。
- **没有**推测 SA 3703 的权限语义 —— `profile/3703.xml` 内容未读到。

## 7. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
cd "$B"
.venv/bin/python /home/audit/wtmp/w166.py   # IPlatformApi 实现者与 sa_profile 路径排查
.venv/bin/python /home/audit/wtmp/w167.py   # 全树文件清单 + SetPlatform 调用方检索
.venv/bin/python /home/audit/wtmp/w168.py   # 可读/不可读切分 + profile/3703.xml 可得性
.venv/bin/python /home/audit/wtmp/w169.py   # 34 个 blob 的点名清单（含完整 OID）
```

脚本在 `/home/audit/wtmp/`，**不入库**。

## 8. 版本绑定

| 项 | 值 |
|---|---|
| 目标 | `openharmony/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| 该提交文件数 | 95（源码 74；可读 43 / 不可读 31） |
| 注入点 | `services/src/platform.cpp:22` `SetPlatform`；`:26` `registerCallback(cb)` |
| SA 声明 | `profile/3703.xml`（blob `d7736f4d42c9…`，**not-local**） |
| 所需 blob | **34 个，本地 0 个** |
| 门字段 | `entry_controlled` **仍未建立**；`validated_vulnerability` 仍为 **0** |
