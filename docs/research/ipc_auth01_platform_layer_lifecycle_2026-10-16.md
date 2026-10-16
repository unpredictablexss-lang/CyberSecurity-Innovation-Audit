# AUTH-01：platform 层从哪来、谁在用它、什么时候没的（2026-10-16）

- 对象：AUTH-01 / `CVE-2023-0036` / `openharmony/inputmethod_imf`
  @ `e663b47013d534a56165ab7467fbb3e14bf7172b`（harness 钉住的 vulnerable 提交）。
- 起因：`docs/research/ipc_auth01_entry_controlled_evidence_2026-10-16.md` §3 把
  `entry_controlled` 判为**跨仓库问题** —— 「谁实现了 `IPlatformApi`」答不出来。
  本文换一个问法：**不追问实现者是谁，先问这个层在历史上是怎么活着的**。
- 全部读法离线、逐 blob 绑定；脚本在 `/home/audit/wtmp/`，**不入库**。

## 0. 三句话

1. **它编进去了**：`services/BUILD.gn:52-55` 把 platform 四个源文件列进输入法 SA 的构建，
   所以钉住版本里 `PlatformCallbackStub` 是**已编译的发布代码**，不是躺着的死文件。
2. **但全历史里没人调它、也没人实现它**：pickaxe 显示 `SetPlatform` 这个字符串在
   **仓库全部历史**里只出现在 `platform.h` / `platform.cpp`；`IPlatformApi` 只出现在另外两个
   文件（接口头 + proxy）；`PlatformApiStub` / `platform_api_stub` **零命中**。
   → 注入方与实现者都在**本仓库之外**。
3. **2022-12 上游把整层当「废弃代码」删了**（三个提交，作者 `cy7717`）。而它当年之所以能被
   删，恰恰因为没人接线。

**本文不移动任何门字段。** 它同时包含一条**对 AUTH-01 不利**的事实（第 5 节：钉住的
「漏洞版」是 3.0-LTS 落后主干加固，不是主干漏洞），也包含一条**对报告有用**的产出
（第 4 节：逐 ref 算出的影响范围）。

## 1. 钉住版本上它确实在构建里

`e663b470:services/BUILD.gn`（capability target 的 sources），原文：

```gn
52      "../services/src/platform.cpp",
53      "../services/src/platform_api_proxy.cpp",
54      "../services/src/platform_callback_proxy.cpp",
55      "../services/src/platform_callback_stub.cpp",
```

四个文件：`Platform` 单例、`IPlatformApi` 的 proxy、`IPlatformCallback` 的 proxy、
`PlatformCallbackStub`。**没有** `platform_api_stub.cpp`（第 2 节）。

## 2. 全历史：没有调用方，也没有实现者

方法：对**全部历史**（`git log --all`）做 pickaxe（`-S`，按字符串出现次数变化匹配），
再看命中的**路径集合**。

| needle | 历史里命中过的唯一路径 | 结论 |
|---|---|---|
| `SetPlatform` | `services/include/platform.h`、`services/src/platform.cpp` | **只有定义，没有第三方调用方** |
| `IPlatformApi` | `i_platform_api.h`、`platform.h`、`platform.cpp`、`platform_api_proxy.cpp` | 只有接口 + proxy，**无 stub 实现** |
| `platform_api_stub` | （空） | 从未存在 |
| `PlatformApiStub` | （空） | 从未存在 |

**这不是「找不到」，是「历史里就没有」。** 该对象库有 312 个 ref（含 master 与
3.0/3.1/3.2 各 release、weekly、monthly），`--all` 覆盖 5356 个提交。

### 2.1 但「没有调用方」≠「死代码」

`platform.cpp`（blob `046a6a570cc1`，189 行）里，**六个转发方法全都有空指针防护**：

| 行 | 方法 | 无注入方时的行为 |
|---|---|---|
| :58-65 | `BindInputMethodService` | `:61 if (platformApi == nullptr) { :62 return nullptr; }` |
| :72-78 | `UnbindInputMethodService` | `:74` 判空 → `:75 return ERROR_NULL_POINTER;` |
| :86-92 | `CreateWindowToken` | `:88` 判空 → `:89 return nullptr;` |
| :99-105 | `DestroyWindowToken` | `:101` 判空 → `:102 return ERROR_NULL_POINTER;` |
| :123-130 | `GetInputMethodProperty` | `:126` 判空 → `:127 return ERROR_NULL_POINTER;` |
| :148-154 | `SetInputMethodSetting` | `:150` 判空 → `:151 return ERROR_NULL_POINTER;` |

另有**两个方法根本不转发**，无条件返回 0：

```cpp
112      int Platform::ListInputMethod(int userId, std::vector<InputMethodProperty*> *inputMethodProperties)
113      {
114          return 0;
115      }
138      int Platform::GetInputMethodSetting(int userId, InputMethodSetting *inputMethodSetting)
139      {
140          return 0;
141      }
```

**唯一的例外是 `SetPlatform` 自己**（`:22-27`）——它不判空，且是**全仓库唯一**
`new PlatformCallbackStub()` 的地方：

```cpp
22      void Platform::SetPlatform(const sptr < IPlatformApi >& platformApi)
23      {
24          this->platformApi = platformApi;
25          sptr < IPlatformCallback > cb = new PlatformCallbackStub();
26          this->platformApi->registerCallback(cb);
27      }
```

**怎么读这件事（不外推）**：转发方法普遍判空，说明代码写的时候**就假定可能没有注入方**；
而 `platform_api_proxy.cpp` 与 `platform_callback_proxy.cpp` 的存在说明设计上
**预期对端是一个 IPC 远端 stub**。所以「本仓库无调用方」的正确含义是
**注入方在仓库之外**，不是「这段代码没被编译/没被使用」。
**本文不主张**「因此产品上一定注入了」—— 那需要产品侧证据，盘上没有。

## 3. 三个恒真校验函数：留了钩子，没实现，也没接线

`platform.cpp` 末尾三个函数**无条件 `return true`**：

```cpp
160      bool Platform::CheckPhysicalKeyboard()
161      {
162          return true;
163      }
169      bool Platform::IsValidWindow(int uid, int pid, int displayId)
170      {
171          (void)uid;
172          (void)pid;
173          (void)displayId;
174          return true;
175      }
181      bool Platform::IsWindowFocused(int uid, int pid, int displayId)
182      {
183          (void)uid;
184          (void)pid;
185          (void)displayId;
186          return true;
187      }
```

参数是 `(uid, pid, displayId)` —— 教科书式的**调用者身份**，注释也写明了用途
（`Check if the remote caller is from a valid window` / `from a focused window`）。
看上去像鉴权闸。**所以必须查调用方**，否则就会写出一个漂亮的误报。

**调用点普查（VUL 全树，74/74 源文件可读）：**

| 函数 | 调用点 | 那一处的性质 |
|---|---|---|
| `CheckPhysicalKeyboard` | **1 处**：`services/src/peruser_session.cpp:490` | 在 `ShowKeyboard` 里，结果赋给 `supportPhysicalKbd`，`:492` 作为参数传给 `imsCore[index]->startInput(clientInfo->channel, clientInfo->attribute, supportPhysicalKbd)`。**行为提示，不是安全闸** |
| `IsValidWindow` | **0 处**（只有声明 `platform.h:46` 与定义 `platform.cpp:169`） | — |
| `IsWindowFocused` | **0 处**（只有声明 `platform.h:47` 与定义 `platform.cpp:181`） | — |

**结论（严格按证据）**：这三个恒真函数**不构成可达的鉴权绕过** —— 两个根本没有调用方，
一个有调用方但用途不是鉴权。它们真正的意义是**设计证据**：上游为「调用者必须是有效/聚焦窗口」
预留了钩子，在钉住版本上**既没实现也没接线**。这与第 5 节「九个月后整层被当废弃代码删掉」
是同一件事的两面。

**本文不把这一节写成漏洞**：没有调用方就没有敏感操作，没有敏感操作就没有影响。

## 4. 影响范围：逐 ref 算出来的（交付件 #4 素材）

对 312 个 ref 逐一取 `services/src/platform_callback_stub.cpp` 的 blob oid，再**逐个读 blob 内容**
（不按桶分类，只看它真的有什么）：

| blob | 行数 | 描述符校验 | `size` 边界校验 | 备注 | ref 数 |
|---|---:|:---:|:---:|---|---:|
| `e90a4e77e9be` | 104 | **无** | 无 | **未修复** | **18** |
| `352b006d2405` | 108 | 有 | 无 | master 2022-03-05 修复版（无尾换行） | 7 |
| `0f9ed2f6…ec68` | 108 | 有 | 无 | 3.0-LTS 回移版（= `pinned-fixed`） | 2 |
| `f34e8ff7d7a9` | 108 | 有 | 无 | 同上，只多两行 `// namespace` 注释 | 38 |
| `7d45b1f09d98` | 116 | 有 | **有** | +`BAD_VALUE` 两条 | 4 |
| `14a849f73d0e` | 116 | 有 | 有 | 同上 | 3 |
| `866c0b6a5825` | 116 | 有 | 有 | 同上 | 7 |
| `022e5d44f76f` | 116 | 有 | 有 | 同上 | 3 |
| （不可读） | — | — | — | 对象库缺对象 | 230 |

**携带未修复 blob 的 18 个 ref（完整列举）**：

```
refs/heads/pinned-vulnerable
refs/remotes/origin/OpenHarmony-3.1-Beta
refs/remotes/origin/revert-merge-21-OpenHarmony-3.0-LTS
refs/remotes/origin/weekly_20220105   weekly_20220111   weekly_20220118   weekly_20220125
refs/remotes/origin/weekly_20220201   weekly_20220208   weekly_20220215   weekly_20220222
refs/remotes/origin/weekly_20220301
refs/tags/OpenHarmony-v3.0-LTS   v3.0.1-LTS   v3.0.2-LTS   v3.0.3-LTS   v3.0.5-LTS
refs/tags/OpenHarmony-3.1-Beta
```

**边界**：`v3.0.4-LTS` 不在该对象库里（不是判定为「有」）。**230 个 ref 读不到**（多为
4.x/5.x/6.x，浅/受限克隆缺对象），**没有纳入判定** —— 因此**不能声称「已穷尽全部 ref」**。

### 4.1 blob 身份 ≠ 语义等价（一条必须写明的读法）

上表里三个 108 行 blob **内容相同、字节不同**：`352b006d2405` 是 3594 字节，
`0f9ed2f6…ec68` 是 3595 字节（**只差文件末尾那一个换行**，108 行逐行相同）；
`f34e8ff7d7a9` 是 3639 字节，多出的是 `} // namespace MiscServices` 与 `} // namespace OHOS`
两处闭合注释（由 `5b5ef7d1 2022-03-25 fix warning` 引入）。

**所以「逐字节相同」这种说法在这三个 blob 之间是不成立的**，只能说「内容等价」。
本仓库早前的两处表述（`ipc_auth01_unknown_refs_triage_2026-10-16.md` §10.2/§10.4 与
`PROGRAM_STATUS.md`）把 `352b006d2405` 写成与 fixed「逐字节相同」——**那是错的，已更正**。

## 5. 时间线：钉住的「漏洞版」是分支落后，不是主干漏洞

四个提交都读过 diff 与 blob（`w188.py`）：

| 日期 | 提交 | 分支 | 消息 | 该提交处的 blob |
|---|---|---|---|---|
| 2022-03-05 | `a6d13a2d` (zhouyongfei) | master | 修复安全测试问题 | `352b006d2405`（**+4 行描述符校验**） |
| 2022-03-09 | `b61148e5` (zhouyongfei) | 3.1 | 更新主干bug修改 | `352b006d2405`（同一次修复） |
| 2022-03-25 | `5b5ef7d1` | master | fix warning | 加 namespace 注释 → 后续 master blob `f34e8ff7d7a9` |
| 2022-05-06 | `e663b470` (`!118`) | **3.0-LTS** | sync to 3.0-LTS | `e90a4e77e9be`（**仍无校验 = pinned-vulnerable**） |
| 2022-08-23 | `540daea7` → merge `5eaddcab` (`!228`) | 3.0-LTS | **同步 master 安全问题修复** | `0f9ed2f6`（= pinned-fixed） |

`a6d13a2d` 加的正是那 4 行（`w188.py` 的 diff，`index e90a4e77..352b006d`）：

```cpp
+        auto descriptorToken = data.ReadInterfaceToken();
+        if (descriptorToken != GetDescriptor()) {
+            return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
+        }
```

**必须写明的一句**：**主干在 2022-03-05 就已经修了**；3.0-LTS 直到 2022-08-23 才**回移**。
所以钉住的 `e663b470` 是「**分支落后主干加固两个月**」的快照，**不是**「OpenHarmony 到
2022-08 才修的主干漏洞」。这两种说法在报告里是完全不同的两件事，**不能混**。

### 5.1 整层被当废弃代码删除

| 日期 | 提交 | 消息 | 规模 |
|---|---|---|---|
| 2022-12-02 | `98e421a2` | 無用代碼刪除 | 20 files, −553 |
| 2022-12-03 | `f2c9feb0` | 删除代码 | 32 files, −2353 |
| 2022-12-05 | `3361ee76` | 清理废弃代码 | 含 `platform.cpp` −189、`platform.h` −65、`i_platform_api.h` −62、`platform_callback_stub.cpp` −116 |

作者均为 `cy7717 <chenyu301@huawei.com>`。**`3361ee76` 被 `OpenHarmony-3.2-Beta5` /
`3.2-Release` 及其 3.2.x tag 包含；`f2c9feb0` 被 `refs/heads/master` 与全部
4.x/5.x/6.x release 分支包含。** 而 `OpenHarmony-3.0-LTS` / `3.1-*` **不含**这些删除提交
（`w185.py` S5）。即：**该层只活在 3.0/3.1/3.2-Beta4 及更早**。

## 6. 顺带修正一处旧记录的表述

`ipc_auth01_callback_capability_2026-10-16.md` §4 记了「`size` 无边界校验」是**未修的独立缺陷**，
并说 4 个变体 blob 带了 `size` 边界校验。**本节把那些 ref 点名了**（上表 116 行那四个 blob，
共 17 个 ref：`7d45b1f09d98`(4) / `14a849f73d0e`(3) / `866c0b6a5825`(7) / `022e5d44f76f`(3)）。
§4 的**结论不变**（那是静态推理，未动态验证，不进任何门字段）；变的只是「哪些 ref 上修过」。

## 7. 门状态（**未因本文移动**）

| 门字段 | 本文之后 |
|---|---|
| `target_bound` | 真（未变） |
| `entry_controlled` | **仍未建立**。本文把问题从「谁实现了 `IPlatformApi`」收窄为「**注入方必须是仓库外的、暴露 `IPlatformApi` stub 的 IPC 对端**」，但仍**未定位** |
| `reachable_sensitive_operation` | 仍是「半」（未变；本文不涉及） |
| `exploitation_conditions` | 仍是「半」（未变） |
| `security_impact` | 仍未建立（未变） |
| `dynamic_reproduced` | 真（PoC 已跑，未变） |

`poc_state = stable_reproduced`、`patch_revalidation = passed` **不变**；
`validated_vulnerability` 仍为 **0**。

## 8. 没有证明的事

- **没有**定位实现 `IPlatformApi` 的组件；`entry_controlled` 不动。
- **没有**主张产品上一定注入了 platform 实现（只证明仓库内没有注入方）。
- **没有**读 `CVE-2023-0036` 的公告原文 —— 所以**没有**把 `a6d13a2d`/`540daea7` 认定为
  该 CVE 的修复提交。二者的对应关系**尚未核对**，只有提交事实。
- **没有**读第 4 节那 230 个不可读 ref 的任何内容。
- **没有**做动态验证；没有改任何检测规则、公共契约或共享面。

## 9. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
cd "$B"
# 全部经 _git（禁 promisor / lazy fetch / transport），离线可复现
.venv/bin/python /home/audit/wtmp/w184.py   # 三个对象库的深浅 + pickaxe + platform 路径
.venv/bin/python /home/audit/wtmp/w185.py   # 删除提交元数据 / pickaxe 路径集合 / ref 归属
.venv/bin/python /home/audit/wtmp/w186.py   # platform.cpp 全文 / ref 存在性 / VUL→FIXED diff
.venv/bin/python /home/audit/wtmp/w187.py   # 三个恒真函数的调用点全树普查 / 祖先关系
.venv/bin/python /home/audit/wtmp/w188.py   # 312 ref 逐 ref blob 普查 + 四个修复提交 diff
.venv/bin/python /home/audit/wtmp/w189.py   # 八个 blob 的实际标记
.venv/bin/python /home/audit/wtmp/w190.py   # 三个 108 行 blob 的字节比较
.venv/bin/python /home/audit/wtmp/w191.py   # blob 尾部/空白差异
.venv/bin/python /home/audit/wtmp/w192.py   # namespace 注释的引入提交
```

脚本在 `/home/audit/wtmp/`，**不入库**。

## 10. 版本绑定

| 项 | 值 |
|---|---|
| 目标 | `openharmony/inputmethod_imf` @ `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| 读取所用对象库 | `~/openharmony-targets/inputmethod_imf`（浅，2 个根；312 ref / 5356 提交） |
| `platform.cpp` | blob `046a6a570cc1`（189 行） |
| `services/BUILD.gn` | platform 四源文件在第 52-55 行 |
| 未修复 blob | `e90a4e77e9be`（104 行，104 = 无描述符校验）→ 18 ref |
| 已修复 blob | `352b006d2405`(7) / `0f9ed2f6…ec68`(2) / `f34e8ff7d7a9`(38) |
| 更强加固 blob | `7d45b1f09d98`(4) / `14a849f73d0e`(3) / `866c0b6a5825`(7) / `022e5d44f76f`(3) |
| 全树调用点普查 | 74/74 可读；`SetPlatform` 无调用方；`IsValidWindow`/`IsWindowFocused` 零调用方 |
| 门字段 | 全部**未变**；`validated_vulnerability` 仍为 **0** |
