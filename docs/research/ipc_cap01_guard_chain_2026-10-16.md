# CAP-01：`TRANS_ID_GET_RENDER_SESSION` 的 guard 链与影响范围（2026-10-16）

- 候选：CAP-01，`CWE-926`（根因）+ `CWE-668`（后果），SA relay 形态。
- 目标：`openharmony/window_window_manager` @ `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`（master，2026-10-08）。
- 本篇做两件事：①用参数化后的 `version_impact.py` 出**影响范围**；②把 guard 链**从原文读实**，
  替换掉此前计划里的转述。
- **结论：guard 缺失这一格已由原文证死；可达性与影响两格仍未闭合 → 状态仍是 `candidate`，不是 `confirmed`。**

## 0. 一句话结论

从 IPC 事务臂到内部对象，`TRANS_ID_GET_RENDER_SESSION` 一路**没有任何权限校验**：
臂内直接调 `GetRenderSession`，该函数只有 null 检查，底层 `ScreenSession::GetRenderSession()`
只是一个返回 `renderSession_` 的 getter。**任何通过接口描述符校验的调用者都会收到这个远程对象。**
同组件里有 132 处 `SessionPermission::IsSystemCalling()` 判断，其中两个直接可比的方法都会拦截 ——
唯独这条路径没有。**但「非系统调用者能否发这个事务」仍未证明，所以不升级为已确认漏洞。**

## 1. 数据源与锚点

| 项 | 值 |
|---|---|
| 克隆 | `/home/audit/openharmony-audit/ipc-research/repos/window_window_manager` |
| 性质 | 非浅克隆；`blob:none` 偏克隆；**无 checkout（工作树为空）** |
| 规模 | 48,759 commits / 46 tag / 386 个 `refs/remotes/origin/*`（含 `origin/HEAD`） |
| 锚点自检 | master 上该路径 blob = `26df3196683976a9f175292fcbf54efef262eaa0`，与预期一致 |

**「无 checkout」这条是实测的**：工作树文件数为 0，`git hash-object` 报
`No such file or directory`。所以不能靠读工作树绕过 `blob:none` —— 能读到的只有
对象库里已物化的 blob，本篇每个 blob 都注明是否 local。

## 2. 影响范围（交付件 #4 的工具，参数化后重跑）

命令见 §8。**431 个 ref**（46 tag + 385 origin 分支；`origin/HEAD` 是符号引用，不计入）逐条 blob 身份判定：

| 状态 | 条数 |
|---|---:|
| `affected` | **2** |
| `fixed` | **0** |
| `not_present` | 255 |
| `unknown` | 174 |

`manifest_sha256 = bfdf0a53d28353d61bf33592a88e1e27f244232ce5dde102506c4c8d43cb182f`

- **affected 两条**：`refs/remotes/origin/master`（`8b0d8fe1b973`，2026-10-08）与
  `refs/remotes/origin/weekly_20261005`（`2743766e03d0`，2026-09-30）。
  两者携带的正是 `26df3196` 这个 blob。
- **`fixed` 为 0 且 `fixed_blob` 为空**：本次**不传** `--fixed-commit`。
  这是工具的既有设计 —— 空 fixed blob **永远不会**产出 `fixed` 状态（见
  `tests/test_version_impact.py::ClassificationTests`）。这一格只能如实留空。

### 2.1 「不存在修复」是被验证过的，不是推断

9 个 status 为 `unknown` 的 tag 取不到日期（它们是注释 tag，`%(committerdate)` 为空，
只有 `%(*committerdate)` 才有值），若不补齐，「没有 ref 比 master 新」这句话就不成立。
用 peeled 提交日期补齐后（表即这 9 个 tag，与 174 条 `unknown` 里的 tag 部分一一对应）：

| tag | peeled 提交日期 |
|---|---|
| `OpenHarmony-v5.1.0-Release` | 2025-04-28 |
| `OpenHarmony-v6.0-Beta1` | 2025-06-18 |
| `OpenHarmony-v6.0-Release` | 2025-09-05 |
| `OpenHarmony-v6.0.0.1-Release` | 2025-11-25 |
| `OpenHarmony-v6.1-Release` | 2026-03-06 |
| `OpenHarmony-v6.0.0.2-Release` | 2026-03-13 |
| `OpenHarmony-v6.1-LTS` | 2026-07-28 |
| `OpenHarmony-v7.0-Beta1` | 2026-06-03 |
| `OpenHarmony-v7.0-Release` | 2026-08-20 |

最新的是 `v7.0-Release`（2026-08-20），**全部早于 master（2026-10-08）**。
结合 174 条 `unknown` 里**没有一条比 master 新**（最晚的是 `OpenHarmony-6.1-LTS`，2026-09-29）：

> **在被扫描的 431 个 ref 范围内，这个文件的最新状态就是脆弱状态 —— 不存在修复边界。**

这与计划里「`8b0d8fe1` 就是所有 ref 的最新提交」的结论一致，但现在有 431 条逐条日期支撑。
（边界：不能推广到未扫描的 ref，也不能说上游永远不会修。）

### 2.2 `not_present` 的成因：这个模块很年轻

`not_present` 的 137 个 weekly 覆盖 2021-12-31 … 2024-09-10，全部 255 条覆盖
2021-12-31 … 2025-09-02 —— 也就是 `window_scene/` 这个路径在 2024 年 9 月之前
**根本不存在**。所以这些 `not_present` 大多不是「文件被删」，而是「模块还没建」。

**有一处必须交代**：255 条里有 **22 条晚于 2024-09-15**，即模块已存在之后仍然 `not_present`
（如 `OpenHarmony-5.0.0-Release`、`OpenHarmony-5.0.3-Release_1742218180` 等 release 分支
与 `revert-mr-*` 分支）。它们不是在脆弱版本之后才删掉文件 —— 这些分支是从**模块创建之前**
的提交点分出去的，从不含该文件。**不能**把这 22 条读成「上游删除了有问题的文件」。

`unknown` 的 174 条覆盖 **89 个不同 blob**，对应文件自 2024-09-15 以来被反复改动 ——
这些是演化变体，**本篇未读其内容**（431 条里只有 5 个 blob 的摘要可取，
见产物里的 `content_digest_coverage`）。

## 3. guard 链：三帧，全部有原文

三帧都在本地对象库里读到了，blob 与行号如下。

**第 1 帧 —— 事务臂**：`window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp`
（blob `26df31966839`，2,088 行）

```cpp
1775          case DisplayManagerMessage::TRANS_ID_GET_RENDER_SESSION: {
1776              ScreenId screenId = static_cast<ScreenId>(data.ReadUint64());
1777              sptr<IRemoteObject> renderSession = GetRenderSession(screenId);
1778              reply.WriteRemoteObject(renderSession);
1779              break;
1780          }
```

臂内没有权限判断，只有一次 `ReadUint64`。

**第 2 帧 —— 服务端方法**：`window_scene/screen_session_manager/src/screen_session_manager.cpp`
（blob `b1b6226de888`，18,484 行）

```cpp
3200  sptr<IRemoteObject> ScreenSessionManager::GetRenderSession(ScreenId screenId)
3201  {
3202      auto screenSession = GetScreenSession(screenId);
3203      if (!screenSession) {
3204          TLOGE(WmsLogTag::DMS, "GetRenderSession: screenSession is null, screenId: %{public}" PRIu64, screenId);
3205          return nullptr;
3206      }
3207      return screenSession->GetRenderSession();
3208  }
```

**只有 null 检查。**`IsSystemCalling` / `Permission` / `IsSystemApp` / `IsStartByHdcd`
在该函数体内**一个都没有**（逐串检索确认）。

**第 3 帧 —— 底层 getter**：`window_scene/session/screen/src/screen_session.cpp`
（blob `2442c62f00c2`，3,795 行）

```cpp
1006  sptr<IRemoteObject> ScreenSession::GetRenderSession()
1007  {
1008      return renderSession_;
1009  }
```

纯 getter，不校验调用者，也不校验状态。

**合起来**：`reply.WriteRemoteObject(renderSession)` 把内部的 `renderSession_`
交回给发起事务的一方。**这条路径上没有任何一步问过「谁在调」。**

### 3.1 入口校验了什么（重要区分）

`screen_session_manager_stub.cpp:50`：

```cpp
50      if (data.ReadInterfaceToken() != GetDescriptor()) {
51          TLOGE(WmsLogTag::DMS, "InterfaceToken check failed");
52          return ERR_TRANSACTION_FAILED;
53      }
```

**接口描述符是被校验的。**描述符相等只证明发送方**知道接口名**，它不是权限判断。
这与 AUTH-01 有本质区别：**CAP-01 不是描述符绕过**（见 §5.2）。

## 4. 同组件对照：这个组件的惯例是拦截，唯独此处不拦

同一文件 `screen_session_manager.cpp`：

| 行 | 方法 | 是否拦截 |
|---|---|---|
| 16347 | `SetScreenSkipProtectedWindow` | `if (!SessionPermission::IsSystemCalling() && !SessionPermission::IsStartByHdcd())` → 拒绝 |
| 16395 | `GetIsRealScreen` | `if (!SessionPermission::IsSystemCalling())` → 拒绝 |
| 3200 | **`GetRenderSession`** | **无** |

该文件里 `IsSystemCalling` 共 **132 处**。

对照样本（原文）：

```cpp
16345  DMError ScreenSessionManager::SetScreenSkipProtectedWindow(const std::vector<ScreenId>& screenIds, bool isEnable)
16346  {
16347      if (!SessionPermission::IsSystemCalling() && !SessionPermission::IsStartByHdcd()) {
16348          TLOGNFE(WmsLogTag::DMS, "permission denied! calling: %{public}s, pid: %{public}d",
...
16350          return DMError::DM_ERROR_NOT_SYSTEM_APP;
```

```cpp
16393  bool ScreenSessionManager::GetIsRealScreen(ScreenId screenId)
16394  {
16395      if (!SessionPermission::IsSystemCalling()) {
16396          TLOGNFE(WmsLogTag::DMS, "Permission Denied.calling: %{public}s, pid: %{public}d",
...
16398          return false;
```

**这是本节最有分量的证据**：不是「某个文件忘了写校验」，而是「同一个类里 132 处都写了，
返回一个远程对象给别人这条路径没写」。

## 5. 对早先说法的两处更正

### 5.1 「同模块有 40+ 处 `IsSystemCalling`」—— 数字要改

实测：`screen_session_manager.cpp` 里 **132 处**；`screen_session_manager_stub.cpp`
里**只有 1 处**（第 2028 行，`ProcSetPrimaryDisplaySystemDpi` 内）。
「40+」低估了实现文件的密度，同时容易让人以为 stub 文件里到处都有 —— **stub 里只有 1 处**。

### 5.2 CAP-01 **不是**描述符绕过

它和 AUTH-01 同属 SA relay 家族，但机制不同：AUTH-01 是**描述符校验完全缺失**，
CAP-01 是**描述符校验在位、但没有权限校验**。两者在报告里必须分开写，
否则会把 AUTH-01 的修复建议错套到 CAP-01 上。

### 5.3 「`renderSession_` 的真实接口在仓库外」—— 只对一半

`ScreenSession::GetRenderSession()` 的**实现就在仓库内**（`screen_session.cpp:1006`）。
在仓库外的是这个远程对象**被拿到之后能做什么**（渲染服务的接口能力）。

## 6. 证据门现状（逐字段，不粉饰）

| 门字段 | 状态 | 依据 |
|---|---|---|
| `target_bound` | **True** | 仓库 + `8b0d8fe1b973` + 路径，blob 自检一致 |
| `entry_controlled` | **未建立** | 描述符校验在位，但**「哪类调用者在什么权限下能发这个事务」没有证据**。`sa_profile/4607.json` 的 blob `bb2aec03568e` **不在本地**，读不到 |
| `reachable_sensitive_operation` | **半** | 操作可达**已证**（三帧链）；「敏感」**未证** —— 取决于 `renderSession_` 交出去后能做什么 |
| `exploitation_conditions` | **半** | 条件只有「接口描述符正确」，而这不是特权；其余条件未证 |
| `security_impact` | **未建立** | C/I/A 影响无证据。拿到一个远程对象 ≠ 拿到某个能力 |
| `dynamic_reproduced` | **False** | 无 PoC、无动态验证 |

→ 按 `evaluate_report_status`：门不全且 `poc_state` 连 `trigger_success` 都没有
→ 状态停在 **`candidate`**。**guard 缺失去没有把它推过门**，因为门的另一格是可达性。

## 7. 没有证明的事

- **没有**证明非系统调用者能发这个事务。这是与 AUTH-01 共同的瓶颈：`AGENTS.md` 明令
  不得把「存在 `OnRemoteRequest` 分支」等同于「任意应用可达」。
- **没有**读 `sa_profile/4607.json` / `sa_profile/scene_board/4607.json`（两者 blob 均不在本地）
  ——它们才是判断该 SA 暴露面的关键。
- **没有**证明 `renderSession_` 交出去后的能力边界，因此没有 C/I/A 影响。
- **没有**读 174 条 `unknown` 里的任何变体内容（431 个 ref 里只有 5 个 blob 可读）。
  因此**不能**说这些变体是安全的。
- **没有**动态验证，**没有** PoC。
- **没有**把 CAP-01 写成与 AUTH-01 同机制（见 §5.2）。

## 8. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
R=~/openharmony-audit/ipc-research/repos/window_window_manager
cd "$B"

# 影响范围（CAP-01 无上游修复 → 不传 --fixed-commit，fixed 因而不可达）
.venv/bin/python /home/audit/wtmp/w151.py

# guard 链三帧 + 同组件对照（全程经 _git，禁 promisor/lazy fetch/transport）
.venv/bin/python /home/audit/wtmp/w156.py   # master 与 weekly_20260928 两个可读 blob 的差异
.venv/bin/python /home/audit/wtmp/w160.py   # GetRenderSession 定义体 + Proc* 统计
.venv/bin/python /home/audit/wtmp/w161.py   # 同组件对照组（会拦截的两个方法）
.venv/bin/python /home/audit/wtmp/w163.py   # ScreenSession::GetRenderSession + sa_profile 可得性
```

产物：`outputs/reports/version_impact_cap01_window_window_manager.json`（不入库）。
分析脚本在 `/home/audit/wtmp/`，**不入库**。

## 9. 版本绑定

| 项 | 值 |
|---|---|
| 目标 | `openharmony/window_window_manager` @ `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` |
| 锚定 blob | `26df3196683976a9f175292fcbf54efef262eaa0` |
| guard 链三帧 blob | `26df31966839`（stub）/ `b1b6226de888`（manager）/ `2442c62f00c2`（session） |
| 影响范围 | 431 refs：affected 2 / fixed 0 / not_present 255 / unknown 174 |
| 工具 | `research/experiments/interface/ipc/version_impact.py`（#4 参数化版，未改动） |
| CWE | 家族 `CAP-01` → `CWE-926`（`src/ohscanner/detectors/interface/detector.py:7` 的 `_CWE`）；后果 `capability_exposure` → `CWE-668`（`src/ohscanner/detectors/interface/models.py:57`） |
| 状态 | **`candidate`** —— 证据门未过，不得写成已确认漏洞 |
