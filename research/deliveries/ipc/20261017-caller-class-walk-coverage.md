# 交付项 8：`caller-class` 的零不是合取失败，是走查从未发出那次调用（2026-10-17）

lane `lanes.ipc`，branch `work/ipc-20261017`，base `6a41dc9b`。检测器**一行未改**
（`0.8.0` / `oh-ipc-2026.10-v6`，pinned 只读树 `635b3e0449c552f0ccc25118850d245962845568`）。
证据：`research/evidence/interface/ipc/caller_class_walk_20261017/caller_class_walk.json`。

## 0. 一句话结论

30 个组件、**83 个** `caller_class_sensitive_calls` 的**调用点**摆在那里，而解释器自己
**一次也没有求值过其中任何一个**（`walked_by_bucket` 里根本没有 `caller_class` 这个键）。
所以这条规则的 0 候选**不是合取条件挡下来的**——`analysis.py:1049` 的
`not state.caller_class` 从来没被问到过。它和交付项 7 的 `identity-domain`、
`service-identity` 同类：**覆盖**，且现在两头都是实测。

## 1. 三种读数，两件仪器

| 读数 | 怎么来的 | 回答什么 |
|---|---|---|
| **文本** | 在组件**实际审计的文件**里数 `IpcPolicy.caller_class_sensitive_calls` 六个名字的出现，并把「声明」与「调用」分开（`caller_class_walk.py`） | 形状在不在 |
| **走查** | `probe_site`（交付项 7 那件仪器，本项扩了一个 `bucket` 字段） | 解释器**求值**了几次 |
| **入口** | `root_probe_site`（**新**仪器，只回答一个问题：这次走查到底跑没跑） | 空的记录是「没有入口根」还是「有入口根但没走到」 |

第三件仪器是必须的。空记录有两种读法，而前两件仪器都区分不出来：只记录策略名的探针，
在「没有入口根」和「有入口根但没碰到那个调用」两种情况下都写空文件。
`root_probe_site` 不计名字，只计每次 `Interpreter.value` 的调用次数、以及 `self.root`
去重后的入口根，所以它能把这第二种读法排除掉。

## 2. 三个数字

```text
30 个组件上解释器求值的调用：identity 145，caller_class 0（键不存在）
同样这 30 个组件的文件里，六个名字的调用点：83（另有 4 处声明、1 处注释）
```

145 与交付项 7 完全一致 —— 加 `bucket` 字段没有扰动身份侧的任何一个数
（`evaluations_by_subject {"": 8, "caller": 102, "request": 4, "unknown": 31}`，
`distinct_sites_by_subject {"": 4, "caller": 10, "request": 2, "unknown": 13}`，
两次逐字相同）。这不是巧合：两个名字集合不相交、分别打标签，合并才会把空 subject
的计数推上去。

## 3. `security_access_token`：走查跑了，而且跑在别的地方

这是唯一一个**既有根探针、又集中了大量该调用点**的组件（83 处里的 58 处）：

| 量 | 值 |
|---|---|
| 审计文件 | 550（`applicable_files` 545，`complete-ast` 分析 489，`shard_errors` 空） |
| 候选 | 0 |
| 六个名字的**调用点** | **58**（另有 4 处声明） |
| 解释器求值的调用表达式 | **998** |
| 走到的函数 | 34 |
| **入口根** | **27 个，分布在 11 个文件** |
| 调用点落在「有入口根的文件」里的 | **0** |

11 个有入口根的文件全在 `interfaces/`：

```text
interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp
    PermissionStateChangeCallbackStub::OnRemoteRequest            [allowlist]
    TokenSyncCallbackStub::OnRemoteRequest / *Inner                [allowlist]
interfaces/innerkits/privacy/src/on_permission_used_record_callback_stub.cpp
    OnPermissionUsedRecordCallbackStub::OnRemoteRequest            [allowlist]
...
```

而 58 个调用点全在 `services/`：

```text
services/accesstokenmanager/main/cpp/src/service/accesstoken_manager_service.cpp
services/privacymanager/src/service/privacy_manager_service.cpp
services/privacymanager/src/record/permission_record_manager.cpp
```

**走查是真的在跑**（998 个调用表达式、34 个函数），只是它的入口根和这些敏感调用
分处两棵目录树，中间那一段由构建期生成的 IDL stub 连接，不在源码树里。
所以「0 次求值」不是「没跑」，是**跑了但没走到**。这正是交付项 4 记的那处缺口，
现在有了逐组件的定位，而不是一句"IDL gap"。

## 4. 正面对照：`update_updateservice`

同一个仪器、同一次判据，换一个**入口根落在 `services/` 里**的组件，结论就反过来了：

```text
value_calls 760，call_expressions 199，distinct_roots 24（3 个文件），functions 26
   root: services/engine/src/update_service_stub.cpp  UpdateServiceStub::ApplyNewVersionStub  [dispatch]
   root: services/engine/src/update_service_stub.cpp  UpdateServiceStub::CheckNewVersionStub  [dispatch]
```

它的根是 **dispatch**（由入口索引绑定出来的），不在 `interfaces/`——于是同一个走查
在它身上求值到了 4 次授权谓词（`caller` 4）。**同一件仪器，一个组件求值到、另一个
组件一点没碰到，差别只在入口根的位置。** 这既是对照，也是「仪器没有系统性失灵」的证明。

## 5. 这条结论改变了什么、没改变什么

**改变了**：`caller-class` 从「推断为覆盖缺口」变成「实测的覆盖缺口」，且缺口位置被
逐组件指出来（根在 `interfaces/`、调用在 `services/`）。至此六条静默规则**全部**
有检测器内部或探针支撑的证据，没有一条还停在推断上：

| 规则 | 证据种类 |
|---|---|
| `copy-range` | 逐类实参普查（交付项 6 §7） |
| `position-underflow` | 删守卫 A/B + 7 例探针（交付项 5） |
| `identity-domain` | 解释器归因实测（交付项 7 §2） |
| `service-identity` | 范围核对 + 解释器归因实测（交付项 7 §4） |
| `request-identity` | 9 例探针 + 敏感效应前置实证（交付项 6 §6 / 交付项 7 §5.1） |
| `caller-class` | **本项**：走查 0 次求值 + 58/58 调用点不在根文件内 |

**没改变**：候选集零移动（仍然 166 条，全部 `candidate`）；没有改任何规则；
`caller-class` 的收益上界仍然是「补上 IDL 入口建模或跨 TU 一跳之后**可能**多出候选」，
仍落在并发 import 的 `analysis.py` 里。**零候选不代表组件安全。**

## 6. 复现

```bash
# 第三批（本项）：同一 argv，只是探针扩了 bucket；30 个组件，约 05:00-05:14
# 驱动树仍是 pinned 只读树 B（cwd 必须是它）
cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b   # HEAD 635b3e0
IPC_PROBE_LOG=<out>/<component>/predicates.jsonl \
PYTHONPATH=<worktree>/research/deliveries/ipc/probe_site \
  .venv/bin/python -m src.ohscanner.detectors.interface.audit \
    --repo-dir <corpus>/<component> --repository <name> --commit <sha> \
    --out-dir <out>/<component> --json-out <out>/<component>/report.json \
    --md-out <out>/<component>/report.md

# 根探针：只跑了 2 个组件（每个约 30 秒），回答「走查到底跑没跑」
IPC_ROOT_LOG=<roots-out>/<component>/roots.json \
PYTHONPATH=<worktree>/research/deliveries/ipc/root_probe_site \
  .venv/bin/python -m src.ohscanner.detectors.interface.audit ...（同上）

# 汇总三种读数（必须在仓库根跑，工具要按相对路径哈希自己的仪器）
.venv-web/bin/python research/deliveries/ipc/caller_class_walk.py \
  --audit-root <reports> --walk-root <out> --roots-root <roots-out> \
  --corpus-root <corpus> [--corpus-root <corpus> ...] \
  --out research/evidence/interface/ipc/caller_class_walk_20261017/caller_class_walk.json
```

## 7. 这些数字**不**说明什么

- `calls_in_a_root_file` 只在 `root_probe_run: true` 的组件上是测量值；另外 28 个组件
  没跑根探针，那个数对它们是**零 by construction**，不是零 by measurement。
  证据 JSON 里逐组件带了这个标记，`root_probe_coverage` 也把两侧分开报。
- 「在同一文件里」是这些规则所依赖的**可达性近似**（走查只走同文件），
  **不是**调用图证明。一个调用点不在根文件里，不代表它在运行时不可达。
- 58 个调用点的「调用点」判定来自一个文本分类器（把声明与调用分开），
  它本身不是证据；真正的证据是**解释器求值 0 次**这个检测器内部的事实。
- 没有验证任何一条调用点是不是安全缺陷。`caller-class` 的规则语义是
  「到达一个 caller-class 敏感调用而状态里没有 caller class」，与这些调用点
  是否真的缺少调用者区分无关。**候选不等于漏洞，零候选也不等于安全。**
