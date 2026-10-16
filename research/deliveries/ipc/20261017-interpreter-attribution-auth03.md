# 交付项 7：用解释器自己的归因取代文本代理，并更正交付项 6 的两处结论（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **检测器（只读固定，一行未改）**：`src/ohscanner/detectors/interface/`，`0.8.0` /
  `oh-ipc-2026.10-v6`，来源树
  `/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` @
  `635b3e0449c552f0ccc25118850d245962845568`
- **证据**：`research/evidence/interface/ipc/auth03_identity_probe_20261017/interpreter_attribution.json`
- 相关：[交付项 6](20261017-shape-corpus-and-auth03-identity.md)、
  [交付项 5 DATA-01 机制](20261017-data01-mechanism.md)
- **本交付更正交付项 6 的两处**：§5/§6 对 `service-identity` 机制的判断（**换了一条机制**），
  以及 §6 代码块的行号（**旧行号错 3 行**）。更正逐条列在 §4、§5。

---

## 0. 一句话结论

交付项 5/6 的结论原先建立在一个**文本代理**上：从源码文本里正则认出"授权谓词被喂了什么"。
本交付把它换成**检测器内部**的测量 —— 在固定的只读树上挂一个 `sitecustomize`，包住
`Interpreter.value`，读**分析自己算出来的** `Value.subject`，不重算任何东西。30 个组件上：

**解释器一共求值了 145 次授权谓词调用**（caller 102、无法归因 31、同文件同名遮蔽 8、
请求派生 4）；**`caller_uid` 0 次、`self` 0 次**。于是：

1. `identity-domain` 的沉默**不再是"两种文本方法都数出 0"**，而是**解释器自己一次也没有**
   把授权谓词归因为调用方 UID。
2. `service-identity` 的机制**被改判**：那 16 处 `self` 站点**全部落在扫描范围内**，
   但**一次都没有被求值** —— 它们所在的函数全是**客户端 / kit / 工具类**函数，
   不是 IPC 服务分发入口。所以它的沉默属于**可达性**（与 `position-underflow`、
   `caller-class` 同类），**不是**交付项 6 写的"还差一个敏感效应"。
3. `request-identity` 的机制**维持原判并被加强**：解释器**确实求值到了**那 2 处站点、
   **确实当场记下了身份问题**（`identity_issues_added=1`，2/2），**但一条候选都没有**
   —— 两处所在的函数体里都没有被建模的敏感调用。这不是推断：两个函数体分别是 14 行与 35 行，
   已逐行读过（§5），两处都不含 `sensitive_calls ∪ object_sensitive_calls` 的任何成员。

**"合取满足的次数"用的是蕴含，不是第二遍独立运行**，这一点必须写清楚：

- `emit()`（`analysis.py:612-631`）**无条件**把观察 append 进 `self.observations`；
- `detector.py:98-113` 把 observations 一对一映射成 findings，中间**没有**过滤；
- 因此**某条规则 0 候选 ⟹ 该规则 0 次发射 ⟹ 合取从未满足**。

所以"这一整批语料里，三条 identity 规则合取满足 0 次"与 `caller-class` 的
"`caller_class_sensitive_calls` 被走到且 `state.caller_class` 为空 0 次"
（`analysis.py:1035-1038`，同样没有额外前置条件）都是**从报告里的 0 候选读出来的**。
另一条把 `Interpreter.action` 也包起来、独立再推一遍的路子**已写好但已停掉**：
它的返回值被上面三条蕴含，而它的运行代价是每个调用表达式一次 Python 包装
（4 个组件约 15 分钟），不值得为重复推导花掉。这条判断本身也记在证据 JSON 的
`conjunction_counts_by_entailment.how` 里，读者若要经验性地复核，可以自己重跑。

## 1. 探针：读，不是重算

```python
# research/deliveries/ipc/probe_site/sitecustomize.py（本次已入库；被测记录由这份文件产生）
def _value(self, fn, node, state, depth):
    before = len(state.identity_issues)
    result = _original(self, fn, node, state, depth)   # 原样调用，不改任何参数
    ...
    "subject": getattr(result, "subject", None)        # 分析自己算出的归因
    "added":   len(state.identity_issues) - before     # 这次调用当场记了几条身份问题
    return result                                      # 返回值原样交回
```

三点方法学约束，逐条对应 B_IPC 的验收：

| 要求 | 本探针 |
|---|---|
| 不隐藏 import 问题 | 探针把 `sys.path` 自己补上 cwd 后 `import`；失败时把异常写进记录、**不吞**（首轮就是靠这条发现 `self.text` 不存在、应改 `fn.text`）。驱动 argv 与测量批次**逐字相同**，未用 `-I` 掩盖。 |
| 不能改变测量 | 包装器不修改任何入参、状态或返回值；`getattr` 读的是原函数已经产出的对象。 |
| 两侧对照 | §3 的 `caller` 102 次就是同一次运行里的对侧：同一个谓词、同一条包装路径，被求值 102 次、全部归因为 caller，**没有**被算成身份问题。 |

判据来自被测代码本身，不是我另外写的正则：

- `analysis.py:1364` `subjects = [a.kind for a in args if a.kind in ("caller","self","request")]`
  → `subject = subjects[0] if subjects else "unknown"`
- `analysis.py:1378` `return Value(kind, text, subject, perm)` —— `subject` 就在返回值里

## 2. pass 1：30 个组件，解释器求值到的每一次授权谓词

| 归因 | 求值次数 | 去重站点 | 含义 |
|---|---:|---:|---|
| `caller` | **102** | 10 | 调用方身份 —— 安全形态，绝大多数 |
| `unknown` | 31 | 13 | 第一个实参解释不出来（例如整段 `if` 被当作调用上下文） |
| `""`（同名遮蔽） | 8 | 4 | 名字被**同文件定义**遮住，helper 归约不出结论 → `UNKNOWN`，见 §6 |
| `request` | **4** | **2** | 请求派生身份 |
| **`caller_uid`** | **0** | **0** | → `identity-domain` |
| **`self`** | **0** | **0** | → `service-identity` |
| 合计 | 145 | 29 | |

30 个组件里**只有 9 个**求值到了任何授权谓词；其余 21 个是 0。这本身是一条覆盖面事实，
不是"这些组件没有权限检查"——它们的权限检查在文本里存在，只是不在入口根走得到的路径上。

### 2.1 两处 `request` 站点

| 组件 | 位置 | 所在函数 | 文件 sha256 |
|---|---|---|---|
| `ability_ability_runtime` | `services/abilitymgr/src/ability_manager_stub.cpp:3465` | `AbilityManagerStub::VerifyPermissionInner` | `7b59dfcac3b9fc4dd98c1fedfdb788fa1689bdfc252e7fde1b4a6c11307e6867` |
| `bundlemanager_bundle_framework` | `services/bundlemgr/src/bundle_installer_host.cpp:1838` | `BundleInstallerHost::CreateCliSandboxApp` | 见证据 JSON `value_attribution.sites.request` |

**第二处是文本代理漏掉的。** 文本法给的是"全语料 1 处"（交付项 6 §5 表里的 `request = 1`）。
解释器走到的是 **2 处**：`bundle_installer_host.cpp:1838` 的实参是
`envCreatorBundleName`，它是**形参**，调用点在第 1858 行传 `Str16ToStr8(data.ReadString16())`。

- 文本法**没有错**：它的 `classify()` 明确写着"经容器/成员/**函数**传递的，报未解析而不是猜"，
  所以它把形参报成 `identifier/unresolved`。**1 是下界，不是总数。**
- 解释器**也没有错**：它跨函数帧绑定了实参。两处都调用同一条 IDL 生成的分发器路径，
  所以这就是"跨函数绑定"这一能力带来的差异。

→ 交付项 6 §5 表里 `request` 那一行应读作**下界 ≥1**，最新实测 **2 处**；
`self` 的 16 与 `caller_token` 的 260 同为文本计数，未变。

## 3. 对侧对照：同一次运行里的 102 次 `caller`

规则不是在无差别地报谓词调用。同一次运行、同一条包装路径下，**102 次求值归因为 caller**，
0 次进入 `identity_issues`；§6 那 4 次同名遮蔽也没有被算成身份问题。
语料级对照因此有两个方向：**安全形态不报**（caller 102 / 0 报），
**遮蔽形态也不报**（8 次 / 0 报）。

## 4. 更正一：`service-identity` 的机制是**可达性**，不是敏感效应

交付项 6 §5 把 `service-identity` 的 16 处与 `request` 的 1 处并列，写"同样还需敏感效应"。
**这一句作废。** 本次两条独立检查：

1. **范围检查**：16 处 `self` 站点（连同 1 处 `request`）所在文件**全部**出现在各自组件
   报告的 `scope.shards[].paths` 里 —— 文件是**交到了检测器手里**的，17/17。
   所以沉默既不是范围问题，也不是语言问题。
2. **求值检查**：那 16 处**一次都没被求值**（§2 表 `self` = 0）。

原因是站点所在的函数形态。逐站点的所在函数（`/home/audit/wtmp/site_enclosing.py`）：

| 类别 | 例 |
|---|---|
| NAPI / kit 客户端接口 | `OH_AT_CheckSelfPermission`（`security_access_token`，C API）、`NapiDlpPermission::Init`、`CheckPermission`（account / dlp 的 napi 自由函数） |
| 客户端 / 会话对象 | `AccountIAMClient::CheckSelfPermission`、`AuthorizationClient::GetAuthorizationProxy`、`CJUIExtensionContentSession::SetWindowPrivacyMode` |
| 工具 / 封装 | `Permission::CheckSelfPermission`（wwm `utils/`）、`CommonTaihe::VerifyRingtonePermission`、`JsApplication::CheckCallerPermission` |

对照之下，唯一 1 处落在**服务分发**函数里的（`AbilityManagerStub::VerifyPermissionInner`，
请求派生）**被求值了**。所以走不走得到，与"是不是服务入口"对得上 —— 这正是入口根语义的
预期行为，不是缺陷。

**改判后的机制表**（替换交付项 6 §5/§6 的相关行）：

| 规则 | 机制 | 本次依据 |
|---|---|---|
| `identity-domain` | **形状不存在** | 解释器 145 次求值中 `caller_uid` **0**；文本法独立地也是 0 |
| `service-identity` | **可达性**：16 处在范围内但都是客户端/kit/工具函数，一次未被求值 | §4 的两条检查 |
| `request-identity` | **敏感效应前置条件**：2 处被求值、问题当场记下 2/2，但没有敏感调用 ⇒ 0 候选 | §5 |
| `caller-class` | 可达性（IDL 生成的分发器）：与 `service-identity` 现属同一类 | 交付项 4 + §4 |

## 5. 更正二：两处 `request` 站点为什么一条都不报

`analysis.py:1018-1021` 是唯一发射点：

```python
1018  sensitive = name in self.policy.sensitive_calls or name in self.policy.object_sensitive_calls
1019  if sensitive:
1020      for issue_fn, issue_node, issue_rule, issue_message in state.identity_issues:
1021          self.emit("AUTH-03", issue_rule, issue_fn, issue_node, state, issue_message, call=name)
```

即：记下的身份问题要变成候选，**同一条状态还必须走到一个被建模的敏感调用**。两处站点：

```cpp
// 站点 1：ability_manager_stub.cpp:3458-3471（14 行；文件 sha256 7b59dfca…）
int AbilityManagerStub::VerifyPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    std::string permission = data.ReadString();
    int32_t pid = data.ReadInt32();
    int32_t uid = data.ReadInt32();
    auto result = VerifyPermission(permission, pid, uid);   // ← 探针在此记录身份问题
    if (!reply.WriteInt32(result)) { ... }                  //   WriteInt32 不在敏感集合里
    return NO_ERROR;
}
```

```cpp
// 站点 2：bundle_installer_host.cpp:1817-1851（35 行），由同文件 :1853 的
// HandleCreateCliSandboxApp（IDL 分发器风格的名字，root_grade="dispatch"）在同一文件内调用
ErrCode BundleInstallerHost::CreateCliSandboxApp(const std::string &creatorBundleName,
    const std::string &envCreatorBundleName, const std::string &bundleName,
    int32_t userId, int32_t &appIndex)
{
    ...
    uint64_t callerToken = IPCSkeleton::GetCallingFullTokenID();      // caller 角色守卫
    if (!BundlePermissionMgr::IsCliToolCalling(callerToken)) { ... }  // 角色谓词，非权限谓词
    ...
    int32_t result = BundlePermissionMgr::VerifyPermission(
        envCreatorBundleName, Constants::PERMISSION_CLI_MANAGE_WEB_SANDBOX, userId);  // ← 站点
    ...
    auto installer = std::make_shared<BundleCliSandboxInstaller>();
    return installer->CreateCliSandboxApp(finalCreatorBundleName, bundleName, userId, appIndex);
}
```

两个函数体里**都没有**任何 `sensitive_calls ∪ object_sensitive_calls` 成员，
所以状态走到函数末尾时 `state.identity_issues` 仍在、却无处发射。
30 个组件 166 条候选按规则分布为：`relay.descriptor-boundary` 92、`capability.export` 43、
`auth.missing` 21、`auth.guard-coverage` 8、`auth.object-owner` 2 ——
**三条 identity 规则合计 0 条**，与上面两处"记录了问题但没有候选"逐条吻合。

### 5.1 站点 2 同时说明"敏感效应"这个前置条件是在**做事**的

站点 2 的语义是：**请求里给的** `envCreatorBundleName` 是否持有
`PERMISSION_CLI_MANAGE_WEB_SANDBOX` —— 服务在问"**另一个** bundle 有没有权限"，
而调用方本身已经过了 `IsCliToolCalling` 的角色守卫。这是**管理型校验**，不是
"用请求里的 UID 冒充调用方"。若把 `analysis.py:1018` 的合取去掉，这一处会被直接报成候选。

所以本次同时得到一条**反对草率放宽规则**的语料内证据：那个前置条件在这份语料上
压掉了 2 处站点，其中至少 1 处（站点 2）读起来是良性管理校验。
"让 `request-identity` 响起来"**不是**"删掉一个条件"，而是"补上入口建模**并且**不牺牲精度"
（技术总方案 §13.1："未知覆盖从分母剥离且单独统计"、"不为了候选数量多牺牲精度"）。

### 5.2 一并更正交付项 6 §6 的行号

交付项 6 §6 的代码块写 `3464 std::string permission = ... / 3465 VerifyPermission(...)`。
**该行号错 3 行**，实际是 **3461-3465**（`3464` 是空行）。文件 sha256
`7b59dfca…` 与当时逐字一致，所以是抄写错误而非版本漂移。本次起以下面的行号为准：

```text
3461  std::string permission = data.ReadString();
3462  int32_t pid = data.ReadInt32();
3463  int32_t uid = data.ReadInt32();
3465  auto result = VerifyPermission(permission, pid, uid);
```

## 6. 真实代码上的同文件同名遮蔽：一次正面对照

B_IPC 要求覆盖"本地同名函数体遮蔽"。语料里有真例子，且探针把它量出来了：
`multimedia_player_framework` 的 `services/services/recorder/ipc/recorder_service_stub.cpp`

```cpp
215      permissionResult = CheckPermission();    // 无实参的成员调用
218      permissionResult = CheckPermission();
...
1134 int32_t RecorderServiceStub::CheckPermission()
1135 {
1136     Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
1138     switch (audioSourceType_) {
1139         case AUDIO_SOURCE_VOICE_CALL:
1140             return AccessTokenKit::VerifyAccessToken(tokenCaller,
1141                 "ohos.permission.RECORD_VOICE_CALL");
...
```

解释器的行为，逐条由探针记录：

- `:215`/`:218`（4 次求值）→ 名字 `CheckPermission` 被**同文件定义**解析到 `:1134`，
  该 helper 多出口、归约不出结论 ⇒ 返回 `UNKNOWN`（`analysis.py:1360-1361`），
  **不**按框架谓词处理。记录 `subject=""`、`kind="unknown"`。
- `:1134` 体内的 `:1140` / `:1148` 两次 `VerifyAccessToken(tokenCaller, …)`
  **照常被求值**、照常归因为 `caller`（含在那 28 次里）。

即：遮蔽只导致**外层那次调用不被当成框架谓词**，**内层真实检查并没有被丢掉**。
这是"拒绝给予信用"方向的行为，与"读同一个名字就当成检查"正好相反 —— 与
`tests/fixtures/ipc/` 的同名夹具对照一致，并且这次是**真实代码**上的证据。

## 7. 这些数字**不**说明什么

- 145 次求值是**被走到**的谓词调用数，不是语料里的谓词调用数（文本法数到 **1,608** 个实参）。
  两者差的是**覆盖**：21 个组件一次谓词都没求值。**未被走到 ≠ 安全**。
- `caller_uid`/`self` 各 0 **不等于**"OpenHarmony 里不存在这种写法"；
  它等于"在这 30 个组件的入口可达范围内不存在"。
- 0 条 AUTH-03 identity 候选**不构成**这些组件安全的证据；它只说明这条规则的**两个前置条件
  同时满足**的站点在这份语料里没有出现。
- `request` 从 1 涨到 2 **不是候选移动**，是换测量方法后把一处文本法按设计拒绝解析的站点量出来了；
  两处都仍然 0 候选。
- 没有任何一条被升级为 confirmed；`validated_vulnerability` 全为 0；无 PoC、无动态验证。

## 8. 同一批报告里已经记着的性能数字

文档（技术总方案 T9 / PRD）要求"扫描时间与规模"。本批 30 个组件的报告里
`elapsed_seconds` / `peak_rss_kb` 是驱动自己写的，无需另测：

| 量 | 值 |
|---|---|
| 组件 / 文件 | 30 / 17,546 |
| 总墙钟（各组件串行相加） | **1,049.2 s**（≈17.5 min） |
| 单文件均值 | 0.060 s |
| 峰值 RSS 上限 | **1,914 MB**（`window_window_manager`，1,112 文件） |
| 候选 | 166 |

最慢三个：`window_window_manager` 201.5 s / 1,913 MB、`bundlemanager_bundle_framework`
174.5 s / 1,240 MB、`ability_ability_runtime` 124.9 s / 1,321 MB。
（探针那一跑是**加了 Python 包装**的，时间不可当性能数据用；上表取自未加包装的测量批次。）

对照：探针那一跑 30 个组件的墙钟合计明显高于 1,049.2 s（每个调用表达式多一次 Python
函数调用），所以**这里的分母不是探针**，只是同一批报告里驱动自己写的字段。

## 9. 复现

探针与聚合器**都已入库**，复现不需要 scratch 目录：

```bash
# pass 1：把解释器的归因记下来（30 个组件；墙钟见下）
# 驱动树是 **pinned 只读树 B**，不是 lane worktree —— 本线不改检测器，
# 也正因为如此 cwd 必须是 B（探针的 sys.path 补的是 cwd）。
cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b   # HEAD 635b3e0
IPC_PROBE_LOG=<out>/<component>/predicates.jsonl \
PYTHONPATH=/home/audit/ohscanner/worktrees/parallel-ipc-20261017/research/deliveries/ipc/probe_site \
  .venv/bin/python -m src.ohscanner.detectors.interface.audit \
    --repo-dir <corpus>/<component> --repository <name> --commit <sha> \
    --out-dir <out>/<component> --json-out <out>/<component>/report.json \
    --md-out <out>/<component>/report.md

# 聚合探针记录与该批报告，产出本目录的证据 JSON（数字全部机器生成，不手打）
.venv-web/bin/python research/deliveries/ipc/interpreter_arg_attribution.py \
  --probe-root <out> --audit-root <reports> \
  --corpus-root <corpus> [--corpus-root <corpus> ...] \
  --probe-site research/deliveries/ipc/probe_site/sitecustomize.py \
  --out research/evidence/interface/ipc/auth03_identity_probe_20261017/interpreter_attribution.json
```

组件清单**从已测的 audit 根枚举**，不硬编码：失败运行（有 `shard_errors`）与脏树会
打印原因后跳过；每个组件写 `<out>/<name>/predicates.jsonl` 与 `stderr.log`，
不覆盖任何已有证据报告。`--probe-site` 必填，其 SHA-256 写进证据 JSON 的
`instrument.sitecustomize_sha256` —— **该哈希必须与产出这批记录的那份文件逐字一致**，
所以本交付是先用入库版探针整批重跑、再取数，而不是拿 scratch 版的记录去配入库版的哈希。
`--audit-root` 刻意用**同一批**测量报告（30 份），因此 §2/§5 的论证里
"解释器求值了 N 次"与"该组件的候选有 M 条"来自**同一次**驱动的输出，
不是两次运行拼起来的。

`--probe-root` 是本批探针记录所在目录；`IPC_PROBE_LOG` 必须指向
`<out>/<component>/predicates.jsonl`（聚合器按这个文件名枚举，不用 shell 变量，
避免内联变量被 WSL 吃掉）。§4 的范围检查与逐站点所在函数仍是两个只读 scratch 脚本，
未入库（它们是**一次性核对**，不是可复用工具）：

```bash
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd /home/audit/wtmp && python3 -I check_scope_of_sites.py"
wsl.exe -d Ubuntu-22.04 -- bash -lc "cd /home/audit/wtmp && python3 -I site_enclosing.py"
```

**可复现性**：本交付不是把 scratch 版记录配入库版哈希，而是用**入库版探针整批重跑**
（30 个组件，04:32–04:52）后取数。重跑与本文件先前引用的数字**逐字相同** ——
`evaluations_by_subject {"": 8, "caller": 102, "request": 4, "unknown": 31}`、
`distinct_sites_by_subject {"": 4, "caller": 10, "request": 2, "unknown": 13}`、
`components_probed 30`、`components_that_evaluated_any_predicate 9`、
`records_reported_as_errors []`、`candidates_by_rule` 合计 166。
故本文件 §2 的每一个数字都有**两次独立运行**支持，且两次用的是同一份仪器。

## 10. 对"其他子类追平子类一"这条目标，本次又量到哪一步

本次没有把任何一条静默规则变成会响的规则，**也没有这个打算** —— 它把**机制**从"推断"
升级为"测量"，并据此**改判了一条**：

- 原来分成两类的三条身份规则，现在**两类**才对：`service-identity` 与
  `caller-class`、`position-underflow` 同属**覆盖**类（入口可达性）；
  只有 `request-identity` 属于**前置条件**类（敏感效应）。
- 覆盖类的三条，收益上界仍然是"补上 IDL 入口建模与跨 TU 一跳之后**可能**多出候选"，
  仍在 `analysis.py`，仍由并发 import 持有，本次未抢。
- 新增一条**可交付给集成人的具体请求**（比交付项 6 §5 更窄）：
  `request-identity` 已在 2 处站点点亮、被 `analysis.py:1018` 的合取挡住；
  若要让它与 `caller-class` 一样能在真实语料上产出候选，需要的是
  **把 IDL 生成的分发器纳入入口建模**，这与交付项 4 的缺口是同一处，
  不是新的改动面。
