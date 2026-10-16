# 交付项 6：第二批语料（+12 组件）实测，与三条 AUTH-03 身份规则的机制（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **检测器（只读固定）**：`src/ohscanner/detectors/interface/`，`0.8.0` /
  `oh-ipc-2026.10-v6`，来源树
  `/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` @
  `635b3e0449c552f0ccc25118850d245962845568`（两次批量同一 commit）
- **证据**：`research/evidence/interface/ipc/component_audit_shape_20261017/`
  （12 份 manifest + `components.json` + `index.json`）、
  `research/evidence/interface/ipc/auth03_identity_probe_20261017/probe.json`
- 相关：[交付项 3 基线 18 组件](20261017-six-family-component-measurement.md)、
  [交付项 4 形状普查](20261017-shape-census-silent-rules.md)、
  [交付项 5 DATA-01 机制](20261017-data01-mechanism.md)

---

## 0. 一句话结论

把语料从 18 个组件扩到 **30 个**（10,413 → **17,546** 个文件、1.53M → **2.44M** 行）
之后，候选从 100 涨到 **166**，但**涨的全部落在原本就已经响过的那三条规则上**
（AUTH-01 +38、CAP-01 +19、AUTH-02 +9）；**AUTH-03 的 5 条与 DATA-01 的 2 条仍然是 0**。
也就是说：**"再下几个组件"能加厚已经有的信号，不能把没有信号的规则变成有信号**。
本交付把剩下三件没被解释过的事做完了：

1. 用一个**实参普查**（`research/deliveries/ipc/permission_arg_classes.py`，只读）把三条
   AUTH-03 身份规则要的实参分类算清楚：30 个组件里授权谓词实参 **1,608** 个，
   `caller_token` **260**、**`caller_uid` 0**、`self` 16、`request` **1**。
   → `identity-domain` 是**形状不存在**（两种独立方法都得到 0），不是规则坏了。
2. 用 9 例探针把 `request-identity` 那唯一一处站点**逐条问到底**：形状**不是**充分条件，
   规则还要求同一条路径上有一个被建模的敏感效应（`analysis.py:1020` 才发射
   `state.identity_issues`）；而真实站点那个 handler 的调用者是**IDL 生成的分发器**，
   不在源码树里 —— 与 `caller-class` 同一类覆盖缺口。
3. 记录一个**必须标注的 0**：新下的 `applications_permission_manager` 是 **ArkTS 应用**，
   74 个选中文件没有一个是检测器声明的语言，**一个文件都没分析**。
   它的 0 与"这个组件没有 IPC 面"是两件事。

## 1. 第二批语料

12 个新仓库，全部 gitee origin、`git status --porcelain` 干净、按 `rev-parse` 现场固定：

| 组件 | commit | 组件 | commit |
|---|---|---|---|
| ability_ability_runtime | `4ae23f04b8f4` | distributedhardware_device_manager | `dce05abccbed` |
| communication_dsoftbus | `ccb1a86fff03` | filemanagement_dfs_service | `bec9c8471cf7` |
| distributeddatamgr_data_share | `84bbefd47473` | multimodalinput_input | `f7ac33c6097a` |
| distributeddatamgr_pasteboard | `e0a1320a94b3` | notification_distributed_notification_service | `4391741ef315` |
| distributeddatamgr_udmf | `1e2e3c35df02` | security_dlp_permission_service | `1adc5b0f36f6` |
| systemabilitymgr_samgr | `0b154e500567` | applications_permission_manager | `9fd6f1e3a65b` |

argv 与交付项 3 **逐字相同**（`run_ipc_audit2.py` 生成，唯一差别是 `--repo-dir` 指向
`corpus-ipc-shape`）。18 个第一批组件在新一轮里记 `already-measured` 跳过，**没有重跑**，
所以第一批那份记录仍是原来那份，两份证据目录互不覆盖。

**合计（两批）**：30 个组件、17,546 个选中文件、**2,435,311 行**、
13,634 完整 / 3,457 partial、1,049 秒、**166 条候选**。

## 2. 逐组件：新批次 12 个

| 组件 | 选中 | 完整/partial | LOC | 分析 | 秒 | 候选 |
|---|---|---|---|---|---|---|
| ability_ability_runtime | 2333 | 1925/272 | 282168 | 1658 | 124.9 | **48** |
| systemabilitymgr_samgr | 96 | 80/16 | 13575 | 80 | 3.5 | **9** |
| communication_dsoftbus | 1555 | 648/907 | 143935 | 648 | 87.2 | **4** |
| distributeddatamgr_data_share | 177 | 134/38 | 23858 | 134 | 5.9 | **4** |
| distributeddatamgr_pasteboard | 231 | 163/55 | 20861 | 163 | 7.5 | **1** |
| distributeddatamgr_udmf | 243 | 168/71 | 29551 | 168 | 8.1 | 0 |
| distributedhardware_device_manager | 386 | 318/51 | 69459 | 318 | 20.2 | 0 |
| filemanagement_dfs_service | 520 | 466/52 | 60235 | 466 | 14.6 | 0 |
| multimodalinput_input | 731 | 668/59 | 113914 | 668 | 26.3 | 0 |
| notification_distributed_notification_service | 622 | 552/45 | 126450 | 552 | 24.8 | 0 |
| security_dlp_permission_service | 165 | 148/17 | 23185 | 148 | 6.1 | 0 |
| applications_permission_manager | 74 | 0/0 | 0 | **0** | 0.7 | 0 |
| **合计** | **7133** | **5270/1583** | **907191** | | **329.9** | **66** |

两个数字要先说清楚：

- `communication_dsoftbus` 的 partial 比 complete **还多**（648/907）。它是 C 与 C++
  混写的，`lnn_hdf_driver_request.c` 一类文件走的是 C 解析路径。partial 影响的是覆盖率
  计数与义务来源，不是候选的成因（v0.8 卡片已复现过成因），但它的候选数要按
  "覆盖率更低"读。
- `notification_distributed_notification_service`（552 文件、126k 行）**0 候选**，
  而它恰好是 `Verify*Token` 调用最多（110 处）与 `GetOwnerUid` 最多（55 处）的组件。
  见 §5、§7。

## 3. 逐规则：候选只涨在已经响过的三条上

| 规则 | 家族 | 18 组件 | +12 组件 | 30 组件 |
|---|---|---|---|---|
| `ipc.relay.descriptor-boundary` | AUTH-01 | 54 | **+38** | **92** |
| `ipc.capability.export` | CAP-01 | 24 | **+19** | **43** |
| `ipc.auth.missing` | AUTH-02 | 12 | **+9** | **21** |
| `ipc.auth.guard-coverage` | AUTH-04 | 8 | +0 | 8 |
| `ipc.auth.object-owner` | AUTH-03 | 2 | +0 | 2 |
| `ipc.auth.caller-class` | AUTH-03 | 0 | +0 | **0** |
| `ipc.auth.identity-domain` | AUTH-03 | 0 | +0 | **0** |
| `ipc.auth.service-identity` | AUTH-03 | 0 | +0 | **0** |
| `ipc.auth.request-identity` | AUTH-03 | 0 | +0 | **0** |
| `ipc.parcel.copy-range` | DATA-01 | 0 | +0 | **0** |
| `ipc.parcel.position-underflow` | DATA-01 | 0 | +0 | **0** |

新增候选的分布：ability_runtime 48 条里 30 条 AUTH-01 + 10 条 CAP-01 + 8 条 AUTH-02；
samgr 9 = 5 + 4；data_share 4 = 2 + 1 + 1；dsoftbus 4 = 2 + 2；pasteboard 1。
**11 条规则里仍然只有 5 条在真实代码上命中过**，与交付项 3 的结论一致 —— 扩语料没有改变
命中集合。

## 4. 必须标注的 0：`applications_permission_manager` 一个文件都没分析

它的报告里 `counts.source_files_audited=74`、`candidates=0`，
看起来与"分析了 74 个文件、没有候选"**一模一样**。真实情况写在覆盖块里：

```json
"files_in_scope_without_a_claiming_detector": {"arkts": 65, "js": 4, "ts": 5},
"files_analyzed": 0
```

74 个选中文件**全部**落在检测器不声明的语言里（ArkTS/JS/TS），`files_analyzed=0`。
这是第三种"0 的理由"（前两种见交付项 3 §5.2 的被拒运行、交付项 5 的覆盖与正确静默）：
**没有声明该语言的检测器**。本次在证据写入器里给它单独加了 `zero_reason` 字段
（`research/evidence/interface/ipc/component_audit_shape_20261017/components.json`），
不让这个 0 混进"组件没有 IPC 面"的读法里。

选语料这一步的教训：从组织页按"名字里有 permission / security"挑仓库，
会挑到前端应用仓库。**C/C++ 组件要按文件语言挑，不能按仓库名挑**。

## 5. 三条 AUTH-03 身份规则要的实参，逐类数清

三条规则都不看"谓词本身"，看**谓词拿到的实参**（`analysis.py:1366-1376`）。
所以数谓词次数会高估形状。新脚本 `research/deliveries/ipc/permission_arg_classes.py`
（只读，括号配平取实参，允许一跳"同一文件里的局部赋值"）在 30 个组件的**报告范围内**
逐个分类授权谓词的每一个实参：

**237** 个文件含至少一个谓词；**1,608** 个实参：

| 实参类别 | 次数 | 说明 |
|---|---|---|
| `identifier`（本方法回溯不到） | 761 | 经容器/成员/函数传递的，未解析 |
| `other` | 541 | |
| **`caller_token`** | **260** | 调用方 TokenID ——**安全形态，占已识别的绝大多数** |
| `permission-literal` | 28 | 权限名字符串 |
| **`self`** | **16** | 服务自身身份（`GetSelfTokenID`/`getuid`，或重置身份后的调用方调用） |
| **`request`** | **1** | 请求派生身份 |
| `call/expression` | 1 | |
| **`caller_uid`** | **0** | → `identity-domain` 的形状 |

按谓词：`VerifyAccessToken` 241 标识符 / 88 caller_token / **14 self**；
`VerifyNativeToken` **116 caller_token**（几乎全是安全形态）；`VerifyPermission`
150 标识符 / 26 caller_token / 2 self / **1 request**；`CheckPermission` 339 标识符 /
30 caller_token。

三条规则的形状因此各有定量结论：

| 规则 | 形状 | 结论 |
|---|---|---|
| `identity-domain` | `caller_uid` **0** | **形状不存在**。与交付项 4 的裸正则（0 次）**互相独立**地得到同一个 0：那是"同一行内组合"，这是"允许一跳局部赋值"。 |
| `request-identity` | **1**（`ability_manager_stub.cpp:3465`） | 全语料唯一一处。逐条问到底是 §6。 |
| `service-identity` | **16**，其中只有 **1** 处在同时含 `ResetCallingIdentity` 的文件里 | 其余 15 处是**直接**用 `GetSelfTokenID()/getuid`（`analysis.py:1246` 直接给 `"self"`），不需要重置身份。9 个文件含 `ResetCallingIdentity`（bundle ×2、wwm ×2、ability/audio/camera/background_task/telephony 各 1）。 |

**顺带的一条正面对照**：260 处 `caller_token` 全部没有被这三条规则报出来 ——
规则不是在无差别地报所有谓词调用。这是"安全侧不报"的语料级对照
（夹具级对照见交付项 2 与 §6 的 `caller_token_safe`）。

## 6. 那唯一一处 `request-identity`：形状不是充分条件

站点（`ability_ability_runtime` @ `4ae23f04b8f4`，
`services/abilitymgr/src/ability_manager_stub.cpp`，文件 sha256
`7b59dfcac3b9fc4dd98c1fedfdb788fa1689bdfc252e7fde1b4a6c11307e6867`）：

```cpp
3464  std::string permission = data.ReadString();
3465  int32_t pid = data.ReadInt32();
3466  int32_t uid = data.ReadInt32();
3467  auto result = VerifyPermission(permission, pid, uid);
```

权限名、pid、uid **全部来自 parcel**，然后交给授权谓词。规则**没有**报它。
9 个探针（`/home/audit/wtmp/where_is_request_identity.py`，base 与 complete-ast 两个
pass 结果一致，记录在 `auth03_identity_probe_20261017/probe.json`）：

| 探针 | 内容 | 结果 |
|---|---|---|
| `real_body_no_sensitive_effect` | 上面 4 句**原文**放进入口，后面只有 `reply.WriteInt32` | **0 条（一条都没有）** |
| `real_body_with_sensitive_effect` | 同上 + 同一路径上 `StartAbility()` | **`request-identity` 1 条**（:8） |
| `fixture_shape_positive` | 夹具形态（请求值 + 谓词 + 敏感效应） | 1 条（:6） |
| `caller_token_safe` | 同一谓词、同一效应，实参换成 `GetCallingTokenID()` | **0 条**（对侧对照） |
| `self_identity_positive` | `GetSelfTokenID()` + `VerifyAccessToken` + 效应 | `service-identity` 1 条 |
| `caller_uid_positive` | `GetCallingUid()` + `VerifyAccessToken` + 效应 | `identity-domain` 1 条 |
| `real_name_inner_helper` | **同名** helper（`VerifyPermissionInner`）放**同一文件**、由入口按名调用 | **`request-identity` 1 条**（:7） |
| `REAL_stub_cpp_only` | 真实 `ability_manager_stub.cpp` 单文件 | AUTH-02 7 / CAP-01 7 / AUTH-01 25，**`request-identity` 0**，`parse_status=complete` |
| `REAL_stub_cpp_and_header` | 真实 `.cpp` + 它的 `.h` | 同上，两文件都 `complete` |

得到两条：

1. **形状不充分。** 同样的 4 句，后面没有建模的敏感效应时**一条都不报**；
   加上 `StartAbility()` 立刻报。原因是 `analysis.py:1020` 只在走到
   `policy.sensitive_calls` 名字时才把 `state.identity_issues` 发射出来，
   而 `VerifyPermission` 是**谓词**、不在 `sensitive_calls` 里。
   于是本语料里那 16 处 `self`、1 处 `request` **都是候选数的上界**，不是候选数。
2. **`*Inner` 这个名字不是障碍。** 同文件的 `VerifyPermissionInner` 由入口按名调用时
   规则**会**报（`real_name_inner_helper`）。真实文件解析完整、还是没有 —— 因为它的调用者是
   **IDL 构建期生成的分发器**（不在源码树），body 不落在任何入口根的路径上。
   这与 `caller-class` 的缺口**是同一件事**，不是第二条独立原因。

**这两条都不支持**"这是个漏洞"。`VerifyPermission` 的语义、能不能被普通应用调到、
`*Inner` 是否只由系统内分发器可达，本次都没有建立。它在这里的作用是**形状样本**：
证明规则的触发条件比"形状"更窄，并给出一条可复核的站点。

## 7. 普查在新语料上的更新

同一批 30 个组件、同一脚本 `research/deliveries/ipc/silent_rule_shape_census.py`：

| 形状 | 18 组件 | 30 组件 | 候选对照 |
|---|---|---|---|
| `caller_class_sensitive_calls` | 70 | **71** | `caller-class` 0 |
| `Verify*Token(caller UID)` 裸组合 | 0 | **0** | `identity-domain` 0 |
| 任何 `result_permission` 调用 | 190 | **348** | |
| `RewindRead(` | 19 | 19 | |
| `RewindRead(<含减号>)` | 2 | **2** | `position-underflow` 0 |
| `copy_calls` | 665 | **1860** | `copy-range` 0 |
| 拷贝调用实参里含 `Read*()` | 0 | **0** | |
| `owner_calls` | 2 | **57** | `object-owner` 2 |

三件事值得单列：

- **`copy-range` 的"正确静默"在新语料上守住**：1860 次拷贝调用按长度实参分类
  （`copy_range_arg_classes.py`）—— 标识符 753、`sizeof` 441、调用/表达式 286、
  其它表达式 195、**实参个数不够 184**、空 1；"拷贝实参里现成出现 `Read*()`" 仍是 **0**。
  同时那条**潜伏缺口**变大了：`ReadRawData` 120 次只有 1 个实参、19 次 2 个，
  `ReadBuffer` 45 次够不到规则的 `index=2` —— 规则的取参下标对这两个名字仍然够不着。
  （这属于规则定义改动，落在并发 import 正在写的 `analysis.py`，本线未动，
  仍建议由集成人裁决：按名字给下标，或把这两个名字移出 `copy_calls`。）
- **`owner_calls` 从 2 涨到 57，候选一条没涨**。55 处在
  `notification_distributed_notification_service`（`advanced_notification_service.cpp`、
  `advanced_notification_utils.cpp` 等）。这说明那个计数**不是**该规则的触发条件：
  `object-owner` 要的是**调用方/资源关系**（`state.owner`）与具名调用
  （`StartBackgroundRunningForInner` 一类）或 `object_sensitive_calls` 的请求实参，
  不是"读一次 owner uid"。**这两处 `report.json` 里的 55 与候选 2 的关系，本次没有逐条核**，
  只作为"文本计数会高估"的又一个实例记录。
- `caller_class_sensitive_calls` 71（59 处集中在 `security_access_token` 的头文件）与
  `caller-class` 0 的关系**不变**：可达它的分发器由 IDL 构建期生成，不在源码树
  （交付项 4 已证），本次语料扩大没有改变这一点。

## 8. 这些数字不说明什么

- 166 条候选**全部是 candidate（unassessed）**，`confirmed_vulnerabilities` 按构造为 0。
  **零候选不代表组件安全，有候选也不代表漏洞**（驱动 limitation 原文）。
- §5 的实参分类建立在**文本**上：允许一跳同文件局部赋值，经容器、成员、函数传递的一律记
  `identifier`/`other`（合计 1,302 个，占 81%）。所以 `caller_uid=0` 是**本方法的结论**，
  不是"世界上没有这种代码"的证明。
- §6 的探针用的是**夹具声明 + 真实语句文本**，不是该组件的完整翻译单元；它证明的是
  "规则还需要敏感效应"与"同文件同名 helper 会被走到"两条机制，
  不是这个组件的实际可达性结论。
- `dsoftbus` 的 partial 比 complete 多，它的 4 条候选只在 648 个 complete 文件上成立；
  `applications_permission_manager` 的 0 **不是**这个组件的信号（§4）。
- 未做：跨 TU 一跳的召回测量；IDL 生成分发器的建模；`ReadRawData`/`ReadBuffer`
  下标修正后的重跑；`owner_calls` 55 处与候选 2 的逐条关系。

## 9. 复现

```console
# 第二批 12 组件的批量（两次 pass，约 5.5 分钟）
$ python3 -I /home/audit/wtmp/run_ipc_audit2.py

# 全量聚合（30 组件，不依赖 run-summary）
$ python3 -I /home/audit/wtmp/aggregate_audit3.py /home/audit/wtmp/ipc-audit

# 第二批证据（写 research/evidence/interface/ipc/component_audit_shape_20261017）
$ python3 -I /home/audit/wtmp/write_evidence2.py

# §5 的实参分类（从仓库根运行；--list-sites 列出每一处 caller_uid/self/request）
$ .venv-web/bin/python research/deliveries/ipc/permission_arg_classes.py \
    --audit-root /home/audit/wtmp/ipc-audit \
    --corpus-root /home/audit/openharmony-audit/perf-corpus \
    --corpus-root /home/audit/corpus-ipc-widen \
    --corpus-root /home/audit/corpus-ipc-shape --list-sites

# §6 的 9 例探针（内存构造单元组，只读）
$ cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b
$ .venv/bin/python -I /home/audit/wtmp/where_is_request_identity.py

# §7 的形状普查（--detail <label> 逐条列站点；--detail copy 显示拷贝实参形态）
$ .venv-web/bin/python research/deliveries/ipc/silent_rule_shape_census.py \
    --audit-root /home/audit/wtmp/ipc-audit --corpus-root <同上> --detail owner_calls
```

`/home/audit/wtmp` 下的四个脚本（`run_ipc_audit2.py`、`aggregate_audit3.py`、
`write_evidence2.py`、`where_is_request_identity.py`）不入 Git，与交付项 3/5 的处理一致；
`permission_arg_classes.py` 在本线允许面内，随提交入库。

## 10. 对"其他子类追平子类一"这条目标，本次量到哪一步

- **量到的**：6 条从未命中的规则，现在每一条都有**可复核的原因**，而且都不是"规则坏了"：
  `position-underflow` = 跨 TU 覆盖（交付项 5，删守卫 A/B）；
  `copy-range` = 正确静默（1860 次调用逐类核，长度无一来自请求）；
  `identity-domain` = 形状不存在（两种独立方法都 0）；
  `request-identity` / `service-identity` = 形状存在但**还需要同路径的敏感效应**，
  且真实站点在**IDL 生成的分发器**之后（§6 的 9 例探针）；
  `caller-class` = 可达它的分发器不在源码树（交付项 4）。
- **没量到的**：把上面两条覆盖缺口补上之后**会多出多少候选**。那两处改动
  （跨 TU 一跳、IDL 入口建模）都在并发 import 正在写的
  `src/ohscanner/detectors/interface/analysis.py` 里，本线**未动**。
  可以现在说的只有上界：`caller_class_sensitive_calls` 71 处、AUTH-03 身份形状 17 处
  （260 处 `caller_token` 是安全形态、不该报），而它们**还要**再过一次敏感效应这一关。
- 因此"其他几个子类做到和子类一同样水平"这件事，**在当前检测器与当前语料下不可能靠扩语料达成**；
  它是一个检测器侧（入口建模）的改动，需要集成人把它当独立请求排期。
