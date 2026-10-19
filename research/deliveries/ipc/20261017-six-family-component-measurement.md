# 交付项 3：18 个真实组件的六家族实测（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **检测器（只读固定）**：`src/ohscanner/detectors/interface/`，`0.8.0` /
  `oh-ipc-2026.10-v6`，来源树
  `/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` @
  `635b3e0449c552f0ccc25118850d245962845568`
- **证据**：`research/evidence/interface/ipc/component_audit_20261017/`
  （`components.json` + `index.json` + 18 份 `.manifest.json`）
- 相关：[交付项 2 控制补齐](20261017-six-family-depth-unit.md)、
  [交付项 1 依赖清单](20261017-v080-dependency-inventory.md)

---

## 0. 一句话结论

18 个 OpenHarmony 组件、**10,413 个文件 / 1,528,120 行**被分析（8,364 个 AST 完整、
1,874 个 partial），共 **100 条候选、0 条 confirmed**。**11 条规则里只有 5 条在真实代码上
命中过**；`ipc.auth.missing` 以外的 AUTH-03 五条规则里四条、以及 DATA-01 的两条**一次都没有命中**。
这就是"其他子类还没到子类一同等水平"的**可量化版本**：不是夹具不够，是**规则在真实代码上
没有信号**。

## 1. 跑了什么

**argv（每个组件一次，由 `run_ipc_audit.py` 生成，非手抄）**：

```bash
<pinned>/.venv/bin/python -m src.ohscanner.detectors.interface.audit \
  --repo-dir <corpus>/<name> \
  --repository <owner/name>            # 由 git remote get-url origin 反推，不是手写
  --commit   <rev-parse HEAD>          # 每个目标仓库现算
  --out-dir  <out>/<name> \
  --json-out <out>/<name>/report.json \
  --md-out   <out>/<name>/report.md
```

驱动工作目录固定在只读来源树。两个 pass（`complete-ast` 与 `all-files`）都是驱动默认，
未改动。目标仓库必须有干净的 `git status --porcelain` 才跑，否则该仓库记 `dirty` 跳过，
避免把测量归到未固定的树上。

**语料**：两个 root、18 个仓库，无重叠，每个按 `rev-parse` 现场固定：

| 组件 | commit | 组件 | commit |
|---|---|---|---|
| security_access_token | `17d88bfb36be` | bundlemanager_bundle_framework | `9e67186cfade` |
| communication_ipc | `bbb92dbb2f52` | account_os_account | `af2e349854d8` |
| inputmethod_imf | `7777cba9eb19` | communication_bluetooth | `1eb489c9c403` |
| multimedia_camera_framework | `085a5d0e2dc1` | device_manager | `53654dce7302` |
| multimedia_player_framework | `9f9a285ff489` | distributeddatamgr_datamgr_service | `a6ba8ce1ec70` |
| notification_common_event_service | `aaaaf6d10aa8` | multimedia_audio_framework | `3a2688e805df` |
| resourceschedule_background_task_mgr | `cff2ff475e38` | sensors_sensor | `571dd5b5b5f5` |
| telephony_call_manager | `6638d1b37f27` | useriam_user_auth_framework | `54966af5d1b6` |
| update_updateservice | `e4942a33cc5e` | window_window_manager | `8b0d8fe1b973` |

**范围形状**：头文件**在范围内**（各组件 `.h` 占 20%–55%，例如 `security_access_token`
550 个选中文件里 308 个 `.h`）。这一点必须写明，见 §5.1。

## 2. 逐组件结果

| 组件 | tracked | 选中 | 完整/partial | LOC | 分析 | 秒 | 候选 |
|---|---|---|---|---|---|---|---|
| bundlemanager_bundle_framework | 10877 | 1069 | 912/102 | 224602 | 912 | 174.5 | **29** |
| multimedia_player_framework | 2902 | 920 | 578/342 | 87428 | 578 | 44.8 | **24** |
| communication_ipc | 1389 | 252 | 154/97 | 27365 | 154 | 12.2 | **12** |
| window_window_manager | 2450 | 1112 | 811/268 | 165340 | 811 | 201.5 | **10** |
| multimedia_camera_framework | 2262 | 1123 | 932/173 | 156092 | 932 | 56.7 | **9** |
| multimedia_audio_framework | 3603 | 1510 | 1317/193 | 281931 | 1317 | 70.8 | **6** |
| inputmethod_imf | 1032 | 412 | 330/72 | 44574 | 330 | 13.9 | **4** |
| resourceschedule_background_task_mgr | 490 | 196 | 162/26 | 24289 | 162 | 6.9 | **2** |
| telephony_call_manager | 621 | 395 | 324/69 | 71008 | 324 | 20.5 | **2** |
| update_updateservice | 289 | 219 | 187/31 | 15624 | 187 | 5.1 | **2** |
| account_os_account | 2496 | 451 | 400/49 | 85793 | 400 | 21.0 | 0 |
| communication_bluetooth | 835 | 640 | 466/160 | 85931 | 466 | 23.5 | 0 |
| device_manager | 448 | 213 | 204/1 | 26342 | 204 | 5.8 | 0 |
| distributeddatamgr_datamgr_service | 1278 | 631 | 448/183 | 52909 | 448 | 16.5 | 0 |
| notification_common_event_service | 432 | 146 | 121/16 | 33075 | 121 | 6.5 | 0 |
| security_access_token | 1989 | 550 | 489/56 | 72618 | 489 | 23.8 | 0 |
| sensors_sensor | 423 | 152 | 131/21 | 21941 | 131 | 4.4 | 0 |
| useriam_user_auth_framework | 945 | 422 | 398/15 | 51258 | 398 | 10.7 | 0 |
| **合计** | | **10413** | **8364/1874** | **1528120** | | **719.3** | **100** |

数字取自每份 `report.json` 的 `scope.counts` / `coverage.analysis_coverage` /
`complete-ast` pass_run；`components.json` 里每一行都带该报告的 `report_sha256`。

## 3. 逐规则：11 条里 5 条命中过

| 规则 | 家族 | 命中 | 分布 |
|---|---|---|---|
| `ipc.relay.descriptor-boundary` | AUTH-01 | **54** | player 24 / comm_ipc 10 / camera 7 / audio 6 / imf 4 / bundle 3 |
| `ipc.capability.export` | CAP-01 | **24** | bundle 14 / wwm 10 |
| `ipc.auth.missing` | AUTH-02 | **12** | bundle 7 / comm_ipc 2 / telephony 2 / camera 1 |
| `ipc.auth.guard-coverage` | AUTH-04 | **8** | bundle 5 / update 2 / camera 1 |
| `ipc.auth.object-owner` | AUTH-03 | **2** | background_task_mgr 2 |
| `ipc.auth.caller-class` | AUTH-03 | **0** | — |
| `ipc.auth.identity-domain` | AUTH-03 | **0** | — |
| `ipc.auth.service-identity` | AUTH-03 | **0** | — |
| `ipc.auth.request-identity` | AUTH-03 | **0** | — |
| `ipc.parcel.copy-range` | DATA-01 | **0** | — |
| `ipc.parcel.position-underflow` | DATA-01 | **0** | — |

按家族看：AUTH-01 **54**、CAP-01 **24**、AUTH-02 **12**、AUTH-04 **8**、
AUTH-03 **2**（5 条规则里 1 条）、DATA-01 **0**（2 条规则全 0）。

**"子类一"（AUTH-01）占全部候选的 54%**，而 AUTH-03 与 DATA-01 合计 2 条。
这个落差是本次最主要的实测事实。

## 4. 与本次控制的对照：这 6 条"能响但没响"

本次（交付项 2）给其中 3 条补了正例控制并实测可命中：

| 规则 | 本次新增正例 | 夹具上 | 1.53M 行真实代码上 |
|---|---|---|---|
| `ipc.auth.caller-class` | `auth03/caller_class_positive.cpp` | 命中（精确 1 条） | **0** |
| `ipc.auth.identity-domain` | `auth03/identity_domain_positive.cpp` | 命中（3 条，含耦合项） | **0** |
| `ipc.parcel.position-underflow` | `data01/position_underflow_positive.cpp` | 命中（精确 1 条） | **0** |

**"夹具能量出来"和"真实代码上会响"是两件事，这里两个方向都有证据。**

要区分"规则不能响"与"语料里没有这种形状"，需要的是**形状普查**而不是再扩组件数。
**已做**，见[交付项 4](20261017-shape-census-silent-rules.md)：在这同一批 10,413 个已扫描文件上，
`RewindRead(<含减号>)` 与 `Verify*Token(<调用方 UID>)` 各出现 **0** 次（前者裸调用 19 次、
后者相关调用 190 次与 `GetCallingUid` 1130 次却从不组合）→ 两条**未被行使**；
`caller_class_sensitive_calls` 出现 **70** 次却 0 候选，因为可达它的分发器由 **IDL 构建期生成、
不在源码树**（覆盖问题）；`copy_calls` 出现 665 次但绝大多数不在入口处理函数内（待逐条核）；
而 `owner_calls` 出现 2 次、`ipc.auth.object-owner` 恰好命中 2 次，**形状与候选精确吻合**。

## 5. 两个方法性发现

### 5.1 AUTH-01 的 descriptor 身份是**跨文件**解析的，只喂 `.cpp` 会凭空产出候选

`openharmony/security_access_token` @ `17d88bfb36be`，
`services/tokensyncmanager/src/service/token_sync_manager_stub.cpp`（在选中范围 550 个文件内、
`parse_status=complete`）：

- **只把这一个 `.cpp` 交给检测器** → **9 条** `ipc.relay.descriptor-boundary`
- **连同它的 `.h` 一起交给检测器** → **0 条**
- 对 `services/tokensyncmanager` 下 35 个文件逐一配对二分：**只有**
  `services/tokensyncmanager/include/service/token_sync_manager_stub.h` 这一个能把计数压到 0，
  其余 34 个谁都不改变结果。

原因：头文件写着 `class TokenSyncManagerStub : public IRemoteStub<ITokenSyncManager>`，
cpp 里是 `descriptor != ITokenSyncManager::GetDescriptor()` —— **这正是匹配的守卫**，
所以 **0 是正确的，那 9 条是缺头文件造成的假阳性**。
检测器声明 `ast_scope = "per_file"`，但 `Interpreter` 接收的是整个组件的 unit 元组，
身份解析实际是组件级的（限制条款里也写明了这一点：只有源码点出该类实现的接口，
比较才被算作守卫）。

**对本次结论的意义**：本实测的 scope 包含头文件，所以 100 条候选**不是**这一类产物。
对 100 条逐条查了 message 模板（`detector.py:27` "比的是别的接口"／`:32` "源码没说是哪个接口"
是身份分支，其余是入口分支），**没有任何一条落在身份分支上**：AUTH-01 的 54 条全部是
"入口没有 descriptor 比较"（24 条）、"dispatch 路径无匹配守卫"（19 条）、
"成员指针分发未解析"（2 条）——都是关于**入口**的声明。

**抽验一条**（`communication_ipc` @ `bbb92dbb2f52`，`dbinder/dbinder_service/src/dbinder_service_stub.cpp:164`）：
`DBinderServiceStub::OnRemoteRequest` 只读 `code` 就 `switch` 分发，
**没有任何 `ReadInterfaceToken`** ——真候选，判定正确。

**对夹具的意义**：现有 AUTH-01 夹具都是单文件喂入，因此表达的是"身份未给出"这一分支。
要表达"有比较但比的是别的接口"，夹具必须**同时给一个声明基类的头文件**。

### 5.2 被拒的运行同样写出"0 候选"的报告

第一次调用驱动时 `--repository` 传了裸名（非 `owner/name`），
`git_source.verify_repository_identity` 抛 `ValueError`，驱动**仍然写出报告**：

```json
"counts": {"source_files_audited": 1069, "candidates": 0, "confirmed_vulnerabilities": 0},
"shard_errors": [{"pass": "complete-ast",
                  "error": "ValueError: invalid declared repository name",
                  "files_not_analyzed": 1069}]
```

它和"真的没有候选"在 `counts` 里长得一模一样。本次在 `aggregate_audit.py` 与
`write_evidence.py` 里都加了闸门：`shard_errors` 非空 **或** `repository` 不含 `/`
的行一律拒绝，并把拒绝理由与 `report_sha256` 记进 `components.json` 的 `refused_runs`
（本次该数组为空，因为 18 个组件全部重跑成功）。
此前 `window_window_manager` 曾读到"0 候选"，就是这份残留文件；重跑后为 **10 条**。

## 6. 这些数字**不**说明什么

- 100 条全部是 **candidate（unassessed）**；`confirmed_vulnerabilities` 按构造为 0。
  **零候选不代表组件安全**（驱动的 limitation 原文），**有候选也不代表漏洞**。
- `all-files` pass 在驱动里记 `blocked`、scope 计数为 0；它贡献的是 recall 视角的同一批解释，
  不是第二份独立证据（限制条款原文）。
- 1,874 个 partial parse 的成因（格式宏拼接、`(this->*f)()`、`return` 作宏实参）在 v0.8
  卡片里已复现过；这里只影响覆盖率计数与义务来源，不是候选的成因。
- 未做：**形状普查**（§4 末）、**为什么 AAC/OS-account 这类组件 0 候选**（已排除解析与 scope，
  剩下的是"该组件的 IPC 入口是否都在范围内、是否都有 descriptor 比较"这一层，未逐条查）。
- 前几轮的 per-component 计数是在**其他 model 版本**下得到的，与本表不可直接比较，本次未做归并。

## 7. 复现

```bash
# 驱动与目标都在 WSL；语料在 /home/audit/openharmony-audit/perf-corpus 与 /home/audit/corpus-ipc-widen
python3 -I /home/audit/wtmp/run_ipc_audit.py        # 18 × 2 pass，约 12 分钟
python3 -I /home/audit/wtmp/aggregate_audit.py      # 逐组件 / 逐规则表
python3 -I /home/audit/wtmp/write_evidence.py       # 写 research/evidence/interface/ipc/...
```

底层命令见 §1 的 argv；`run-summary.json` 记录每次运行的 `repo_dir`、`out_dir`、
`commit` 与 `driver_commit`。原始 `report.json` 不入 Git（驱动规定生成物在 Git 之外），
入库的是 `components.json`（每行带 `report_sha256`）与 18 份 `.manifest.json`。
