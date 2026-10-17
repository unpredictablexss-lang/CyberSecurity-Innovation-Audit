# 交付项 16：第五批 5 个组件、六族实码发射面与逐族复核

> 本项同时回应两件事：
> 1. "**多下载几个组件仓库测试**"——新克隆 5 个组件（第 6 个无 `master`），
>    在 47,603,959 字节、5,619 个入选文件上重跑同一 argv；
> 2. "**把其他子类完成到和子类 1 同样的水平**"——把 11 条规则在 54 个真实组件上
>    的发射面、控制集和静默成因放到**同一张表**，并对每族新出现的真实候选做
>    一次源码复核，而不是只数候选。
>
> 本项不修改检测器、不删除任何候选、不改动任何语料克隆，也没有做任何 `git fetch`。

## 0. 一句话结论

54 个真实组件、六族 11 条规则，**每一族都至少有一条从真实代码发出的候选**：
AUTH-01 175、AUTH-02 22、AUTH-03 2、AUTH-04 8、CAP-01 56、DATA-01 1；
其中 AUTH-03 的五条规则只有 object-owner 发射，DATA-01 的两条只有 copy-range 发射。
其余四条（caller-class / identity-domain / service-identity / request-identity、
position-underflow）为 0，且每一条的 0 都在**同一 54 组件的形状普查**上有计数解释，
不是"规则应该没问题"的推断。

本批 5 个组件新增 84 条候选，其中 **83 条集中在 `graphic_graphic_2d`**；
`ability_form_fwk` 的 1 条 AUTH-02 经源码复核是**虚分派一跳**造成的疑似误报，
`multimedia_camera_framework` 的 AUTH-02 / AUTH-04 则是**变参宏体含 `##__VA_ARGS__`**
使守卫不可见的第三、第四个独立实例——与交付项 15 的 `FALSE_RETURN_V`、
交付项 11 的 `ENFORCE` 同属一个展开器边界，只是这次同时命中了两个子类。

## 1. 本批语料：5 个组件与固定版本

浅克隆 `--depth 1`（`clone_batch3.sh`），`account_app_account` 的
`git ls-remote --heads ... master` 没有返回分支，未克隆；其余 5 个的 SHA 与
`clone-manifest.txt`、报告里的 `commit` 三者一致。

| 组件 | commit | 入选文件 | 字节 | 完整/部分 AST | 候选 |
|---|---|---:|---:|---:|---:|
| `ability_form_fwk` | `0914d437af5988ffbea2ec29fa4259a943bceadf` | 605 | 5,059,884 | 397 / 188 | **1** |
| `communication_netmanager_base` | `d1a2c26d3dc07e4582b6d32417fe9a0f7d2359d7` | 739 | 5,767,040 | 615 / 115 | 0 |
| `filemanagement_app_file_service` | `a7815f653bd669026cad48421ed1ecc0dfbbe9f2` | 291 | 2,394,630 | 244 / 42 | 0 |
| `graphic_graphic_2d` | `286721f97d69fe04f9327ce38227c73e6f86160b` | 3411 | 26,981,078 | 2350 / 1051 | **83** |
| `multimedia_image_framework` | `5fbe952024f16cb518a5a7cec24063cffcc038bd` | 573 | 7,401,327 | 442 / 128 | 0 |
| **合计** | | **5619** | **47,603,959** | **4048 / 1524** | **84** |

4048 + 1524 = 5572，比 5619 少 47 个文件：这些是范围内但解析器不产 AST 的
非 C/C++ 文件，报告在 `files_in_scope_without_a_claiming_detector` 里逐个登记，
不是"没读"。

## 2. `graphic_graphic_2d`：83 条候选集中在 32 个 stub 文件

| 规则 | 候选 | 完整 AST | 部分 AST | 文件数 |
|---|---:|---:|---:|---:|
| `ipc.relay.descriptor-boundary`（AUTH-01） | 71 | 42 | 29 | 30 |
| `ipc.capability.export`（CAP-01） | 12 | 6 | 6 | 6 |
| **合计** | **83** | **48** | **35** | **32** |

这个组件有 1051 个部分解析文件，是 54 个组件里最多的；35 条候选只走了
`all-files`，报告自己标 `file_analysis_status=not_analyzed` /
`incomplete_ast:partial`。举一个可读的 CAP-01 路径
（`rosen/modules/composer/vsync/src/vsync_connection_stub.cpp:54`）：

```text
Entry=VSyncConnectionStub::OnRemoteRequest
path=((34, 'GetDescriptor() != remoteDescriptor => False'),
      (43, 'switch entry'),
      (46, 'reply.WriteInt32(ret) => True'),
      (50, 'ret != VSYNC_ERROR_OK => False'))
```

描述符校验在路径里出现了（第 34 行），所以 AUTH-01 不响；CAP-01 响在
`reply.WriteFileDescriptor`，路径上没有任何 caller 授权。这类"能力导出"候选
需要逐站点读语义（占位 fd、只回给已鉴权连接等都可能使其成为误报），本项只登记
分布与解析状态，**不逐条判真**。

## 3. `ability_form_fwk`：AUTH-02 的"虚分派一跳"

候选（`interfaces/inner_api/src/form_mgr_stub.cpp:1698`，两个 pass 都发出，
文件完整解析）：

```cpp
1683  int32_t FormMgrStub::HandleStartAbility(MessageParcel &data, MessageParcel &reply)
...
1693      sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
1694      if (callerToken == nullptr) { ... return ERR_APPEXECFWK_PARCEL_ERROR; }
1698      int32_t result = StartAbility(*want, callerToken);
```

候选路径只有两个空指针检查（`1688`、`1694`），没有任何鉴权。但
`FormMgrStub : public IRemoteStub<IFormMgr>`，`IFormMgr::StartAbility` 是纯虚
（`interfaces/inner_api/include/form_mgr_interface.h:456`），而服务实现
`FormMgrService` **继承 `FormMgrStub`**
（`services/include/form_mgr/form_mgr_service.h:58-60`），其重写体在
`services/src/form_mgr/form_mgr_service.cpp:1396-1410`：

```cpp
int32_t FormMgrService::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_START_ABILITIES_FROM_BACKGROUND);
    if (ret != ERR_OK) {
        HILOG_ERROR("start ability check permission denied");
        return ret;
    }
    ...
    return FormAmsHelper::GetInstance().StartAbilityByCallerToken(want, callerToken);
}
```

也就是说，第 1698 行是一次**经 `IFormMgr` 的虚调用**，守卫在被重写的实现里，
与候选行只隔一次类层次跳转。检测器没有绑定这次分派，候选自己的
`callee_and_policy` 义务状态也是 `unknown`。

**判定：疑似误报（虚分派一跳，守卫在实现类）；静态候选保留，不删除。**
还不能升格为"已排除"：本项没有证明 `FormMgrService` 是运行时唯一绑定，
也没有动态验证 `CheckFormPermission` 的 `checkSA` 默认值在本产品配置下的行为。

## 4. 变参宏守卫：同一展开器边界，这次同时命中 AUTH-02 与 AUTH-04

`multimedia_camera_framework` 的 `HCameraService::CreateCameraDevice`
（`services/camera_service/src/hcamera_service.cpp`）在第 1076 行显式检查权限：

```cpp
1076      int32_t ret = CheckPermission(permissionName, callerToken);
1077      CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "...", ret);
```

但 AUTH-02 与 AUTH-04 都发在 `1098`（`deviceForWrapper = new HCameraDevice(...)`），
两者路径相同：

```text
path=((1081, 'isPrivilegeApp => False'),
      (1097, 'deviceForWrapper == nullptr => True'))
```

路径里没有 1076/1077。原因在宏定义（`common/utils/camera_log.h:163-169`）：

```cpp
#define CHECK_RETURN_RET_ELOG(cond, ret, fmt, ...) \
    do { if (CAMERA_UNLIKELY(cond)) {              \
        MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);         \
        return ret;                                \
    } } while (0)
```

宏体含 `...` 与 `##__VA_ARGS__`，`cpp_macros.py:235-237` 的拒绝条件命中
`variadic_stringify_or_token_paste`，整个 `if` 不进入被解释的程序，守卫不可见。
该文件同时是部分解析（`file_analysis_status=not_analyzed`），两条候选都只走了
`all-files`。

这是该误报类的**第三、第四个独立实例**：
`FALSE_RETURN_V`（交付项 15，AUTH-01）、`ENFORCE`（交付项 11，AUTH-01）、
`CHECK_RETURN_RET_ELOG`（本项，AUTH-02 + AUTH-04）。它说明展开器的这条边界
不是某个子类的特例，而是**跨子类共享的**：同一个不可见守卫，会让"描述符边界"
和"授权缺失/守卫覆盖"同时响。

**判定：疑似误报（守卫在源码第 1076 行，且被变参宏包裹）；候选保留。**

## 5. DATA-01：唯一候选的源码复核，与唯一一个"形状存在但规则不响"

### 5.1 `copy-range` 的 1 条候选：容量与长度是同一个受检值

`communication_wifi`，`wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp:385`：

```cpp
364      int cfgLen = data.ReadInt32();
365      if (cfgLen <= 0) { ... return; }
369      if (cfgLen > MAX_LEN) { ... return; }          // MAX_LEN = 1024
374      const char *dataBuffer = ...data.ReadBuffer(cfgLen);
380      char* cfgData = new (std::nothrow) char[cfgLen];
385      if (memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen) != EOK) { ... }
```

候选路径里**有**这两条边界（`365: cfgLen <= 0 => False`、`369: cfgLen > 1024 => False`），
但仍然报 "lacks matched nonnegative/destination-capacity bounds"。读规则
（`analysis.py:1064-1072`）可知它要求 `state.upper` 里存在
`(cfgLen, 目标容量)` 这一对；而这里目标容量参数与拷贝长度参数**是同一个
`cfgLen`**，源码上 `length <= capacity` 恒真，规则却没有把 `cap == length`
当作匹配。目标缓冲区也是按 `cfgLen` 分配的。

**判定：疑似误报（同值容量/长度）；候选保留。** 这条同时是 DATA-01 的
第一个"真实代码候选 + 源码级误报类"，与 AUTH-01 的宏守卫复核同构。

### 5.2 `position-underflow`：形状存在，规则不响

54 个组件里 `RewindRead(` 共 14 处（5 个组件），其中带减号的只有 1 处：
`graphic_graphic_2d`，`rosen/modules/render_service_base/src/platform/ohos/rs_marshalling_helper.cpp:2327`：

```cpp
2327      if (readPosition > PIXELMAP_UNMARSHALLING_DEBUG_OFFSET &&
2328          parcel.RewindRead(readPosition - PIXELMAP_UNMARSHALLING_DEBUG_OFFSET)) {
```

这是一次**带下界检查的减法**，且位于一个错误日志分支里。规则没有发射；
现有仪器不能区分"守卫被建模"与"该站点未被走到"（报告不含逐站点求值轨迹），
所以本项只记录形状与源码事实，**不声称规则判对了**。

## 6. 六族 11 条规则：同一张发射面 / 控制集表

证据文件 `research/evidence/interface/ipc/family_parity_20261017/parity.json`
（`components_read: 54`，四个干净 audit 根，不含任何反事实运行）。

| 族 | 规则 | 实码候选 | 正控 | 族级 fixed | 族级 safe |
|---|---|---:|---:|---:|---:|
| AUTH-01 | `ipc.relay.descriptor-boundary` | **175** | 17 | 6 | 1 |
| AUTH-02 | `ipc.auth.missing` | **22** | 17 | 4 | 3 |
| AUTH-03 | `ipc.auth.caller-class` | 0 | 1 | 5 | 1 |
| AUTH-03 | `ipc.auth.object-owner` | **2** | 1 | 5 | 1 |
| AUTH-03 | `ipc.auth.identity-domain` | 0 | 1 | 5 | 1 |
| AUTH-03 | `ipc.auth.service-identity` | 0 | 2 | 5 | 1 |
| AUTH-03 | `ipc.auth.request-identity` | 0 | 1 | 5 | 1 |
| AUTH-04 | `ipc.auth.guard-coverage` | **8** | 5 | 2 | 2 |
| CAP-01 | `ipc.capability.export` | **56** | 10 | 4 | 2 |
| DATA-01 | `ipc.parcel.copy-range` | **1** | 2 | 2 | 1 |
| DATA-01 | `ipc.parcel.position-underflow` | 0 | 1 | 2 | 1 |

控制数从 `tests/fixtures/ipc/*/manifest.json` 与共享 manifest 读取；
fixed/safe 行在 manifest 里只写族名（`expected_rule: null`），所以按族计数，
不按规则计数。**六族都有正控、fixed、safe 三类**，没有一族只靠正控。

候选数为 0 的四条规则，每条都带一个 `corpus_zero` 字段（见 §7），
不是留空的 0。

## 7. 54 组件的形状普查：0 的计数解释

`silent_rule_shape_census.py` 在同一批报告的 shard 路径上做文本计数
（`shape_census.txt` / `shape_census_detail.txt`）：

| 形状 | 计数 | 组件数 | 与候选的关系 |
|---|---:|---:|---|
| `caller_class_sensitive_calls` | 12 | 6 | 规则 0：其中 6 处在 `*mock*` 路径；余下 6 处经探针确认**未从被建模入口走到** |
| `Verify*Token(caller UID)` | 0 | 0 | identity-domain 0：真实调用点传的是 token ID，不是 UID |
| 任意 `result_permission` 调用 | 260 | 33 | 说明不是 API 不存在，而是实参形态不满足 |
| `RewindRead(...)` | 14 | 5 | position-underflow 0：只有 1 处带减号，且是受检减法（§5.2） |
| `RewindRead(<args 有减号>)` | 1 | 1 | 同上 |
| `copy_calls` | 3349 | 40 | copy-range 只发 1 条：绝大多数长度不是请求派生 |
| `copy` 且实参含 `Read*` | 2 | 1 | 与 1 条候选不是同一站点，见 §5.1 |
| `owner_calls` | 55 | 1 | object-owner 发 2 条，都在同一组件（后台任务管理器） |

`caller-class` 的"未走到"不是推断：对含真实站点的三个组件
（`multimedia_audio_framework`、`ability_ability_runtime`、
`bundlemanager_bundle_framework`）用当前探针重跑，记录见
`callclass_probe_20261017/summary.json`：

| 组件 | 入选文件 | 探针记录 | caller-class 记录 |
|---|---:|---:|---:|
| `multimedia_audio_framework` | 1510 | 0 | 0 |
| `ability_ability_runtime` | — | 2（均为 `VerifyPermission`） | 0 |
| `bundlemanager_bundle_framework` | — | 2（均为 `VerifyPermission`） | 0 |

`caller_class` 桶在三个组件里都是空的：`analysis.py:1049` 需要的那条合取
（走到敏感调用且 `state.caller_class` 未设）一次都没有出现。这与
AUTH-03 的 0 条候选是同一条陈述，不是两个独立结论。

本批 5 组件的 `attribution.json` 也给出同样的方向：只有
`ability_form_fwk`（2 次）与 `communication_netmanager_base`（68 次）求值过权限谓词，
subject 全部是 `unknown` 或空串；caller/self/request 三个桶都是 0，
`caller_class` 求值次数为 0。

## 8. 复现

检测器只读 pinned 树
`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`
@ `635b3e0449c552f0ccc25118850d245962845568`，版本 0.8.0，
模型 `oh-ipc-2026.10-v6`。每个组件的 argv 与交付项 15 相同，仅替换路径：

```bash
cd <pinned tree>
<...>/.venv/bin/python -m src.ohscanner.detectors.interface.audit \
    --repo-dir /home/audit/corpus-ipc-batch3/<component> \
    --repository openharmony/<component> \
    --commit "$(git -C /home/audit/corpus-ipc-batch3/<component> rev-parse HEAD)" \
    --out-dir <out>/<component> \
    --json-out <out>/<component>/report.json \
    --md-out <out>/<component>/report.md
```

根探针与谓词探针只在同一 argv 上加 `PYTHONPATH` 与环境变量
（`IPC_ROOT_LOG` / `IPC_PROBE_LOG`），不改检测器返回值；探针版本与交付项 15
同一份文件。

证据文件（提交在本仓库）：

| 文件 | sha256 | 说明 |
|---|---|---|
| `family_parity_20261017/parity.json` | `c5bb6af459e21be734b179e0541c693543e09c8df0c59dd8406358663d041c34` | 54 组件、11 规则、控制集 |
| `family_parity_20261017/rules.json` | `e5a10dc4ef5bc7d3684131011dba03630787718b34d9b1938132c7506f68d834` | 由 pinned `families.registry()` 导出 |
| `family_parity_20261017/shape_census.txt` | `0a476f55476e361440902ad20e872d634730fef0a6c904894d66e54f15a6ce94` | 54 组件形状普查 |
| `family_parity_20261017/shape_census_detail.txt` | `c4103455f2c86e21f3ec48ebb89d406be8d23a1199231ffc7ba23817763e5a8b` | caller-class 逐站点 |
| `extra_corpus_batch3_20261017/components.json` | `33890e1e0c8483ab4864e0de5be95dc9df4481519f75be91fb79fc57bca5ce4f` | 本批 5 组件、zero_reason、哈希 |
| `extra_corpus_batch3_20261017/attribution.json` | `6902478d9f4348840052f3a3b2e79eacaa5ec6722a7a39cd7de83a670952f751` | 谓词求值与 subject |
| `callclass_probe_20261017/summary.json` | `d47d963697ad9765c4989a655a00426286af7f030b27238ec26b0cf09c524e1e` | 三个组件的 caller-class 探针汇总 + 原始 JSONL |

生成器与仪器（本轮运行时的版本）：

| 文件 | sha256 |
|---|---|
| `research/deliveries/ipc/family_capability_parity.py` | `e4957bbd34bce5288f6bf8da62e4d0e4a375b22ea457d1cf69195e059762688c` |
| `research/deliveries/ipc/silent_rule_shape_census.py` | `b14196ef384c686e31a6c087d6e07d20067c3b6fb2660a9f1dd6ca844220d7a0` |
| `research/deliveries/ipc/extra_corpus_measurement.py` | `05cab6c189f78d81b96264d4b4c263734a936e9bf697d0482677b9ba26a84922` |
| `research/deliveries/ipc/probe_site/sitecustomize.py` | `67177e28683de37037e6b0b2bb88db86f2cd8453c80f5fbef452db95b23a5c9e` |
| `research/deliveries/ipc/root_probe_site/sitecustomize.py` | `8e49770f2e1db6dd3d9c3f9bd53e26fb2b0fb4b14f82f4338c05eac78ecaca16` |

`shape_census.py` 本轮从单 `--audit-root` 扩展为可重复传入（同一份报告只计一次，
重复时向 stderr 打印），`extra_corpus_measurement.py` 的 `--batch` /
`--attribution` 改为参数，避免把上一批的标签写进这一批。

## 9. 限制

- 语料是 2026-10-17 的 `master` 浅克隆快照，不覆盖分支与历史；
- 本批 1524 个部分解析文件里产出了 35 条候选，宏守卫误报与部分解析在同一
  文件上同时存在，本项没有把两者拆开归因；
- §3 的"虚分派一跳"是本项读源码的结论，检测器尚未绑定虚调用；
  该候选的 `callee_and_policy` 义务仍是 `unknown`；
- §5.1 的"同值容量/长度"同样只是源码复核结论，未做动态验证；
- `caller-class` 的"未走到"以三个组件上的探针为准，不外推到其余 48 个组件；
- 54 个组件之外仍有未测组件；本批数字不能代表整个 OpenHarmony；
- 所有候选均为未验证静态证据，`validated_vulnerability` 仍为 0。
