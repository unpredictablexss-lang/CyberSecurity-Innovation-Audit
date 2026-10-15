# RC-JSPROXY A 线补证（不升级 confirmed/reportable）

更新：2026-10-15（中国标准时间）。

## 1. 本轮结论

状态保持 **`candidate/unknown`，`validated_vulnerability=0`，`confirmed/reportable=false`**。本补证不分配 CVE、不声明受影响分支/版本，不声称产品崩溃、UAF、数据泄露或权限提升。

已补强的事实：

- 固定 `distributeddatamgr_kv_store` commit/tree、`js_proxy.h` Git blob、Git blob payload SHA-256 和 checkout SHA-256。
- 固定 JSProxy -> `getResultSet` / `closeResultSet` / 同步 `getEntry` -> `NapiQueue::AsyncWork` 调用链及其源对象。
- 固定当前 Detector implementation SHA-256、Harness、PoC runner、manifest、测试和运行产物。
- 新增 `close_get_entry` 模式，直接模型化 `CloseResultSet` 异步 execute 清空 owner 与同步 `getEntry` 复制 owner 的交错。
- vulnerable / fixed_control_mutex / patched_atomic_minimal 在隔离环境各重复 3 次；generic race 与 `close_get_entry` 均为 vulnerable 3/3 TSan 触发、两种同步化变体 3/3 clean。
- 无法建立真实 OpenHarmony 组件构建或产品级 Harness；产品权限、完整性/机密性影响、跨模块影响和稳定可利用性均明确保持 `unknown`。

本文件是补充证据，不改写 `research/evidence/cpp/shared_ptr_jsproxy_2026-10-15.md`、历史报告、候选 ID 或 review。旧报告中的 Detector 版本字段与 implementation SHA 自报版本不一致；本补证以固定 implementation SHA 对应文件自报的 `0.5.0` 为当前实现事实。

## 2. 实际 checkout 与源对象

### 2.1 OHScanner 工作仓库

| 项目 | 实际值 |
|---|---|
| branch | `codex/full-runtime-performance-audit-20261014` |
| HEAD | `0dd71fd78baa01283df081f9bd02fe4b7f2df326` |
| tree | `8ecb14155c265bffe0a8b4ab7ee1a9451e8468e8` |
| remote | `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git` |
| dirty | 是；保留 detector/PoC/docs/research 未提交改动 |
| push | 未执行 |

### 2.2 目标仓库

| 项目 | 实际值 |
|---|---|
| repository | `openharmony/distributeddatamgr_kv_store` |
| local checkout | detached HEAD，工作树干净 |
| commit | `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` |
| tree | `3b92c53fde616d5a3f9487b0c295670a42c63023` |
| remote | `https://gitee.com/openharmony/distributeddatamgr_kv_store.git` |
| mirror | `https://gitcode.com/openharmony/distributeddatamgr_kv_store.git` |

SHA-256 口径：

- `sha256`：Git blob payload 的 SHA-256，是可跨 checkout 复核的 canonical source hash。
- `checkout_sha256`：本地工作树原始字节的 SHA-256；当前 checkout 含 CRLF，因此与 blob payload hash 不同。

| path | blob | Git blob payload SHA-256 | checkout SHA-256 |
|---|---|---|---|
| `frameworks/common/js_proxy.h` | `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` | `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f` | `e417eb614183e090fe9390e3c5842bfa8ff1bacb382b191e6560d4591cc6d050` |
| `.../js_single_kv_store.cpp` | `303443958e5fb9c4406e2e8dc6ab5894f7ff94bb` | `40d13acacbb7cedc7516c967990892f9999bee6a3ec2b5dbf3c7e2478740d7d7` | `b03b018ca1338bd668260e81e4e218d39f7b4a90dd1f0af6d7f5f65a943c9235` |
| `.../js_kv_store_resultset.cpp` | `97986ef7d4c1e73ddc0c5d8326db693e565c9914` | `3bf08751cc58a142674b17e2d80d23c936193ab61fa9ffde300ede6039bae65f` | `0506d6e6a21b6edc863e70f388f3af75c9cdf22e3fdb73504f7efca1c8ef6ac3` |
| `.../napi_queue.cpp` | `a52a814a3570b7e274c9cd8d1a74f7d56f024f1c` | `b93054a1d7ab7e97b1c381029bdeb5101bd1feba77a77aa203245f2488de9ca9` | `62711571d96440e846067822490734cd6d20a446b8e7f4b4c0530033e5568471` |

其余入口、权限和部署源对象的 blob/payload/checkout hash 固定在 `shared_ptr_jsproxy_supplement_2026-10-15.json` 与 Harness manifest。

## 3. Detector 与本地 Harness/PoC

| 项目 | SHA-256 / 版本 |
|---|---|
| Detector | `ohscanner.cpp.shared_ptr_race` `0.5.0` |
| rule | `ohcpp-shared-ptr-race-candidate-001` |
| Detector implementation | `70197fb273054a20e2e6de82aa4eaa6bdeeaf4951ead6d5076b0e9832c65e230` |
| Harness | `67e4eb8bb832b57ce224bae4d3cb020be348c84424d3c8791ce9504efa9d6b59` |
| PoC runner | `72dd5b44a65db18bf100338d4bb4e9ccf5fc1d02a9f93cce8900333b4d2b1f0d` |
| manifest | `d503621783eb96372571d4f62fb7315387a779c50654c01618c719a8b0d58f46` |
| tests | `6cf47c039692e28a0551c89ec11dd92a4651025629d91dcf79f328c6c2779695` |
| canonical `poc.json` | `f7a150fe071afd09723a90f1f9806f6c7effc59d808173ce4abeca737aa076d2` |
| evidence bundle | `d98d11a98dbb59a52917d9f723f3cb8ece4b0c8c912478544c56878d9bfd272f` |

Detector 对 exact `js_proxy.h` bytes 返回 `completed`、2 条 candidate（line 37 write、line 42 read），`synchronization_proof=unknown`。fixed control 和 minimal patch 均为 0 findings；这只说明窄规则不再命中。

## 4. 真实入口、权限和部署边界

### 4.1 已见入口

1. `@ohos.data.distributedKVStore` JS 测试可见 `SingleKVStore.getResultSet` / `closeResultSet`。
2. `JsSingleKVStore::GetResultSet` 注册并调用 `NapiQueue::AsyncWork`；worker execute 调用 `resultSet->SetInstance(kvResultSet)`。
3. `KVStoreResultSet.getEntry` 注册为同步方法，`GetEntry` 调用 `GetInstance()` 后同步执行 `resultSet->GetEntry(entry)`。
4. `CloseResultSet` 注册为异步方法；worker execute 先 `GetInstance()`，再 `SetInstance(nullptr)`，最后 `kvStore->CloseResultSet(resultSet)`。
5. `NapiQueue::AsyncWork` 通过 `napi_create_async_work` 调度 execute。

结论是 **source-visible same-application JS entry=partial**，不是完整产品入口证明。

### 4.2 运行时权限

- `GetResultSet` 的 `IsSystemApp` 守卫只在 `JSUtil::IsSystemApi(statusMsg.jsApiType)` 为真时强制；`IsSystemApi` 只识别 `DATASHARE` 输入分类。
- `test/unittest/distributedKVStore/config.json` 和 sample manifest 请求 `ohos.permission.DISTRIBUTED_DATASYNC`。
- `types.h` 只在 autoSync 配置注释中说明该权限必要，不能外推为 `getResultSet/getEntry/closeResultSet` 的强制权限。
- 三项目标入口没有观察到与该交错直接绑定的 permission assertion。

因此 **产品运行时权限=unknown**；测试/sample manifest 只是部署样例，不是策略执行证明。

### 4.3 部署边界

- `interfaces/jskits/distributedkvstore/BUILD.gn` 声明 standard-system `ohos_shared_library`，安装到 `module/data`，依赖完整 OHOS GN、NAPI、ability runtime、IPC 和外部库。
- `entry_point.cpp` 注册 `data.distributedKVStore`。
- `distributed_kvstore.js` 当前观察到 `requireInternal('data.distributedData')`；与注册名的差异需要真实产品 packaging/SDK resolution 证明。

因此 **部署边界=partial，产品 module resolution/image deployment=unknown**。

## 5. CloseResultSet 与同步 getEntry 的触发窗口

1. `getResultSet` Promise 返回后，JS 持有 `KVStoreResultSet`。
2. 调用 `closeResultSet(resultSet)`，JS 线程只负责 unwrap 和创建 async work。
3. NAPI worker execute 进入 `CloseResultSet`：读取 owner，随后写 `SetInstance(nullptr)`，再关闭底层 result set。
4. 在 worker 写 owner 的同时，JS 线程同步调用 `getEntry`，执行 `GetInstance()` 的 `shared_ptr` copy。
5. 没有 repository-local mutex/atomic API 保护 `instance_`，因此 owner copy 与 owner assignment 可重叠。

需要严格区分：

- Harness/TSan 已证明的是 **JSProxy owner `shared_ptr` read/write data race**。
- `getEntry` 对底层 `KvStoreResultSet` 的使用与 `kvStore->CloseResultSet` 是否形成 UAF/状态破坏，仍是 pointee protocol 的独立未知项。
- 若 `getEntry` 在清空前复制 owner，`shared_ptr` 会延长对象寿命；若清空后复制，得到 nullptr 并断言。不能据此伪造 UAF 或崩溃。

## 6. 隔离重复验证

Canonical run：`outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/`。

环境：Ubuntu clang 14.0.0、ThreadSanitizer、`TSAN_OPTIONS=halt_on_error=1:exitcode=66`、WSL2 x86_64。每个 variant 独立 include/binary/output；不访问 live service。

| variant | Detector | generic race | `close_get_entry` | controls |
|---|---:|---:|---:|---:|
| vulnerable | 2 | 3/3 TSan | 3/3 TSan | single/unrelated clean |
| fixed_control_mutex | 0 | 3/3 clean | 3/3 clean | single/unrelated clean |
| patched_atomic_minimal | 0 | 3/3 clean | 3/3 clean | single/unrelated clean |

`close_get_entry` 每次 2000 rounds。vulnerable 三次 TSan 栈均落在 exact `JSProxy<Widget>::GetInstance()` copy 与 `SetInstance()` assignment；fixed/patched 全部 clean。该结果证明受控 workload 可稳定复现 owner race，并验证两种同步化变体消除该 race；不证明产品级稳定可利用性。

## 7. 补丁与修复重验

- 补丁：`outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/patch.diff`
- SHA-256：`3b04fd4e5575e224df35f77be487f3cd90d0a40501b1ff65f5d01886037124c9`
- proposed local patch：`std::atomic_store(&instance_, ...)` / `std::atomic_load(&instance_)`；不是上游修复。
- `git apply --cached --check` 通过，证明 canonical Git-blob patch 可应用。
- 直接对 CRLF checkout 执行 `git apply --check` 需要 whitespace normalization；`--ignore-space-change` 通过。目标仓库未修改。

fixed source SHA-256：`9044ccaac42cefdd2c153c01b07c0893634aa0aee8ad54093e1065740329a902`。
patched source SHA-256：`4d57f286602e15af636c40158e8cdabc6f617fda89d8276128c674b4ab633b6f`。

## 8. CIA、稳定可利用性和跨模块影响

| 维度 | 本轮结论 |
|---|---|
| Product runtime permission | `unknown` |
| Availability | controlled race/UB candidate；产品 crash/DoS rate `unknown` |
| Integrity | `unknown`：没有 returned entry、result-set state 或 control block 破坏证据 |
| Confidentiality | `unknown`：没有跨应用/跨设备暴露证据；同应用可见性不是保密边界证明 |
| Stable exploitability | `unknown`：TSan race 稳定，但无产品 crash/UAF/内存破坏 primitive/权限边界穿越 |
| Cross-module impact | `unknown`：没有产品构建或多模块 runtime trace |

主 CWE 仍为 `CWE-362`。`CWE-416` 仅为可能后果，不作产品结论。未识别/未分配 CVE，不伪造 CVE、分支、受影响版本或产品崩溃。

## 9. 为什么当前不能建立真实组件构建/产品 Harness

- 当前组件 checkout 不含完整 OpenHarmony `//build` tree 和外部依赖闭包。
- `BUILD.gn` 需要完整 OHOS GN、NAPI、ability runtime、IPC、common event 等产品依赖。
- 当前 host 没有 `hvigorw`、Java、OpenHarmony SDK；只有 WSL clang 14 可用。
- 没有可隔离控制的真实 KV store backend + NAPI execute/complete event-loop fixture。

因此本轮执行的是 exact-header component Harness，不是产品运行；产品权限、完整性/机密性影响、跨模块影响必须保持 unknown。

## 10. 备选闭环候选同步评估

| 组 | 真实入口 | 可复现 PoC | 评估 |
|---|---|---|---|
| `RC-REMOTE-CHANNEL` | 潜在更强：SoftBus device-online 与 remote-command service；`ProcessOneCommand`/`CreateChannelIfNeeded` 可能与 `NotifyDeviceOnline` 交错 | 未建立 | **备选 #1**。`RemoteCommandManager::mutex_` 覆盖 manager map 与部分 Get/SetChannel，但 executor worker 对 `ptrChannel_` 的直接访问、外部引用生命周期和线程归属仍 unknown。当前证据不如 RC-JSPROXY 闭环。 |
| `RC-PIP-CONTROLLERS` | 有真实 PIP/window API，但 setter/source-rect/reset 看起来处于 event-loop 顺序路径 | 未建立 | 同对象跨线程交错未证明，不是更强闭环候选。 |
| `RC-STREAM-LISTENER` | 有 stream receive callback，但候选点是构造初始化与 setup 阶段 `SetStreamRecvListener` | 未建立 | callback 的独立 `listener_` 生命周期和同 owner write/read overlap 未证明，不是更强闭环候选。 |

备选定位使用既有 review 组和 diagnostic ID；本轮未把这些候选升级、未伪造其 PoC、版本或产品影响。

## 11. 交给项目负责人的最小接口/证据需求

1. 真实组件/device image 的可重复构建命令、完整依赖/工具链 manifest、产物 hash 和安装/package 路径。
2. 带 thread ID 的产品/NAPI fixture：JS thread、async execute、complete callback queue 和确切 close/getEntry 重叠窗口。
3. `getResultSet/getEntry/closeResultSet` 的运行时策略 trace：permission、app identity、user/sandbox、grant mode 和拒绝结果。
4. 产品进程 crash/sanitizer/memory 证据，区分 JSProxy owner UB 与 result-set use-after-close。
5. CIA 实测：availability failure rate、returned-entry integrity、跨应用/设备 confidentiality boundary。
6. Attacker control：调用者身份、所需权限、输入约束、触发速率/窗口、部署可达性。
7. 将补丁应用到真实组件，在相同 product build/profile 下重跑 vulnerable/fixed/patched；独立 reviewer 签字前不升级。

## 12. 重放

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.test_shared_ptr_jsproxy_poc -q"

wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m src.ohscanner.poc.cpp_shared_ptr_jsproxy --output outputs/poc/shared-ptr-jsproxy-supplement-20261015/replay --repeats 3"
```

结构化证据：`research/evidence/cpp/shared_ptr_jsproxy_supplement_2026-10-15.json`。
