# A 线 shared_ptr / lifetime 候选竞赛闭环（RC-JSPROXY）

更新：2026-10-15（中国标准时间）。

## 1. 结论和状态

从当前 208 条 shared_ptr 候选的独立静态复核结果中，选择 `RC-JSPROXY` 的 2 条候选作为证据最强项：

- `7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef`
- `844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c`
- diagnostic：`ohscanner.cpp.shared_ptr_race:fdd6e227d2ca661e`、`ohscanner.cpp.shared_ptr_race:cf558619929424b7`

A 线已完成：固定代码身份、Detector 事实、真实调用路径、入口/权限边界调查、触发条件、可达敏感操作、CIA 影响边界、本地隔离 Harness/PoC、最小补丁以及 vulnerable/fixed/patched 重复验证。

最终状态仍为 **`candidate/unknown`，`validated_vulnerability=0`**。已证明的是固定 `JSProxy` owner 在模型化调用形态下存在 ThreadSanitizer 可见竞争；尚未证明真实产品进程中的稳定崩溃、可利用内存破坏、跨应用数据泄露或权限提升。`confirmed/reportable`、最终报告归并和跨模块影响结论交项目负责人审核。

本报告只使用当前 208 条工作台 review ledger 的稳定 ID。历史 229 条逐条 ID 不可恢复，未建立或伪造任何映射。

## 2. 为什么选择 RC-JSPROXY

| 复核组 | 独立复核结论 | 本轮处理 |
|---|---|---|
| `RC-JSPROXY` | `SetInstance`/`GetInstance` 直接读写同一 `shared_ptr`，且 `NapiQueue::AsyncWork` 与同步 result-set 方法存在真实跨线程调用形态 | 选中并闭环 |
| `RC-PIP-CONTROLLERS` | 检测器命中的 getter/setter 主要用于 `ani_pip_utils.cpp` 的顺序对象转移；更广字段访问的线程归属仍未证明 | 不升级，保留候选 |
| `RC-REMOTE-CHANNEL` | `GetChannel`/`SetChannel` 受 `RemoteCommandManager::mutex_` 覆盖；外部引用生命周期仍未知 | 不选 |
| `RC-STREAM-LISTENER` | 构造初始化与后续 setter 未证明为同一对象上的并发冲突对 | 不选 |

`RC-JSPROXY` 的优势不是候选数量，而是有可审计的异步 execute、同步 read/close 调用链和无锁 owner 访问对。

## 3. 固定代码身份

目标仓库本地 checkout 为 detached HEAD，工作树干净；branch claim 不作为实现证明。

| 项目 | 值 |
|---|---|
| repository | `openharmony/distributeddatamgr_kv_store` |
| remote | `https://gitee.com/openharmony/distributeddatamgr_kv_store.git`（另记录 GitCode mirror） |
| commit | `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` |
| tree | `3b92c53fde616d5a3f9487b0c295670a42c63023` |
| vulnerable path | `frameworks/common/js_proxy.h` |
| blob | `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` |
| source SHA-256 | `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f` |
| Detector | `ohscanner.cpp.shared_ptr_race` |
| Detector version | `0.4.0` |
| rule | ohcpp-shared-ptr-race-candidate-001 |
| Detector implementation SHA-256 | 70197fb273054a20e2e6de82aa4eaa6bdeeaf4951ead6d5076b0e9832c65e230 |
| harness SHA-256 | `4f344ceb0fc4545dbc4870542a12af8bf5e1a28deb6a927eadf046c8ad2e7a06` |

调用路径源对象：

| path | blob | SHA-256 |
|---|---|---|
| `frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp` | `303443958e5fb9c4406e2e8dc6ab5894f7ff94bb` | `40d13acacbb7cedc7516c967990892f9999bee6a3ec2b5dbf3c7e2478740d7d7` |
| `frameworks/jskitsimpl/distributedkvstore/src/js_kv_store_resultset.cpp` | `97986ef7d4c1e73ddc0c5d8326db693e565c9914` | `3bf08751cc58a142674b17e2d80d23c936193ab61fa9ffde300ede6039bae65f` |
| `frameworks/jskitsimpl/distributedkvstore/src/napi_queue.cpp` | `a52a814a3570b7e274c9cd8d1a74f7d56f024f1c` | `b93054a1d7ab7e97b1c381029bdeb5101bd1feba77a77aa203245f2488de9ca9` |

## 4. Detector 事实

`ohscanner.cpp.shared_ptr_race` `0.4.0` 对 exact `js_proxy.h` bytes 返回 `completed` 和 2 条 candidate：

- `js_proxy.h:37`：`instance_` non-atomic write；
- `js_proxy.h:42`：`instance_` non-atomic read；
- primary candidate CWE：`CWE-362`；
- `CWE-416` 仅为可能后果；
- `synchronization_proof=unknown`。

同一 Detector 对 `fixed_control_mutex` 和 `patched_atomic_minimal` 均返回 `completed`、0 findings。0 findings 只表示该窄规则不再命中，不是全局安全结论。

## 5. 真实调用路径

1. `SingleKVStore.getResultSet` 注册于 `js_single_kv_store.cpp:155`，入口实现为 `JsSingleKVStore::GetResultSet`（`:1165`）。
2. `GetResultSet` 通过 `NapiQueue::AsyncWork` 提交 execute（`:1209`）；worker execute 在 `:1201` 调用 `ctxt->resultSet->SetInstance(kvResultSet)`，进入 `JSProxy<T>::SetInstance` 并写 `instance_`（`js_proxy.h:35-37`）。
3. `KVStoreResultSet.getEntry` 注册于 `js_kv_store_resultset.cpp:43`，同步入口 `GetEntry` 在 `:269-277` 调用 `GetInstance()`，复制同一 `instance_`（`js_proxy.h:40-42`）。
4. `SingleKVStore.closeResultSet` 注册于 `js_single_kv_store.cpp:156`，入口实现为 `CloseResultSet`（`:1217`）。execute 在 `:1244-1246` 执行 `GetInstance()`、`SetInstance(nullptr)`、`kvStore->CloseResultSet(resultSet)`。
5. `NapiQueue::AsyncWork` 在 `napi_queue.cpp:100-123` 通过 `napi_create_async_work` 和 `napi_queue_async_work_with_qos` 调度 execute；这为 JS 线程同步 result-set 方法与 async worker close/get-set 操作的并发提供了真实调度形态。

## 6. 入口、权限和触发条件

- 产品入口：同一应用的 ArkTS/JS `distributedKVStore.SingleKVStore` / `KVStoreResultSet` API。
- 对象来源：应用先通过 `createKVManager` / `getKVStore` 获得 store，再通过 `getResultSet` 获得 result-set wrapper。
- 权限边界：`getResultSet(keyPrefix)` 的已读输入路径没有显式 permission assertion；`Query` overload 检查 `IsSystemApi`/`IsSystemApp`。`DISTRIBUTED_DATASYNC` 在源码文档中与 auto-sync/sync 能力相关，不能外推为所有本地 result-set 操作的统一权限门。完整运行时部署策略仍为 `partial/unknown`。
- 跨进程/跨设备：未证明。当前证据只支持同一应用进程内的本地 owner race。
- 触发条件：
  1. `getResultSet` 成功取得 `KVStoreResultSet`；
  2. 在 JS 线程持续调用 `getEntry` 等同步方法；
  3. 同时调用 `closeResultSet`，让 execute 进入 async worker；
  4. 在 result-set 仍存活时重复 close/read，且没有 owner mutex/atomic API。

## 7. 可达敏感操作和 CIA 影响

可达敏感操作是 `kvStore->CloseResultSet(resultSet)` 与 result-set read 路径通过同一 `JSProxy` owner 并发执行，直接触及 native result-set 的 close/lifetime 操作。

| 维度 | 结论 |
|---|---|
| Availability | **candidate**：`shared_ptr` data race 产生未定义行为，可能导致应用进程崩溃/DoS；TSan 证明 race，未证明稳定 crash |
| Integrity | **unknown**：shared_ptr/control block 破坏或错误 result access 是可能后果，未动态证明 |
| Confidentiality | **not claimed**：没有跨应用/跨设备数据暴露证据 |

因此不满足 confirmed/reportable 的 CIA 影响证据门，继续保持 candidate/unknown。

## 8. PoC 和重复验证

Canonical evidence：`outputs/poc/shared-ptr-jsproxy-20261015/run-004/`，绑定当前 dirty worktree 中的 Detector implementation SHA-256。另保留 `run-001`、`run-002`、`run-003` 补充重放；各次 variant 结果一致。

Harness：`src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/harness.cpp`。它是自编最小 workload，围绕 exact `JSProxy` header bytes 模型化 async close 与 sync read；不是完整 OpenHarmony build 或 live KV store。

| variant | source meaning | Detector | race repeats |
|---|---|---:|---|
| `vulnerable` | exact target `js_proxy.h` | 2 | 3/3 `sanitizer_triggered` |
| `fixed_control_mutex` | 独立 mutex safe control | 0 | 3/3 `clean` |
| `patched_atomic_minimal` | 最小 proposed patch | 0 | 3/3 `clean` |

canonical race 均使用 4 readers、2 writers、50000 iterations；`single` 和 `unrelated` 控制均为 clean。run-001/002/003/004 均得到相同 variant 结果。

编译器：Ubuntu clang 14.0.0；sanitizer：ThreadSanitizer；本地隔离执行，无 live service。

## 9. 最小修复补丁和修复重验

补丁：`outputs/poc/shared-ptr-jsproxy-20261015/run-004/patch.diff`

- 补丁 SHA-256：`3b04fd4e5575e224df35f77be487f3cd90d0a40501b1ff65f5d01886037124c9`
- 仅修改 `frameworks/common/js_proxy.h`：加入 `<atomic>`，将 `instance_ = std::move(instance)` 改为 `std::atomic_store(&instance_, std::move(instance))`，将 `return instance_` 改为 `return std::atomic_load(&instance_)`。
- `git apply --check` 在 exact target checkout 上通过；未修改目标源码仓库。
- `fixed_control_mutex` source SHA-256：`9044ccaac42cefdd2c153c01b07c0893634aa0aee8ad54093e1065740329a902`
- `patched_atomic_minimal` source SHA-256：`4d57f286602e15af636c40158e8cdabc6f617fda89d8276128c674b4ab633b6f`

`fixed_control_mutex` 是独立安全控制，不是上游修复；`patched_atomic_minimal` 是本地方案，不声称是上游补丁。

## 10. CWE / CVE 和影响范围

- 主 CWE：`CWE-362`（共享资源并发访问缺少同步）。
- 可能后果 CWE：`CWE-416`（use-after-free），仅是候选后果；没有产品级 UAF 证据。
- CVE：本地证据中未识别/未分配 CVE，不伪造 CVE 映射。
- 受影响模块：`frameworks/common/js_proxy.h`、`frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp`、`js_kv_store_resultset.cpp`、`napi_queue.cpp`。
- 受影响版本：只确认 audited commit/tree；版本声明不外推。
- 受影响分支：unknown。目标本地 detached HEAD，无 tag/branch membership 证明。历史 `470b5336...` 可见相关 non-atomic owner 形状，但 API 形态不同，不能作为当前版本分支证明。

## 11. 证据门、限制和交付边界

已满足 A 线检测事实、Harness、PoC、补丁和修复重验要求；未满足产品级权限、攻击者控制、稳定 CIA 后果和可利用性证据门。

关键限制：

- PoC 是自编 workload，不是完整 OpenHarmony 构建或真实 distributed KV store 运行。
- TSan race 不等于稳定 UAF、内存破坏或跨应用泄露。
- 产品入口源码可见，但运行时 permission/deployment policy 仍 partial。
- 0 findings 不是安全证明；candidate 不自动升级。
- Detector 工作树包含未提交改动；本证据固定 implementation SHA-256，版本字段 `0.4.0` 本身不足以唯一定位实现。
- 历史 229 条逐条 ID 不可恢复，未伪造映射。

## 12. 重放命令

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.test_shared_ptr_jsproxy_poc -q"

wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m src.ohscanner.poc.cpp_shared_ptr_jsproxy --output outputs/poc/shared-ptr-jsproxy-20261015/replay --repeats 3"
```

A 线交付到此收口；`confirmed/reportable` 状态、最终报告归并和跨模块影响结论由项目负责人审核。
