# A 线 229 条候选勘误与首轮深挖报告

日期：2026-10-14（Asia/Shanghai）
Checkout：`codex/full-runtime-performance-audit-20261014`
HEAD：`34dbe374e2703466069ef719c95c9a527dd16971`
远端：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`

## 1. 勘误结论

本报告更正四类容易误读的表述：

1. **229 不是 229 个漏洞、根因或确认案例。**它是 A 线 `ohscanner.cpp.shared_ptr_race` 在五个固定组件、历史范围上的逐访问点 `syntax candidate` 诊断数。`validated_vulnerability=0`，`confirmed/reportable=0`。
2. **48 不是 48 个已证明根因。**现有聚类只按 snapshot、detector/version、rule、file、symbol、source SHA 分组，`root_cause_conclusion` 仍为 `not_inferred`。
3. **229 与当前 208 不能直接做准确率比较。**229 是历史 detector 快照；当前同范围复扫使用 `ohscanner.cpp.shared_ptr_race 0.4.0`，结果为 208。208/229 的差异是 detector 版本、同步建模和访问点归并变化，不是 FP/FN 统计。
4. **当前逐条报告里存在操作语义和范围语义勘误。**构造函数成员初始化被标成 `read`；`kvstoremock` 因路径段匹配规则未被排除；同一成员的跨文件写入不会出现在单文件诊断的完整上下文中。

## 2. 同范围复扫基线

源码补齐和逐文件 scope 已由 `research/evidence/cpp/source_sync_20261014.json` 与
`research/evidence/cpp/component_scans/` 固定。`scripts/verify_owner_cpp_components.py`
已核对 commit、tree、文件数、字节数、报告范围和 detector 版本。

| 组件 | 固定 commit | scope 文件/字节 | 历史 A | 当前 0.4.0 | 当前执行边界 |
|---|---|---:|---:|---:|---|
| `update_updateservice` | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` | 219 / 851345 | 3 | 1 | shared_ptr completed；lifetime completed |
| `security_access_token` | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` | 550 / 3484891 | 12 | 10 | shared_ptr completed；lifetime blocked/unknown |
| `distributeddatamgr_kv_store` | `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` | 1446 / 11765303 | 180 | 167 | shared_ptr blocked/unknown；lifetime blocked/unknown |
| `window_window_manager` | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` | 1112 / 20206691 | 31 | 27 | shared_ptr blocked/unknown；lifetime blocked/unknown |
| `communication_dsoftbus` | `652f88e0261ce4d0610f73cc451c26b84d2597af` | 1656 / 15243597 | 3 | 3 | shared_ptr completed；lifetime completed |
| **合计** |  |  | **229** | **208** | `validated_vulnerability=0` |

当前 208 条按 review grouping 为 44 组：`read=189`、`write=19`。这不是根因数量，也不是漏洞数量。

## 3. 首轮深挖：先处理的机制

### 3.1 `kv_store` 的 161 条高密度候选：优先视为稳定 owner pointer 形状

在 `distributeddatamgr_kv_store` 的
`frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp` 中：

- `nativeStore_` 69 条；
- `nativeQueryPtr_` 45 条；
- `nativeResultSet_` 28 条；
- `kvDataManager_` 17 条；
- `proxy_` 2 条。

源码检索显示这些成员主要在构造函数中初始化，之后通过 `->`/`.` 读取或调用，没有发现同一源码中的后续 owner 赋值。因此当前最可能的机制是：

> detector 把构造期 owner 初始化和后续稳定指针读取配对成共享指针竞争，导致逐访问点数量被放大。

这只能降低“shared_ptr owner 本身被并发改写”的优先级，不能证明安全。`DataQuery`、`KvStoreResultSet`、`SingleKvStore` 等 pointee 的内部状态是否线程安全、对象是否安全发布，仍为 unknown。此类候选应标为 `candidate / stable-owner-pointer-shaped`，不能标为 fixed 或 safe。

### 3.2 `kvstoremock` 3 条：生产范围误入

`kvstoremock/external_inner_kit/napi/include/extension_context.h` 被扫入，但它是 mock 形状的源码目录。当前 production-only 排除表只匹配精确路径段 `mock`/`mocks`，没有匹配 `kvstoremock`。

勘误：这 3 条不是生产组件候选，保留在历史报告中但应单独标为 `non-production/scope-error`；下一轮 scope manifest 必须显式排除或记录为 unrelated control。

### 3.3 仍然值得优先核查的可变 owner 访问对

以下形状有明确 setter/getter 或赋值/读取关系，当前没有可靠锁证明：

- `frameworks/common/js_proxy.h::JSProxy::instance_`：`SetInstance` 写、`GetInstance` 读，2 条；
- `ResultSetProxy::resultSet_`：构造/赋值与 `Create` 读取；当前 detector 只给出 1 条，源码中还有未被完整归并的读取；
- `communication_dsoftbus` `StreamManager::msgManager_`：`SetStreamMsgManager` 写、`GetStreamMsgManager` 读，2 条；
- `security_access_token` `RemoteCommandExecutor::ptrChannel_`：`SetChannel` 写、`GetChannel` 读，2 条；
- `window_window_manager` PIP controller 的 `mainWindowXComponentController_` / `pipXComponentController_` getter/setter，共 6 条。

这些是首轮 high-priority candidate，不是确认漏洞。必须补调用点、线程/事件队列、对象发布顺序和冲突触发条件；如果只能证明单线程初始化后再发布，才允许降级为 safe control。

### 3.4 单访问点和构造初始化噪声

`update_updateservice::StatusCache::timeUtilsProxy_`、`security_access_token` 的 `data_`/`asyncContextPtr` 共 9 条，源码形状主要是构造函数成员初始化或单个 handle 保存。当前消息把成员初始化标为 `read`，这是操作分类错误；单个词法访问也不足以证明外部同步。应增加 `constructor_only` / `single_lexical_access` 证据状态，而不是把它当成已观察冲突。

### 3.5 `StreamManager::streamListener_` 的跨文件缺口

`stream_manager.h:67` 的候选把构造函数初始化标为 `read`，但 `stream_manager.cpp:175` 还有 `streamListener_ = recvListener`。这意味着单文件诊断不是完整访问集合，不能据此判安全，也不能把该条简单归入“不可变指针”组。需要把跨文件 setter 写入纳入同一成员访问汇总。

### 3.6 第二轮调用点复核：优先级需要再分层

- `JSProxy::instance_` 是高优先级：`SetInstance` 在 NAPI async work 的 execute 阶段写入，`GetInstance` 在多个同步/异步回调中读取；当前未见锁。需要验证 `NapiQueue` 是否提供串行/发布边界。
- `JsKVStoreResultSet` 暴露出跨文件动态转移：async 完成时 `SetInstance(kvResultSet)`，`Create()` 先 `GetInstance()` 再 `SetInstance(nullptr)`，`CloseResultSet` 也执行 get-then-clear。该形状比当前单条 `resultSet_` 候选更完整，属于高优先级候选。
- `RemoteCommandExecutor::ptrChannel_` 的仓库内调用点均在 `RemoteCommandManager::mutex_` 下：`NotifyDeviceOnline` 在锁内 get/set，`GetExecutorChannel` 在锁内 get 并按值返回。首轮可标为 `candidate / narrow external synchronization observed`，但 `GetChannel()` 返回成员引用的 API 边界仍需审查。
- PIP controller 的 getter/setter 只在 `ani_pip_utils.cpp` 的两个顺序字段转移函数中成对出现；当前仓库内未见并发调用，优先级降低，但缺少产品线程/事件队列证明。
- `StreamManager::msgManager_` 在 factory 返回对象前只设置一次，仓库内未发现 `GetStreamMsgManager()` 调用；`streamListener_` 则在 channel 创建路径中再次写入且无锁。两者应拆开评估，不能合并成同一根因。

## 4. Detector/范围勘误项

1. **构造初始化语义**：`member(param)` 应记录为 `initialization/write`，不能记录为 `read`。
2. **初始化后稳定 owner**：只有后续 owner 赋值/重置才与初始化形成共享指针冲突；初始化后只读应单独记录 `stable_owner_pointer`，并保留 pointee 并发 unknown。
3. **单访问点策略**：纯构造初始化且无后续同文件访问时，输出 `unknown/constructor_only` 或 limitation，不应伪装成冲突 pair。
4. **跨文件成员访问**：同一类成员的 setter/getter 分散在 `.h/.cpp` 时，报告 limitations 必须明确“cross-file access set incomplete”。
5. **范围排除**：`kvstoremock`、`previewer/mock` 等非生产目录必须按明确规则排除，或在 manifest 中成为 unrelated control；不能因路径段拼写差异混入生产候选。
6. **源码哈希与报告哈希**：当前 `verification.json` 已重新计算 `communication_dsoftbus.json` 的 SHA-256 为
   `d77718d72403f8cae0a3a1a5cd4a7cb95174623d4f165d02b2d405226b8be4f1`；此前版本中的 `c7fdd...` 是报告被重写前的旧哈希，不能继续引用。

## 5. 证据边界

- 本报告只复核静态源码形状、固定 commit/tree/source hash 和 detector 输出。
- 没有证明真实入口、权限边界、触发条件、线程交错、CIA 影响、PoC 可利用性或 CVE。
- `blocked/unknown` 不是 miss；空结果不是安全结论。
- 没有独立 labelled holdout，不计算 Precision/Recall、FPR/FNR 或“零误报/零漏报”。
- `CWE-362` 是候选根因类别；`CWE-416` 只能是可能后果。

## 6. 下一步

1. 对 3.3 的可变 owner 访问对补齐调用图、事件队列/线程归属、发布顺序和触发条件。
2. 为 3.1 的稳定 owner pointer 形状建立 fixed/safe/unrelated controls，并验证 pointee 线程语义。
3. 修正 detector 的初始化操作、跨文件访问汇总和 scope 排除后，重新生成同范围报告；保留旧 229 身份和哈希，不改写历史结果。
4. 只有在入口/权限/触发/CIA/PoC/修复重验证据全部闭合后，才允许把某个候选升级为 confirmed/reportable。

机器可读摘要：`research/evidence/cpp/a_shared_ptr_229_erratum_2026-10-14.json`。
