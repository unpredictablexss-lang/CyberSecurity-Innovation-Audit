# communication_netmanager_ext：IPC 候选与 GN 构建归属复核

日期：2026-10-18
工作线：`work/ipc-20261017`
审计仓库：`openharmony/communication_netmanager_ext`
固定组件提交：`8c35917b7e2f152813b13a20530a8452cf73d938`
固定组件 tree：`e26372f6cd65be928b9c1cf4a96d3c7dd5ece804`

## 结论

本次对《IPC 候选入口来源与 G 盘实测复核》中的 11 条候选做了固定提交 GN 目标追踪。证据把“入口代码是否属于产品构建”和“候选锚点的服务实现是否也编进产品目标”分成两件事：

| 证据问题 | 结论 | 可支持的说法 |
|---|---|---|
| fuzz harness 入口是不是产品入口 | 否；GN 中标为 test-only | 三个入口分别在 `ohos_fuzztest` 目标中，fuzzer 聚合 group 也声明 `testonly = true`。不能把 harness 自己当成产品的真实 IPC 调用路径。 |
| harness 是否链接了服务处理代码 | 是；链接 test-only 静态库 | 三个 fuzz 目标分别依赖对应服务的 `*_static` 目标；静态目标也声明 `testonly = true`，并包含相应服务实现源文件。 |
| 候选锚点服务代码是否存在产品构建目标 | 是；有条件的非 test-only 共享库 | 同一服务 `.cpp` 也列在正式 `ohos_shared_library` 的 `sources` 中；组件根 `bundle.json` 将服务包 group 列为 `service_group`，根 `BUILD.gn` 按 feature flag 接入这些共享库。 |
| 这些库是否进入某一具体 OpenHarmony 产品镜像 | unknown | 还没有固定具体产品/设备的完整源码树、GN args、产品配置与最终 target graph。组件仓库内的 bundle/group 证明“可被产品构建选择”，不证明任意产品镜像实际包含它。 |

因此，人工复核已把 11 条候选的 fuzz harness 来源确认成 test-only；但现有扫描报告里的 `entry_build_membership` 义务仍保持 unknown，因为检测器尚未解析并记录这些 GN 证据。产品入口可达性、目标镜像是否启用功能、以及候选安全结论也仍未解决。不能因此把 11 条整体判成误报，也不能把服务源进入共享库等同于漏洞成立。

## 逐项定位

候选位置与固定报告 `/tmp/ohscanner-b-ipc-provenance-20261018/communication_netmanager_ext.json` 一致；该 JSON 是本机实验产物，不入库。

| 候选锚点 | 规则 | 入口定义 | fuzz GN 目标 | 生产服务目标 |
|---|---|---|---|---|
| `services/ethernetmanager/src/ethernet_service.cpp:124` | `ipc.auth.missing` | `test/ethernetmanager/fuzztest/ethernetclient_fuzzer/ethernet_client_fuzzer.cpp` | `EthernetClientFuzzTest` → `fuzztest` | `ethernet_manager` |
| `services/mdnsmanager/src/mdns_service.cpp:121` | `ipc.auth.missing` | `test/mdnsmanager/fuzztest/mdnsclient_fuzzer/mdns_client_fuzzer.cpp` | `MDnsClientFuzzTest` → `fuzztest` | `mdns_manager` |
| `services/networksharemanager/src/networkshare_service.cpp:98` | `ipc.auth.missing` | `test/networksharemanager/fuzztest/netshareclient_fuzzer/netshare_client_fuzzer.cpp` | `NetShareClientFuzzTest` → `fuzztest` | `net_tether_manager` |
| `services/networksharemanager/src/networkshare_service.cpp:115` | `ipc.relay.descriptor-boundary` | 同上 | 同上 | 同上 |
| `services/networksharemanager/src/networkshare_service.cpp:117` | `ipc.relay.descriptor-boundary` | 同上 | 同上 | 同上 |
| `test/ethernetmanager/fuzztest/ethernetclient_fuzzer/ethernet_client_fuzzer.cpp:122` | `ipc.relay.descriptor-boundary` | 自身 | `EthernetClientFuzzTest` → `fuzztest` | 锚点在 harness |
| `test/ethernetmanager/fuzztest/ethernetclient_fuzzer/ethernet_client_fuzzer.cpp:157` | `ipc.relay.descriptor-boundary` | 自身 | 同上 | 锚点在 harness |
| `test/mdnsmanager/fuzztest/mdnsclient_fuzzer/mdns_client_fuzzer.cpp:134` | `ipc.relay.descriptor-boundary` | 自身 | `MDnsClientFuzzTest` → `fuzztest` | 锚点在 harness |
| `test/mdnsmanager/fuzztest/mdnsclient_fuzzer/mdns_client_fuzzer.cpp:142` | `ipc.relay.descriptor-boundary` | 自身 | 同上 | 锚点在 harness |
| `test/networksharemanager/fuzztest/netshareclient_fuzzer/netshare_client_fuzzer.cpp:135` | `ipc.relay.descriptor-boundary` | 自身 | `NetShareClientFuzzTest` → `fuzztest` | 锚点在 harness |
| `test/networksharemanager/fuzztest/netshareclient_fuzzer/netshare_client_fuzzer.cpp:143` | `ipc.relay.descriptor-boundary` | 自身 | 同上 | 锚点在 harness |

“锚点在 harness”只表示该文件不是组件产品 target 的源文件；没有据此删除候选或声明误报。还需要复核这些规则是否把测试驱动封装误解释成真实 IPC relay 边界。

## 候选质量复核

将 GN 事实与固定源码调用点放在一起看，11 条候选可分为两类；这里只作本轮人工分诊，不改历史 JSON，也不删任何候选：

- **6 条锚在 fuzz harness 自身**（Ethernet 2、mDNS 2、NetworkShare 2）。它们所在文件只由 test-only fuzz target 编译，因而不属于这三个组件服务的产品 target。对于“产品漏洞”口径，这 6 条应视为测试代码范围结果，不能计作产品漏洞候选；若规则要保留它们用于检查测试驱动本身，应在报告里单独标记 source role。
- **5 条锚在服务实现的 Init 路径**（三条 Publish AUTH-02：Ethernet :124、mDNS :121、NetworkShare :98；两条 NetworkShare relay：:115、:117）。固定源码显示 Ethernet OnStart()（:52-68）、mDNS OnStart()（:82-93）、NetworkShare OnStart()（:53-70）都直接调用各自 Init()。相应命中分别是服务启动期发布系统能力、订阅 CommonEvent/Wi-Fi 共享通知；不是处理某个 IPC 请求时的授权/relay 决策。fuzzer 也通过本地 Init() 包装触发这些逻辑。因此这些命中很可能是入口上下文/规则适用性误报，而不是“产品里没有这段代码”：同一实现确实进入条件式产品共享库。
- 上述 5 条的候选锚点是真实产品源代码，但导致规则命中的上下文是服务启动路径。更准确的修复方向是让检测规则要求敏感操作处于可信 IPC dispatch/request context，或证明实际 attacker-controlled request 到达该操作；不应把 Publish、事件订阅等服务启动操作一概当作缺授权。

建议对 6 条 harness 锚点和 5 条 Init 锚点分别保留 likely_false_positive_for_product_scope 的复核标签（或等价人工标签），不把它们计作已确认漏洞。当前扫描协议尚无该标签，本报告只记录判断，不改候选 severity/status；要写入正式 triage DB 或扩展候选分类，需按公共契约流程处理。

这项分诊使本组件 11 条候选中没有一条目前构成经证实的产品漏洞证据。此结论只针对这批候选和当前规则/组件提交，不外推到整个仓库无漏洞，也不代替独立标注集上的误报率测量。

## 固定源码证据链

以下均基于固定组件提交。审计重点文件的 Git blob 身份：

| 路径 | Git blob |
|---|---|
| `test/ethernetmanager/fuzztest/ethernetclient_fuzzer/BUILD.gn` | `3451c6f63dddf43629ffb44368d934297bd128bf` |
| `test/mdnsmanager/fuzztest/mdnsclient_fuzzer/BUILD.gn` | `be10f332100fce24a793214617f2956f5afbacd7` |
| `test/networksharemanager/fuzztest/netshareclient_fuzzer/BUILD.gn` | `a6d0dd40a4d234219f6911304d01184a63a33132` |
| `services/ethernetmanager/BUILD.gn` | `acd196fb27d80d13b977c9e52d149c698fa8263e` |
| `services/mdnsmanager/BUILD.gn` | `bd943e2bb8a14395c45ba122478ff73e8bc4781f` |
| `services/networksharemanager/BUILD.gn` | `d9c25e223fae52975870a63595d425764226d816` |
| `BUILD.gn` | `fa1071aebb9c15fb9de869ae72a902e0428fbd03` |
| `bundle.json` | `1d61d31b4ca8a5d91565058d015eaffcb66b23d1` |
| `netmanager_ext_config.gni` | `39c03b2172aa49fd453df816582e732089df508f` |



1. 三个 `test/.../fuzztest/.../BUILD.gn` 分别定义 `ohos_fuzztest` 并把对应 harness 纳入 `sources`：Ethernet 第 21、50 行；mDNS 第 19、46 行；NetworkShare 第 21、53 行。末尾的 fuzztest group 都声明 `testonly = true`，依赖本 fuzz target（分别第 93、71、113 行）。
2. fuzzer 的 deps 指向 `ethernet_manager_static`、`mdns_manager_static`、`net_tether_manager_static`（fuzz BUILD 分别第 56、50、59 行）。服务 BUILD 中这些静态库也显式标为 `testonly = true`（分别第 128、92、160 行），且源列表含对应 `*_service.cpp`（分别第 142、106、175 行）。
3. 同一服务 BUILD 还定义非 test-only 的 `ohos_shared_library`：`ethernet_manager`、`mdns_manager`、`net_tether_manager`。各自 sources 同样包含候选服务源（分别第 26/33、36/41、43/48 行）。
4. 组件根 `bundle.json` 的 `component.build.group_type.service_group` 第 114–116 行列出 `ethernet_packages`、`share_packages`、`mdns_packages`。根 `BUILD.gn` 第 25–70 行的 group 分别按 `netmanager_ext_feature_ethernet/share/mdns` 依赖相应共享库；ethernet/share 还在 `!netmanager_ext_fpga_mode_enable` 条件下添加服务库。
5. `netmanager_ext_config.gni` 第 62–64 行这些 feature 的默认值为 true，但默认配置不证明具体产品最终采用它。产品 GN args、功能裁剪、系统类型与构建入口会影响镜像内容。
6. 组件级 GN 不是完整产品构建图。要证明某一镜像实际包含目标，需固定完整 OpenHarmony manifest/product configuration，解析最终 GN target graph，并保存产品配置、args、生成目录和目标清单哈希。

代表性代码也说明 harness 的性质：`netshare_client_fuzzer.cpp` 定义本地 `OnRemoteRequest`，用 `DelayedSingleton<NetworkShareService>` 初始化并直接调用服务对象的 `OnRemoteRequest`；这是 fuzz 测试在进程内构造的调用路径，不等价于普通应用通过 IPC 到达产品服务。Ethernet harness 也有本地 `Init`/`OnRemoteRequest` 包装。

## 对检测器和平台的建议

### 拆分两个构建归属事实

单一 `entry_build_membership` 名称容易混淆入口与候选锚点。建议后续向公共层提交契约申请，评估拆成：

- `entry_build_membership`：入口定义/驱动是否属于所选产品 target。本批 harness 有固定 GN 的 test-only 证据。
- `finding_source_product_membership`：候选锚点实现是否进入所选产品 target。本批服务源有组件内条件式共享库证据，但具体镜像仍 unknown。

每条都绑定 exact commit/tree/blob、BUILD 路径与 hash、target label、条件表达式、解析方法及未解决配置。缺完整产品图时只能记“组件内存在条件式产品 target”，不可写“该镜像已包含”。此项涉及公共义务模型，由集成人决定，IPC 线不改公共 contracts/runner/catalog。

### 暂不实现通用 GN 正则解析器

只用正则收集 `sources/deps` 会遗漏变量拼接、模板、import、条件和上游配置，产生虚假的精确感。近期先保留路径提示与 unknown 义务，对重点候选用固定提交逐目标复核；针对具体产品时使用完整源码和官方构建系统生成 target graph。多个组件证明同一类 GN 事实可稳定自动化后，再设计输出 `resolved / conditional / unknown` 的解析接口，并加入变量、模板、条件和 safe/fixed harness 正反控制。

## 状态

- **已验证**：组件 commit/tree；三个 fuzz target 的 harness、deps 与 test-only 声明；三份生产共享库的服务源列表；bundle service groups 与 feature-gated package groups；11 条候选的锚点/入口对应关系。
- **部分验证**：服务源同时被 test-only 静态库和组件正式共享库目标使用；组件 bundle 声明产品包 group。这证明组件仓库存在产品构建路径，不证明具体产品镜像已包含。
- **unknown**：具体产品是否启用这些 feature、服务库是否进入镜像、真实 IPC 入口的调用者/可达性、候选可利用性与影响；6 条 harness 锚点是否构成测试代码自身问题也未复核。它们不属于产品构建目标这一点已验证。
- **未执行**：没有完整 OpenHarmony checkout、产品 GN args、`gn gen/desc` 输出、镜像构建或运行时验证；没有改 detector 规则或变更 11 条候选判定。

## 重现

```bash
TARGET=/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/communication_netmanager_ext
COMMIT=8c35917b7e2f152813b13a20530a8452cf73d938

git -C "$TARGET" cat-file -t "$COMMIT"
git -C "$TARGET" rev-parse "$COMMIT^{tree}"
git -C "$TARGET" show "$COMMIT:test/networksharemanager/fuzztest/netshareclient_fuzzer/BUILD.gn"
git -C "$TARGET" show "$COMMIT:services/networksharemanager/BUILD.gn"
git -C "$TARGET" show "$COMMIT:BUILD.gn"
git -C "$TARGET" show "$COMMIT:bundle.json"
```

本次只读核查 GN/C++ 声明，没有运行 OpenHarmony 构建脚本，没有写入 G 盘仓库。
