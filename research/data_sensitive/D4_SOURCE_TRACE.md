# D4：真实请求到日志的源码证据链

## 结论

固定历史版本 `d33177135ec6c6aaf4a4c42de1f6878652b330e3` 中，源码证明 TCP Direct 发起端会生成会话密钥，把它加入请求 JSON 的 `SESSION_KEY` 字段，再以 `FLAG_REQUEST` 发送。接收端 `DecryptMessage` 把 `AuthDecrypt` 成功输出写到 `crypInfo.out`，随后解析 JSON 后，在调用 `ProcessMessage` 分流请求/回复之前，把整个解密 JSON 传给 `SoftBusLog`。发送前 `TransTdcPostBytes` 通过 `PackBytes` 调用 `AuthEncrypt`/`AuthEncryptBySeq` 生成包缓冲并把该缓冲交给 TCP 发送；接收端在 `AuthDecrypt` 成功、解析 JSON 后才记录，因此这里支持的是解密后日志暴露候选，不是网络明文泄露结论。请求经过该路径时日志参数可能含会话密钥；回复也会经过这条日志语句，但固定版本 `PackReply` 不构造 `SESSION_KEY` 字段。

这是源码机制证据，不能证明目标产品实际编译/启用此代码、目标设备采用相同 Secure-C 实现、日志记录最终写入并保留，或日志可被未授权主体读取，也不能证明运行时出现了具体泄露。此候选仍为条件研究结果。

## 逐跳核验

1. `trans_tcp_direct_listener.c:68-99`：`StartVerifySession` 调用 `SoftBusGenerateSessionKey`，随后 `PackRequest`；包头 flags 设置为 `FLAG_REQUEST | cipherFlag`，再由 `TransTdcPostBytes` 发送。`trans_tcp_direct_message.c:229-374`：`TransTdcPostBytes` 经 `PackBytes` 把 JSON 输入交给 Auth 加密 API 写入包缓冲，再发送包缓冲；因此静态证据显示线上传输受加密封装。发起路径由 `OnDataEvent` 的 socket out 分支在连接端调用。
2. `softbus_message_open_channel.c:52-98`：`PackRequest` 对 `appInfo->sessionKey` 做 Base64 编码，并将值作为 `SESSION_KEY` 字符串字段写入 JSON。`UnpackRequest` 从同名字段读取后 Base64 解码回 `appInfo->sessionKey`，并清零临时编码字符串；这将“JSON 中有该字段”与“字段被恢复为会话密钥”区分开来。新增离线源码断言分别核对了解码目标和临时缓冲清理。
3. `trans_tcp_direct_listener.c:206-239`、`trans_tcp_direct_message.c:722-740`：socket in 分支进入 `TransTdcSrvRecvData`，收齐数据后调用 `TransTdcSrvProcData` / `ProcessReceivedData`。
4. `trans_tcp_direct_message.c:628-677`：`ProcessReceivedData` 分配 `crypInfo.out`，调用 `DecryptMessage`；成功后 NUL 结束并解析 JSON。第 671 行把 `crypInfo.out` 作为 `%s` 参数交给 `SoftBusLog`。之后第 672 行才调用 `ProcessMessage`；`ProcessMessage` 在第 588 行用 `flags & FLAG_REPLY` 区分回复与请求。
5. `softbus_message_open_channel.c:147-181`：`PackReply` 不写 `SESSION_KEY` 字段。接收日志在类型分派之前，所以日志调用对两种消息都会执行；只有请求消息的内容被源码证明含此字段。
6. **组件构建图**也已按两个固定 commit 的真实构建文件追到服务目标：根 `BUILD.gn` 声明 `dsoftbus` 组件并列出 `core:softbus_server` feature；`core/BUILD.gn` 将该 feature 连接到 `frame:softbus_server_frame`；`core/frame/BUILD.gn` 的 `dsoftbus_server_common_src` 包含 `trans_session_src`，标准系统的 `ohos_shared_library("softbus_server")` 使用这组 common sources。`core/transmission/trans.gni` 把 `trans_channel_src` 赋给 `trans_session_src`；`trans_channel.gni` 导入 `tcp_direct.gni` 并把 `trans_direct_channel_src` 合并进 `trans_channel_src`；`tcp_direct.gni` 明确列出 `trans_tcp_direct_listener.c` 和 `trans_tcp_direct_message.c`。因此，仓库定义的标准 SoftBus 服务 target 构建图确实包含这两个文件。`adapter/BUILD.gn` 还定义标准 `softbus_adapter` target 并列入 `softbus_adapter_log.c`，与前述 HiLog 适配器实现相对应。
   以上只证明该历史仓库的组件/标准 target 构建图包含这些源码；没有 OpenHarmony 产品仓库的具体产品配置、构建参数、最终 target graph 或镜像产物，仍不能证明任何特定产品实际启用或打包了它们。对应的 9 个 BUILD/GNI 文件在两个 commit 的完整 recursive tree 中均逐路径核对，文件 SHA 和 Git blob 记录在 `D4_SOURCE_MANIFEST.json`，本地副本由离线校验器复核。
7. **源码级安全/同名无关对照**：在同一固定版 `trans_tcp_direct_message.c` 中，JSON 解析失败分支先释放输出缓冲，记录不含该缓冲的固定错误文案，再返回；`GetAuthSideFlag` 也调用同名 `SoftBusLog`，但参数只是 `flags`、`side`、`seq` 这类协议元数据，不含 `crypInfo.out` 或 `SESSION_KEY`。离线校验器以精确固定源码 blob 断言这两条事实，避免仅凭 sink 名称把同文件的所有日志都视为敏感流。它们证明源码有安全/无关对照路径，不证明这些分支经过动态执行。

## 日志格式化、等级与读取边界

8. 固定版本 `core/common/log/softbus_log.c` 定义 `LOG_PRINT_MAX_LEN=256`，在 256 字节栈缓冲中先写模块前缀，再调用 `vsprintf_s(&szStr[ulPos], sizeof(szStr)-ulPos, fmt, arg)`。本例模块名为 `TRAN`，前缀 `[TRAN]` 占 6 字节，因此传给格式化函数的 `destMax` 是 250 字节。SoftBus 标准 adapter target 的 `adapter/BUILD.gn` 还明确声明外部依赖 `//third_party/bounds_checking_function:libsec_static`。该依赖源码截至 DSoftBus 候选时期的最近可见版本为 `ebef58f44419d0694e984d25acac231e737d60ff`（2021-03-11）；其 [`securec.h`](https://github.com/openharmony/third_party_bounds_checking_function/blob/ebef58f44419d0694e984d25acac231e737d60ff/include/securec.h#L207-L218)（blob `23bac2c4d83fd6abbeb066da48d076020a44f160`）说明 `destMax` 包含结尾 NUL、成功返回不含 NUL 的字符数、错误返回 `-1`；[`vsprintf_s.c`](https://github.com/openharmony/third_party_bounds_checking_function/blob/ebef58f44419d0694e984d25acac231e737d60ff/src/vsprintf_s.c#L35-L64)（blob `012f522c4987d99a448a5f4b6a157a5d3a271e9f`）显示底层错误会清空首字节并返回 `-1`。按该实现，格式正文最多写 249 个字节；超长不是“截断后照常写出”：`SoftBusLog` 检查到负返回值后只写一条长度告警并立即返回，不调用 `SoftBusOutPrint`。仓库声明依赖不等于锁定产品最终链接的 Secure-C revision，因此边界行为仍须以目标构建依赖和运行结果确认。
9. 同文件从 `SOFTBUS_INT_ADAPTER_LOG_LEVEL` 读取阈值，并在 `level < g_logLevel` 时过滤。该历史版本的默认配置把 `ADAPTER_LOG_LEVEL` 设为 `0`，`SoftbusGetConfig` 将配置值复制给调用方；因此代码默认没有高于 0 的过滤阈值。产品适配层仍可能覆写该配置，目标设备的最终值未知。
10. 同版本 `adapter/common/log/softbus_adapter_log.c` 对 HiLog 分支以 `HILOG_ERROR(..., "%{public}s", buf)` 输出，`SOFTBUS_PRINTF` 构建则写 `printf`。这证明代码的输出标记/调用方式，不证明记录实际进入目标产品的日志缓冲或由谁获准读取。
11. HiLog 官方 README 描述用户态日志进入 hilogd ring buffer，`hilog` 命令从缓冲读取；官方开发文档说明默认不持久化，需要显式启用持久化任务，且以 `hdc shell hilog` / `hdc file recv` 作为开发者查看方式。它说明开发/调试链路存在，不构成普通应用或未授权用户可读的证据。读取 ACL、产品是否开启持久化、shell/hdc 的权限配置必须在目标产品单独核验。

## 同时期读取权限配置线索（非设备实测）

DSoftBus 固定候选 commit 是 2022-03-29；另核对了 OpenHarmony HiLog 的相邻日期 commit `45e229a0228a3dc2bb2f01eeb69b2d0ff33c4c31`（2022-03-28），作为当时期日志服务权限配置参考，不声称它与 DSoftBus 来自同一个产品构建快照。

- DSoftBus 的 `core/frame/BUILD.gn` 按 `use_musl` 选择 init 配置；非 musl 的 `softbus_server.cfg` 将服务 uid 设为 `system`、gid 设为 `system,shell`，musl 变体设为 uid `dsoftbus`、gid `dsoftbus,system,shell`。这证明该仓库提供的两种服务身份配置，不证明目标产品选用了哪一种。
- 同期 HiLog 的 [hilogd.cfg](https://github.com/openharmony/hiviewdfx_hilog/blob/45e229a0228a3dc2bb2f01eeb69b2d0ff33c4c31/services/hilogd/etc/hilogd.cfg#L24-L43)（Git blob `032464a48a69e144d0e51366c5347f0df13c2e9f`）将 `hilogControl` seqpacket socket 配成 `0600`、owner/group `logd:logd`；`hilogInput` 是另一个 `0666` socket。同期 [HiLog 命令行](https://github.com/openharmony/hiviewdfx_hilog/blob/45e229a0228a3dc2bb2f01eeb69b2d0ff33c4c31/services/hilogtool/main.cpp#L480-L489)（blob `85a6900b0eb73bd188bc5457c963045f9cbbfedf`）通过控制 socket 发请求，[共享头文件](https://github.com/openharmony/hiviewdfx_hilog/blob/45e229a0228a3dc2bb2f01eeb69b2d0ff33c4c31/frameworks/native/include/hilog_common.h#L25-L28)（blob `9b9158ed80513b3d39c6afd4e97ffe9e9d9c379b`）把其名称定义为 `hilogControl`；[服务端查询处理](https://github.com/openharmony/hiviewdfx_hilog/blob/45e229a0228a3dc2bb2f01eeb69b2d0ff33c4c31/services/hilogd/service_controller.cpp#L486-L505)（blob `f13be17310b0630d4152fe5a53a25e55ab843ec5`）从 hilog buffer 查询并返回日志。
- 因此，在这两份相邻日期配置同时适用、未被产品改写、且调用主体没有额外特权的条件下，普通应用既不是 `logd` owner，也不在 `logd` group，按 socket DAC 无法打开读取控制 socket；DSoftBus 配置的 `system`/`dsoftbus` 服务身份也不是 `logd`。这是较强的源码配置推论，不是普通应用 UID 的实机拒绝测试。Shell/hdc 的实际身份、授权能力、产品对 socket/HiLog 配置的变更，以及更晚版本是否增加其他读取接口，仍需目标产品验证。
- 本地环境没有该 2022 HiLog 源码 checkout，也没有目标产品镜像；这些 immutable GitHub 链接可复核，但不能等同于已在 D4 的 DSoftBus Git-object manifest 中验证，或证明目标产品 ACL。

## 历史对比

日志行出现在修改前的固定 commit `d33177135ec6c6aaf4a4c42de1f6878652b330e3` 的 `trans_tcp_direct_message.c:671`，而后续固定版本 `63efce3ff7f2708527eb29216decaf5fe2dc33d0` 已删除该整段输出。源码校验器还确认后续版本仍保留 `PackRequest` 写入 `SESSION_KEY`、`UnpackRequest` 将该字段 Base64 解码回 `appInfo->sessionKey` 的协议路径；因此版本差异是移除了接收侧明文日志语句，不是从请求协议中移除了会话密钥字段。两端文件 SHA-256、Git blob、tree 与来源 URL 记录在本目录 `D4_SOURCE_MANIFEST.json`。这说明历史上存在一次日志语句删除；它本身不是漏洞确认或修复有效性证明。

日志实现来源文件的 commit、tree、blob、SHA-256 与大小追加记录在 `D4_SOURCE_MANIFEST.json`。Secure-C 格式化契约参考[OpenHarmony Secure-C `securec.h`](https://github.com/OpenHarmony-mirror/third_party_bounds_checking_function/blob/master/include/securec.h)；HiLog 数据流参考[OpenHarmony HiLog README](https://github.com/openharmony/hiviewdfx_hilog/blob/master/README.md)与[HiLog 开发文档](https://github.com/openharmony/docs/blob/master/en/application-dev/dfx/hilog.md)。外部文档为核查时版本，未绑定到历史产品构建依赖；因此不能替代产品级版本与权限证据。

可用 `node research/data_sensitive/d4_verify_sources.js --git-dir <本地 communication_dsoftbus Git 对象库>` 离线复核 manifest 中的 Git tree、blob、文件 SHA-256、大小及关键代码事实。当前 Windows checkout 未保留上游 Git 对象库，因此通过只读 GitHub API 获取两个固定 commit 和完整 recursive tree 响应（各 1374 个条目，均未截断），将 44 个 commit/path/blob/size 映射记录在 `D4_SOURCE_API_VERIFICATION.json`，并把 23 个唯一 Git blob 原始字节缓存于本地 `outputs/d4-source-cache/`。缓存覆盖两个历史 profile 的全部 10 个 required_files，并包含构建链和两种 SoftBus 服务身份配置。`--source-cache` 模式在本机逐一核对 Git blob SHA-1、清单 SHA-256/大小、API 中 commit/tree/path 映射和 35 项关键代码、构建图及安全对照事实，全部通过。复核命令为 `node research/data_sensitive/d4_verify_sources.js --source-cache outputs/d4-source-cache`。这使缓存字节检查可离线重跑，但 API 记录不是签名 Git 对象库；需要完全独立的 Git 对象验证时，仍应提供对应上游 Git 对象库。缓存只在本地 outputs 中，不属于应提交的第三方源码。HiLog 权限线索则在上文以另一仓库的不可变 commit/文件 blob 直接引用；它不属于该 DSoftBus manifest，也不证明目标产品 ACL。

基于这套完整 profile 输入，`d4_replay_real_source.py` 实际调用研究型 Detector 对两个固定版本各 10 个源文件重放：旧版得到 1 个 `SoftBusLog` 候选，新版 0 个。两版各有 6 个文件解析为 partial，因此 Detector 总状态均为 `blocked`，结果是候选差异而非完整扫描；这不证明漏洞成立、被引入或已修复。逐次输出、文件覆盖和全部义务保存在 `D4_REAL_SOURCE_REPLAY.json`。

## 仍待补的运行态证据

- 锁定产品构建配置，证明组件、源文件、宏和日志适配器确实进入目标镜像。
- 在隔离、授权环境确认请求是否真实到达，锁定目标 Secure-C 实现并记录 `vsprintf_s` 返回值、日志等级、最终输出与持久化行为；静态源码表明超长输入按接口契约会被丢弃，不能再笼统称作“未知截断”。
- 用目标产品日志服务实现/设备策略证明日志读取者及其权限边界，验证普通应用与非授权 shell 是否能读到；HiLog 开发者的 `hdc` 读取能力不等同于应用权限。
- 按 D4 平台流程使用现有 Docker Worker；当前 WSL 未安装/暴露 Docker 命令，本轮没有运行动态 PoC。
