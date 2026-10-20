# T44 独立静态证据审计：Samgr callback IPC，CR-0214–CR-0218

- 独立验证 checkout：`codex/t44-samgr-callback-audit-20261027`，基线 `9ae0e9d40ddf5682282752f00b0dc2e6ed880153`。
- 源码：`openharmony/systemabilitymgr_samgr` commit `08e2a552b839ea7727251cb9b749a5c1dd9cfeff`，tree `b7a89e95be788f2f2372258e341f7be842c7826d`。
- 当前 CLI：`ohscanner.interface.ipc` 0.12.12 / model `oh-ipc-2026.10-v32`；4 个精确文件、92,495 字节，13 条候选。解析为 1 complete、3 partial；IPC 覆盖 1 complete、3 partial。三条本轮 callback 候选均来自 partial 文件，故仅是语法候选。
- 5/5 A0 源位置均有同位置当前候选。CR-0214–0216 是 `ipc.relay.descriptor-boundary`，CR-0217–0218 是既有 Samgr manager 文件同规则的 descriptor-boundary 候选；这些不能直接解释为缺少校验或可绕过边界。

| A0 | 文件:行 | 当前 CLI finding | 源码/分派证据 | 结论 |
|---|---|---|---|---|
| CR-0214 | `frameworks/native/source/system_ability_load_callback_stub.cpp:36` | `ohscanner.interface.ipc:65ca547870c4581d` | `OnRemoteRequest` 先调用 `EnforceInterceToken`，失败即 `ERR_PERMISSION_DENIED`，再按 4 个 load callback transaction code 分派。`OnLoadSystemAbilitySuccessInner` 验证 parcel 读取与 SA ID 范围，读取 `IRemoteObject` 并回调。`EnforceInterceToken` 比较 `ReadInterfaceToken()` 与 `GetDescriptor()`。 | 发现不是源码缺少 token 校验的证据；跨接口可达性未建立。 |
| CR-0215 | `frameworks/native/source/system_ability_status_change_stub.cpp:46` | `ohscanner.interface.ipc:4d18bc4caa73ac77` | 构造函数将 ADD/REMOVE 两个 code 注册到本 stub 的 handler；`OnRemoteRequest` 在 dispatch map 前执行 token 校验。handlers 检查 SA ID 范围，再调用 listener 的 add/remove 回调。 | descriptor 检查存在；调用者身份、listener 注册来源与外部可达性未知。 |
| CR-0216 | `frameworks/native/source/system_process_status_change_stub.cpp:43` | `ohscanner.interface.ipc:c39c845fef977fd6` | 构造函数注册 STARTED/STOPPED/ACTIVATED/IDLED 四个 handler；`OnRemoteRequest` 在 dispatch map 前校验 token。handlers 经 `ReadProcessInfo` 读取 name/pid/uid 后调用 listener。 | descriptor 检查存在；字段语义授权、注册来源和可达性未证明。 |
| CR-0217 | `services/samgr/native/source/system_ability_manager_stub.cpp:298` | `ohscanner.interface.ipc:b360d1d29c25e580` | manager dispatcher 检查 `SAMANAGER_INTERFACE_TOKEN`，随后按 `memberFuncMap_` 查找 transaction 并分派；见同文件 293–309 行及 T30 audit。 | protocol token 已见；候选不构成 relay 漏洞确认。 |
| CR-0218 | `services/samgr/native/source/system_ability_manager_stub.cpp:302` | `ohscanner.interface.ipc:6136103fc662c4a6` | 同一 manager dispatcher 对未知 transaction 转交基类；与 CR-0217 同文件、同一 partial CLI 结果。 | 未知 code 的基类行为、有效调用路径/影响仍需目标验证。 |

## 构建与测试归属

精确源码树的 `interfaces/innerkits/samgr_proxy/BUILD.gn` 将三个 callback stub `.cpp` 都编入 `ohos_shared_library("samgr_proxy")`。`services/samgr/native/BUILD.gn` 的可安装 `ohos_executable("samgr")` 还显式编入 load callback stub，并依赖 `samgr_proxy`。因此源文件存在生产构建目标证据，但本次没有绑定某一产品/设备实际选择的 profile、宏与产物。`services/samgr/native/test/unittest/BUILD.gn` 也在测试 targets 中编入相关源文件，且 `system_ability_mgr_stub_load_test.cpp`、`system_ability_mgr_subscribe_test.cpp` 存在 callback/listener 测试；本轮仅做静态审阅，没有编译或运行目标测试。

三类 callback stub 接收的是 listener/callback 的远程对象请求，不是 manager 的 caller-authorization 边界。Manager 经 `LoadSystemAbility`、`SubscribeSystemAbility` 等路径保存或触发 callback/listener，proxy 负责打包接口 token 与 parcel。需要产品配置、可信 callback 注册端、Binder/IPC peer 身份、跨设备和目标 SA policy、对 callback 数据的安全影响及代表性授权/未授权 IPC 测试，才能判断是否存在实际安全问题。无可信 fixed source/control pair；不作修复差分结论。

## 判定与状态

整体 `PARTIAL/BLOCK`。CLI 的 descriptor-boundary 候选与源码可见的 descriptor 校验形成需要继续核实的模型差异；可能是分析模型/解析 coverage 问题，不能记作已确认漏洞或安全通过。CR-0214–0218 五条 A0 原始状态保持 `not_testable / paused_pending_evidence`。没有改 detector、测试、fixtures、API 或 A0 队列。验证脚本：`python research/evidence/cpp/verify_t44_samgr_callback_audit_20261027.py`。
