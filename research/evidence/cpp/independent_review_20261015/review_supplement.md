# A 线 shared_ptr 独立复核技术补充

- 生成日期：2026-10-15
- 项目 checkout：`codex/full-runtime-performance-audit-20261014` / `0dd71fd78baa01283df081f9bd02fe4b7f2df326`
- `independent_review=false`：当前执行者参与过首轮复核流程且已接触汇总标签。
- 本文件不是最终真值签字，不升级 candidate/review/case/confirmed/reportable，不计算 Precision/Recall。
- 范围：11 条 `plausible_unproven`、34 条 holdout、共 45 个复核项、44 个唯一候选；流监听器候选同时属于两个集合。

## 技术结论

- 技术建议统计：{"safe": 1, "unknown": 13, "unrelated": 31}。
- 与首轮对照：{"consistent_non_vulnerability": 28, "consistent_refuted_scope": 3, "consistent_unresolved": 12, "disagreement_keep_unknown": 1, "disagreement_resolved_safe": 1}。
- 所有 `unknown` 仍需独立 reviewer 签字；所有 `unrelated` 只排除已观察到的 owner-race 形状，不证明组件安全。

## 根因组摘要

### RC-CONSTRUCTOR-NOISE

- 技术建议：`unrelated`；优先级：`normal`。
- 结论：The reported site is constructor/member initialization or a stable-owner read. Repository-wide exact symbol search did not show a later owner reassignment for the same object. This excludes the observed non-atomic shared_ptr owner write/read race shape, but does not prove pointee thread safety.
- 待补事实：Pointee internal thread safety and safe publication remain outside this owner-race disposition.
- 最小复现：Only needed if a later owner assignment or cross-thread pointee mutation is discovered.

### RC-JSPROXY

- 技术建议：`unknown`；优先级：`high`。
- 结论：JSProxy::instance_ has an unsynchronized SetInstance/GetInstance owner pair. The result-set lifecycle clears or replaces the owner while other operations call GetInstance, so NAPI queue serialization and safe publication are required before deciding whether the pair can overlap.
- 待补事实：NAPI execute/complete thread affinity and callback queue ordering for each JSProxy subtype.；Whether SetInstance(nullptr) can overlap a queued GetInstance operation.；Product entry, attacker control, and concrete CIA impact.
- 最小复现：Run concurrent SetInstance(nullptr) and GetInstance calls for a representative result-set wrapper under TSan, then repeat after serializing owner mutation through the actual NAPI queue.

### RC-PIP-CONTROLLERS

- 技术建议：`unknown`；优先级：`high`。
- 结论：PictureInPicture controller owner members have getter/setter or direct read/write pairs without a repository-local lock. Direct member accesses also occur from source-rect, reset, and ext-controller paths. Thread/event-runner affinity is not established.
- 待补事实：Whether setters run on the same event runner as source-rect/reset/extension-controller readers.；Feasible interleaving while a controller is shared between main and PIP windows.；Reachable product trigger and concrete CIA impact.
- 最小复现：Create two controller variants and race SetXComponentController/SetMainWindowXComponentController against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner.

### RC-REMOTE-CHANNEL

- 技术建议：`unknown`；优先级：`high`。
- 结论：RemoteCommandExecutor::ptrChannel_ has an unsynchronized setter/getter pair and is also written by CreateChannelIfNeeded and read while commands execute. The executor mutex covers only part of the owner accesses; concurrent device-online and command-processing paths remain a realistic race shape.
- 待补事实：Exact thread/event-runner ownership for NotifyDeviceOnline, GetExecutorChannel, and command execution.；A happens-before proof or a controlled race/fixed run for ptrChannel_ publication and reset.；Real product entry, privilege boundary, trigger, and CIA consequence.
- 最小复现：Build a narrow RemoteCommandExecutor harness that concurrently calls SetChannel/GetChannel and CreateChannelIfNeeded/ProcessOneCommand under TSan, then repeat with one owner mutex or atomic shared_ptr protocol.

### RC-SCOPE-MOCK

- 技术建议：`unrelated`；优先级：`normal`。
- 结论：The diagnostic is under kvstoremock/external_inner_kit, which is non-production mock/support source and was admitted by the historical scope path rule. It is not a production component vulnerability.
- 待补事实：No product fact is required to classify this specific item as out of production scope.
- 最小复现：No vulnerability PoC. Retain as an unrelated/scope-control item and exclude from production scoring.

### RC-STREAM-LISTENER

- 技术建议：`unknown`；优先级：`high`。
- 结论：StreamManager::streamListener_ is initialized in the constructor, read while creating client/server channels, and reassigned by SetStreamRecvListener without synchronization. The candidate constructor site is not itself a conflicting runtime access, but it participates in the same owner lifecycle.
- 待补事实：Whether channel creation and SetStreamRecvListener can execute concurrently on one StreamManager.；Publication ordering between streamListener_, socketListener_, and the socket callback.；Reachable trigger and CIA consequence in the product.
- 最小复现：Race SetStreamRecvListener with CreateStreamClientChannel/CreateStreamServerChannel in a controlled StreamManager harness under TSan, then repeat with a common mutex or immutable listener publication.

### RC-WINDOW-SINGLE

- 技术建议：`unrelated`；优先级：`normal`。
- 结论：Most reported accesses are constructor initialization or Marshalling reads paired with Unmarshalling writes to a newly allocated, distinct object. The lexical sites do not establish a same-object concurrent owner write/read pair.
- 待补事实：Pointee behavior and broader object lifecycle are not safety proof.
- 最小复现：Only needed if a same-object owner mutation path is found.

### RC-WINDOW-SINGLE override: `utils/include/ui_effect_controller_common.h`

- 技术建议：`unrelated`；优先级：`normal`。
- 结论：The reported IsEmpty() reads occur after ConvertFromJsValue initializes a newly created local UIEffectParams in the same NAPI flow. Parcel Unmarshalling also constructs a fresh object before publication. No same-object post-publication owner mutation pair was found, so these sites are unrelated to the observed shared_ptr owner race shape; this is not pointee safety proof.
- 待补事实：Pointee Filter/VisualEffect thread safety is outside this owner-race disposition.
- 最小复现：Only needed if a same UIEffectParams object is mutated after publication or concurrently parsed.

### RC-WINDOW-SINGLE override: `surface_capture_future.h::hdrPixelMap_`

- 技术建议：`unknown`；优先级：`high`。
- 结论：Most hdrPixelMap_ accesses are protected by mutex_, including GetHDRResult and the HDR/error callbacks. However OnSurfaceCapture assigns hdrPixelMap_ = nullptr before FutureCall() takes mutex_, so that write can overlap the locked GetHDRResult read after a timeout. The owner pair remains unresolved.
- 待补事实：Whether an OnSurfaceCapture callback can overlap a timed-out GetHDRResult caller in product paths.；Controlled TSan evidence for the out-of-lock hdrPixelMap_ reset.；Product trigger and CIA consequence.
- 最小复现：Race OnSurfaceCapture with GetHDRResult around timeout under TSan, then repeat after moving hdrPixelMap_ = nullptr inside the mutex.

### RC-WINDOW-SINGLE override: `surface_capture_future.h::pixelMap_`

- 技术建议：`safe`；优先级：`normal`。
- 结论：All observed pixelMap_ owner accesses are serialized by mutex_. OnSurfaceCaptureHDR and OnSurfaceCaptureWithErrorCode lock directly; OnSurfaceCapture writes through FutureCall(), and GetResult()/FetchResult() read while Future::GetResult holds the same mutex. This establishes synchronization for the non-atomic shared_ptr owner access set, not pointee safety.
- 待补事实：Pointee PixelMap thread safety and product-level CIA impact are outside this owner-race disposition.
- 最小复现：Keep as a safe synchronization control and verify that concurrent callback/GetResult runs remain clean under TSan.

## 逐项对照

| Scope | Candidate | Component | Location | Symbol | First round | Technical suggestion | Comparison |
|---|---|---|---|---|---|---|---|
| plausible_unproven | `0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b` | security_access_token | `services/tokensyncmanager/include/remote/remote_command_executor.h:37:16` | `ptrChannel_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b` | security_access_token | `services/tokensyncmanager/include/remote/remote_command_executor.h:41:9` | `ptrChannel_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef` | distributeddatamgr_kv_store | `frameworks/common/js_proxy.h:37:9` | `instance_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c` | distributeddatamgr_kv_store | `frameworks/common/js_proxy.h:42:16` | `instance_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `c722752a78ed08cfb6cc59dd310836450dae9cfa7a26e6f417e84591aaf9c3d8` | window_window_manager | `wm/include/picture_in_picture_controller.h:50:16` | `mainWindowXComponentController_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `91a26bea4359381a25147a29a0d7e4e7d03ff4e6c92f79138b379d98ca095d0d` | window_window_manager | `wm/include/picture_in_picture_controller.h:54:9` | `mainWindowXComponentController_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `0ebba8620c4dd9cf41d5da993d590ba788befdeb941fbfca7d1aa148e3b9bf81` | window_window_manager | `wm/include/picture_in_picture_controller_ani.h:53:16` | `mainWindowXComponentController_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `610820828f23db15834dde0632174496f43cf3de75f048e3936d217363e27a7c` | window_window_manager | `wm/include/picture_in_picture_controller_ani.h:57:9` | `mainWindowXComponentController_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `6334c63528ae670fc6f7d17947c9275aa46a4a44e562a3285e0595b1ca9b6652` | window_window_manager | `wm/include/picture_in_picture_controller_base.h:141:16` | `pipXComponentController_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `951e6357190d927ffab7a4d1970a623403d3879e6d735343ef99afa480aa04af` | window_window_manager | `wm/include/picture_in_picture_controller_base.h:145:9` | `pipXComponentController_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| plausible_unproven | `1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7` | communication_dsoftbus | `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67:86` | `streamListener_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |
| holdout | `2c7fb8c5e56f8f2488762f1c65dec2f8a2c3cd9fb6f743df83c9e99c4687d679` | update_updateservice | `services/core/ability/status_cache/include/status_cache.h:27:67` | `timeUtilsProxy_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6` | security_access_token | `interfaces/kits/cj/accesstoken/include/at_manager_impl.h:115:86` | `data_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30` | security_access_token | `interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h:51:9` | `asyncContextPtr` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116` | security_access_token | `interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h:49:9` | `asyncContextPtr` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710` | security_access_token | `interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h:61:9` | `asyncContextPtr` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122` | security_access_token | `interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h:68:9` | `asyncContextPtr` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc` | security_access_token | `interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:72:9` | `asyncContextPtr` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4` | security_access_token | `interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:117:71` | `data_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495` | security_access_token | `interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h:63:9` | `asyncContextPtr` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427` | distributeddatamgr_kv_store | `kvstoremock/external_inner_kit/napi/include/extension_context.h:61:16` | `abilityInfo_` | `refuted` | `unrelated` | `consistent_refuted_scope` |
| holdout | `de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5` | distributeddatamgr_kv_store | `kvstoremock/external_inner_kit/napi/include/extension_context.h:65:9` | `abilityInfo_` | `refuted` | `unrelated` | `consistent_refuted_scope` |
| holdout | `a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d` | distributeddatamgr_kv_store | `kvstoremock/external_inner_kit/napi/include/extension_context.h:81:16` | `abilityInfo_` | `refuted` | `unrelated` | `consistent_refuted_scope` |
| holdout | `3f33ecdd5899ae2cbbff6aae95eeef494c583c294112752e69c72f3ab569dbba` | window_window_manager | `interfaces/innerkits/wm/wm_animation_common.h:220:37` | `animationConfig` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `98a2ac1ba0b1d0501fe6fc17e979d887a2623f843221e9582259eac902cc7e1a` | window_window_manager | `interfaces/innerkits/wm/wm_animation_common.h:261:37` | `animationParams` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `96d94fd92a003251ec386f66069c5a52f4bd88f63a0ff30d0679456ae6a3ce84` | window_window_manager | `interfaces/innerkits/wm/wm_animation_common.h:265:37` | `animationSystemParams` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `ead5f473d62f6d21712f7eb0ae59bc743f1d7222f5fba437120c4508668ea785` | window_window_manager | `interfaces/innerkits/wm/wm_animation_common.h:273:52` | `needAnimation` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `f6f50c28e7e1dd49302cecc20d4ecbd713d0e5e7f97d0e813bf3aa6c49e633f9` | window_window_manager | `interfaces/innerkits/wm/wm_animation_common.h:289:54` | `excludeFromDock` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `48ff783415251c95ed5e93eabe1817f941d11c8f4727222408d25a6480416e20` | window_window_manager | `interfaces/innerkits/wm/wm_animation_common.h:297:56` | `excludeFromRecent` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `a786eb0afcb5cd995219af27c26d2770b3d5e9560a394868769adfdbb3c03fee` | window_window_manager | `interfaces/kits/napi/float_view_napi/js_float_view_listener.h:32:22` | `jsCallBack_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `228aa372f6f5454101891f359b3bedcad2cc55d90afbd43d9c50f8de35f27598` | window_window_manager | `interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h:33:22` | `jsCallBack_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `385d0407467c117c1bc471deaee058fa95493080dc74d75d3b12833bac0a3eff` | window_window_manager | `interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h:32:22` | `jsCallBack_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `4e9afc5ec4b9b2c8418de2868780ce9c410e056cda6a5a76c803ad5216b75701` | window_window_manager | `previewer/include/wm_animation_common.h:214:37` | `animationConfig` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `fc90aa9eaa7a862404445c7a7b340636035341caf97d661223a49f930f6bc5d3` | window_window_manager | `previewer/include/wm_animation_common.h:253:37` | `animationParams` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `8ab1907289a43e543ac716c3db76d8db1e06a9990741d1ecbdee109caf7f739e` | window_window_manager | `previewer/include/wm_animation_common.h:257:37` | `animationSystemParams` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `3f69ba23ee35ab8b695eb5b3019703343504bae60835da22335e2ab165116dde` | window_window_manager | `previewer/include/wm_animation_common.h:265:52` | `needAnimation` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `0c3d001e4abbb837b5b164bade7dfca901342fca31a94ec355667827f2376e4c` | window_window_manager | `previewer/include/wm_animation_common.h:281:54` | `excludeFromDock` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `1e0688494c36112e34cd1f27f9c35be050c26bb3ffec36ed41e8b0de1cb9fa00` | window_window_manager | `previewer/include/wm_animation_common.h:289:56` | `excludeFromRecent` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `df1d89f286c9727a550f92b5c451d9126cd66adeb96a10be52415868b6fe2eb1` | window_window_manager | `utils/include/surface_capture_future.h:73:29` | `hdrPixelMap_` | `likely_false_positive` | `unknown` | `disagreement_keep_unknown` |
| holdout | `91a5f46b96a11a6166bccc207946d7524912938daf1cb7058fd89d79cd8ce881` | window_window_manager | `utils/include/surface_capture_future.h:73:18` | `pixelMap_` | `likely_false_positive` | `safe` | `disagreement_resolved_safe` |
| holdout | `a652b1b68097421147c0051e3c8f75cd993e286907958c8c40bec5a8a4c8056a` | window_window_manager | `utils/include/ui_effect_controller_common.h:53:16` | `backgroundFilter_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `869e521a61c57900b90bc59f13ce6c298aa86da99f03996db8340bfccc09ebe9` | window_window_manager | `utils/include/ui_effect_controller_common.h:53:48` | `effect_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `a3080f2b2c90a12166ec6d4ad76a3c7886033b47e9356f124a74c00fb1426a80` | window_window_manager | `wmserver/include/drag_controller.h:68:9` | `vsyncCallback_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `4e5f35efb3f6c9480e5016776b81acd7e82b5fd3aacbd5aa211c0ed7dda3dc2d` | window_window_manager | `wmserver/include/window_common_event.h:41:64` | `eventHandler_` | `likely_false_positive` | `unrelated` | `consistent_non_vulnerability` |
| holdout | `1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7` | communication_dsoftbus | `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67:86` | `streamListener_` | `plausible_unproven` | `unknown` | `consistent_unresolved` |

## 独立签字门槛

- 另一位未参与首轮候选分诊的 reviewer 先盲审，再与本表和首轮记录对照。
- 对每项选择 `vulnerable/fixed/safe/unrelated/unknown`，引用固定 commit/blob/source hash。
- `vulnerable` 必须补齐真实入口/权限、触发、可达敏感操作、CIA 影响和可审计并发证据。
- 未满足门槛的项目保持 `unknown`，不得计算 Precision/Recall。
