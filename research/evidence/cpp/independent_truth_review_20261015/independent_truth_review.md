# A 线 shared_ptr 独立真值复核追加记录

更新：2026-10-15（中国标准时间）。本文件是新追加记录，不覆盖 review ledger、历史 review 或既有证据。

## 范围与结论边界

- 追加 review item：45；plausible_unproven：11；holdout：34；独立根因/文件/symbol/source-hash 分组：37。
- 真值标签：`vulnerable=0`、`fixed=0`、`safe=1`、`unrelated=31`、`unknown=13`。
- `RC-JSPROXY` 的组件级 owner-race 机制为 controlled `vulnerable`，但产品级安全真值仍为 `unknown`：入口部署、权限/攻击者边界和 CIA 尚未闭合。
- 不计算 Precision/Recall，不输出零误报/零漏报结论；`eligible_for_metrics=false`。

## 分组

| root cause | file | symbol | source SHA-256 | items | labels |
|---|---|---|---|---:|---|
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/cj/accesstoken/include/at_manager_impl.h` | `data_` | `287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h` | `asyncContextPtr` | `1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h` | `asyncContextPtr` | `a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h` | `asyncContextPtr` | `01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h` | `asyncContextPtr` | `96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h` | `asyncContextPtr` | `ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h` | `data_` | `ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h` | `asyncContextPtr` | `c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560` | 1 | unrelated=1 |
| `RC-CONSTRUCTOR-NOISE` | `services/core/ability/status_cache/include/status_cache.h` | `timeUtilsProxy_` | `cd9dbbd3a2e16405198c2e6bc63f8178d4c45106b5d8a31a00f713d0f66bc6d9` | 1 | unrelated=1 |
| `RC-JSPROXY` | `frameworks/common/js_proxy.h` | `instance_` | `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f` | 2 | unknown=2 |
| `RC-PIP-CONTROLLERS` | `wm/include/picture_in_picture_controller.h` | `mainWindowXComponentController_` | `5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c` | 2 | unknown=2 |
| `RC-PIP-CONTROLLERS` | `wm/include/picture_in_picture_controller_ani.h` | `mainWindowXComponentController_` | `c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a` | 2 | unknown=2 |
| `RC-PIP-CONTROLLERS` | `wm/include/picture_in_picture_controller_base.h` | `pipXComponentController_` | `a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418` | 2 | unknown=2 |
| `RC-REMOTE-CHANNEL` | `services/tokensyncmanager/include/remote/remote_command_executor.h` | `ptrChannel_` | `2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7` | 2 | unknown=2 |
| `RC-SCOPE-MOCK` | `kvstoremock/external_inner_kit/napi/include/extension_context.h` | `abilityInfo_` | `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458` | 3 | unrelated=3 |
| `RC-STREAM-LISTENER` | `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h` | `streamListener_` | `66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100` | 2 | unknown=2 |
| `RC-WINDOW-SINGLE` | `interfaces/innerkits/wm/wm_animation_common.h` | `animationConfig` | `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/innerkits/wm/wm_animation_common.h` | `animationParams` | `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/innerkits/wm/wm_animation_common.h` | `animationSystemParams` | `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/innerkits/wm/wm_animation_common.h` | `excludeFromDock` | `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/innerkits/wm/wm_animation_common.h` | `excludeFromRecent` | `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/innerkits/wm/wm_animation_common.h` | `needAnimation` | `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/kits/napi/float_view_napi/js_float_view_listener.h` | `jsCallBack_` | `fe3710593c477a3c4e450eee87e8ab89267a0312738bacece7f34686d7fa2e1b` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h` | `jsCallBack_` | `b2de64e2e5bb197f96b1d7693dbe7aca4c5966cd31c9133b17f412c3615a40bc` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h` | `jsCallBack_` | `20706185efad40245b844eb5b1397da2de26a1f42b5d6dc4719ea5520f300348` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `previewer/include/wm_animation_common.h` | `animationConfig` | `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `previewer/include/wm_animation_common.h` | `animationParams` | `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `previewer/include/wm_animation_common.h` | `animationSystemParams` | `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `previewer/include/wm_animation_common.h` | `excludeFromDock` | `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `previewer/include/wm_animation_common.h` | `excludeFromRecent` | `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `previewer/include/wm_animation_common.h` | `needAnimation` | `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `utils/include/surface_capture_future.h` | `hdrPixelMap_` | `6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7` | 1 | unknown=1 |
| `RC-WINDOW-SINGLE` | `utils/include/surface_capture_future.h` | `pixelMap_` | `6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7` | 1 | safe=1 |
| `RC-WINDOW-SINGLE` | `utils/include/ui_effect_controller_common.h` | `backgroundFilter_` | `1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `utils/include/ui_effect_controller_common.h` | `effect_` | `1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `wmserver/include/drag_controller.h` | `vsyncCallback_` | `9e59f4470eb1d59efaa1b12643d579b4f5315dc69a61250fbf3a05823f2efa23` | 1 | unrelated=1 |
| `RC-WINDOW-SINGLE` | `wmserver/include/window_common_event.h` | `eventHandler_` | `2ff4b5f81e9305bb595477281b49ff744d516c90ac962e4c0baf8f34416eb9af` | 1 | unrelated=1 |

## 逐条记录

### 01. `plausible_unproven` `RC-REMOTE-CHANNEL` `services/tokensyncmanager/include/remote/remote_command_executor.h:37` `ptrChannel_`

- candidate `0017e7042647b7ec0b39b9fc086697a7d66cd696d0dd334c05b7ca174222b77b`；diagnostic `ohscanner.cpp.shared_ptr_race:9206921efb49a379`；group key `RC-REMOTE-CHANNEL|services/tokensyncmanager/include/remote/remote_command_executor.h|ptrChannel_|2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `f5f6974f1d47ed2456af573b62e975e28e499276` source SHA-256 `2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：Send command work is posted to TokenSyncManagerService::GetSendEventHandler() on an FFRT EventRunner; device online/offline enters through SoftBus device callbacks and socket session callbacks. Exact callback thread identities and common serialization are not proven.
- 发布顺序：GetOrCreateRemoteCommandExecutor publishes the executor; NotifyDeviceOnline checks GetChannel and calls SetChannel under RemoteCommandManager::mutex_. CreateChannelIfNeeded writes ptrChannel_ under RemoteCommandExecutor::recursive_mutex_; ProcessOneCommand/ExecuteRemoteCommand read it. Different locks leave no proven happens-before edge.
- 共享对象生命周期：Manager map owns the executor. The posted runner captures weak_from_this and locks self while processing. Offline releases the channel and removes the map entry; GetExecutorChannel returns a channel shared_ptr by value. Channel retention is visible, but ptrChannel_ publication/reset order is unresolved.
- 触发窗口：Device-online channel creation versus send-runner processing or socket callback use, with offline release/remove as a third event. Feasible product schedule and rate are not established.
- 同步协议：Manager mutex covers map and manager wrapper; executor mutex covers buffering/CreateChannelIfNeeded. Public Get/SetChannel and several reads/writes are not covered by one lock. Protocol incomplete.
- 判定理由：Partial synchronization and incomplete reachability/impact evidence; retain unknown.
- 无法独立证明：exact thread/event-runner ownership; happens-before or controlled ptrChannel_ race/fixed run; product trigger and CIA impact
- 证据引用：unable_to_determine=source

### 02. `plausible_unproven` `RC-REMOTE-CHANNEL` `services/tokensyncmanager/include/remote/remote_command_executor.h:41` `ptrChannel_`

- candidate `5d677d300a9ffdbe76a0ad582decd272f11d78557c140950dd03f346b830bb6b`；diagnostic `ohscanner.cpp.shared_ptr_race:3bac2f99cba097b8`；group key `RC-REMOTE-CHANNEL|services/tokensyncmanager/include/remote/remote_command_executor.h|ptrChannel_|2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `f5f6974f1d47ed2456af573b62e975e28e499276` source SHA-256 `2124970c2fc77f6e1a71eeb4c567ec00eb72c2a7d3ea8dcc07cd85a7458025e7`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：Send command work is posted to TokenSyncManagerService::GetSendEventHandler() on an FFRT EventRunner; device online/offline enters through SoftBus device callbacks and socket session callbacks. Exact callback thread identities and common serialization are not proven.
- 发布顺序：GetOrCreateRemoteCommandExecutor publishes the executor; NotifyDeviceOnline checks GetChannel and calls SetChannel under RemoteCommandManager::mutex_. CreateChannelIfNeeded writes ptrChannel_ under RemoteCommandExecutor::recursive_mutex_; ProcessOneCommand/ExecuteRemoteCommand read it. Different locks leave no proven happens-before edge.
- 共享对象生命周期：Manager map owns the executor. The posted runner captures weak_from_this and locks self while processing. Offline releases the channel and removes the map entry; GetExecutorChannel returns a channel shared_ptr by value. Channel retention is visible, but ptrChannel_ publication/reset order is unresolved.
- 触发窗口：Device-online channel creation versus send-runner processing or socket callback use, with offline release/remove as a third event. Feasible product schedule and rate are not established.
- 同步协议：Manager mutex covers map and manager wrapper; executor mutex covers buffering/CreateChannelIfNeeded. Public Get/SetChannel and several reads/writes are not covered by one lock. Protocol incomplete.
- 判定理由：Partial synchronization and incomplete reachability/impact evidence; retain unknown.
- 无法独立证明：exact thread/event-runner ownership; happens-before or controlled ptrChannel_ race/fixed run; product trigger and CIA impact
- 证据引用：unable_to_determine=source

### 03. `plausible_unproven` `RC-JSPROXY` `frameworks/common/js_proxy.h:37` `instance_`

- candidate `7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef`；diagnostic `ohscanner.cpp.shared_ptr_race:fdd6e227d2ca661e`；group key `RC-JSPROXY|frameworks/common/js_proxy.h|instance_|38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`
- source `openharmony/distributeddatamgr_kv_store` commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` tree `3b92c53fde616d5a3f9487b0c295670a42c63023` blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` source SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `vulnerable`；证据处置 `positive_control`；证据完整度 `partial`
- 线程/事件队列：Sync ResultSet methods use GetCbInfoSync on the NAPI/JS call context. GetResultSet/CloseResultSet use NapiQueue::AsyncWork: execute runs on the NAPI worker pool and complete on the JS/NAPI queue. The same JSProxy owner can be read by a sync call while async CloseResultSet clears it.
- 发布顺序：GetResultSet execute calls SetInstance; completion returns the wrapper. Sync methods copy GetInstance. CloseResultSet execute calls GetInstance then SetInstance(nullptr). Completion serialization does not order execute against a later sync JS call.
- 共享对象生命周期：napi_wrap owns the JS wrapper until finalize; async ContextBase keeps selfRef. GetInstance copies retain the pointee while SetInstance(nullptr) drops the wrapper owner. Owner control-block and pointee lifetime cross JS/worker contexts.
- 触发窗口：Source-visible sequence getResultSet -> closeResultSet -> immediate getEntry/getCount before async close execute completes. The controlled Harness models this exact overlap.
- 同步协议：No mutex/atomic owner API in JSProxy. NapiQueue serializes completion only. Fixed control uses a mutex; proposed minimal patch uses atomic_load/atomic_store.
- 判定理由：Real owner pair but unresolved queue, trigger, entry/privilege and CIA facts; retain unknown.
- 无法独立证明：product build/deployment identity; runtime permission and attacker-control boundary; measured product CIA and stable exploitability
- 证据引用：positive_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; fixed_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; safe_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; unrelated_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; patch=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/patch.diff

### 04. `plausible_unproven` `RC-JSPROXY` `frameworks/common/js_proxy.h:42` `instance_`

- candidate `844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c`；diagnostic `ohscanner.cpp.shared_ptr_race:cf558619929424b7`；group key `RC-JSPROXY|frameworks/common/js_proxy.h|instance_|38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`
- source `openharmony/distributeddatamgr_kv_store` commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` tree `3b92c53fde616d5a3f9487b0c295670a42c63023` blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` source SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `vulnerable`；证据处置 `positive_control`；证据完整度 `partial`
- 线程/事件队列：Sync ResultSet methods use GetCbInfoSync on the NAPI/JS call context. GetResultSet/CloseResultSet use NapiQueue::AsyncWork: execute runs on the NAPI worker pool and complete on the JS/NAPI queue. The same JSProxy owner can be read by a sync call while async CloseResultSet clears it.
- 发布顺序：GetResultSet execute calls SetInstance; completion returns the wrapper. Sync methods copy GetInstance. CloseResultSet execute calls GetInstance then SetInstance(nullptr). Completion serialization does not order execute against a later sync JS call.
- 共享对象生命周期：napi_wrap owns the JS wrapper until finalize; async ContextBase keeps selfRef. GetInstance copies retain the pointee while SetInstance(nullptr) drops the wrapper owner. Owner control-block and pointee lifetime cross JS/worker contexts.
- 触发窗口：Source-visible sequence getResultSet -> closeResultSet -> immediate getEntry/getCount before async close execute completes. The controlled Harness models this exact overlap.
- 同步协议：No mutex/atomic owner API in JSProxy. NapiQueue serializes completion only. Fixed control uses a mutex; proposed minimal patch uses atomic_load/atomic_store.
- 判定理由：Real owner pair but unresolved queue, trigger, entry/privilege and CIA facts; retain unknown.
- 无法独立证明：product build/deployment identity; runtime permission and attacker-control boundary; measured product CIA and stable exploitability
- 证据引用：positive_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; fixed_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; safe_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; unrelated_control=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json; patch=outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/patch.diff

### 05. `plausible_unproven` `RC-PIP-CONTROLLERS` `wm/include/picture_in_picture_controller.h:50` `mainWindowXComponentController_`

- candidate `c722752a78ed08cfb6cc59dd310836450dae9cfa7a26e6f417e84591aaf9c3d8`；diagnostic `ohscanner.cpp.shared_ptr_race:120564aa8b3e5e0e`；group key `RC-PIP-CONTROLLERS|wm/include/picture_in_picture_controller.h|mainWindowXComponentController_|5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `02928bb18057a2485b0dfbbb83e21c88ebd7f1d8` source SHA-256 `5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：NAPI/ANI PIP methods and window lifecycle/source-rect/reset callbacks are visible, but all setter/reader paths are not bound to one event runner or proven serial queue; main and PIP controller paths may differ.
- 发布顺序：Start copies main XComponentController from PipOption; reuse can replace it. SetXComponentController writes pipXComponentController_ and attaches it; ResetExtController detaches on stop. Source-rect/reset readers use the same members.
- 共享对象生命周期：PIP/window manager and PipOption share controller shared_ptrs. Reset tears down attachment but does not establish synchronized owner publication/destruction for all fields.
- 触发窗口：Concurrent Start/Update/Stop/SetX while main and PIP windows share a controller. No controlled product interleaving or runner trace.
- 同步协议：No local lock/atomic owner API covers both controller members and observed access paths. Same-runner serialization is possible but unproven.
- 判定理由：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 无法独立证明：same event-runner or queue serialization; feasible main/PIP shared-controller interleaving; reachable trigger and CIA impact
- 证据引用：unable_to_determine=source

### 06. `plausible_unproven` `RC-PIP-CONTROLLERS` `wm/include/picture_in_picture_controller.h:54` `mainWindowXComponentController_`

- candidate `91a26bea4359381a25147a29a0d7e4e7d03ff4e6c92f79138b379d98ca095d0d`；diagnostic `ohscanner.cpp.shared_ptr_race:dbb5f947830c529b`；group key `RC-PIP-CONTROLLERS|wm/include/picture_in_picture_controller.h|mainWindowXComponentController_|5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `02928bb18057a2485b0dfbbb83e21c88ebd7f1d8` source SHA-256 `5185852d3a0b6be8ac178984036863571abf1400c0f83089e29bcf10b3fa9c8c`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：NAPI/ANI PIP methods and window lifecycle/source-rect/reset callbacks are visible, but all setter/reader paths are not bound to one event runner or proven serial queue; main and PIP controller paths may differ.
- 发布顺序：Start copies main XComponentController from PipOption; reuse can replace it. SetXComponentController writes pipXComponentController_ and attaches it; ResetExtController detaches on stop. Source-rect/reset readers use the same members.
- 共享对象生命周期：PIP/window manager and PipOption share controller shared_ptrs. Reset tears down attachment but does not establish synchronized owner publication/destruction for all fields.
- 触发窗口：Concurrent Start/Update/Stop/SetX while main and PIP windows share a controller. No controlled product interleaving or runner trace.
- 同步协议：No local lock/atomic owner API covers both controller members and observed access paths. Same-runner serialization is possible but unproven.
- 判定理由：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 无法独立证明：same event-runner or queue serialization; feasible main/PIP shared-controller interleaving; reachable trigger and CIA impact
- 证据引用：unable_to_determine=source

### 07. `plausible_unproven` `RC-PIP-CONTROLLERS` `wm/include/picture_in_picture_controller_ani.h:53` `mainWindowXComponentController_`

- candidate `0ebba8620c4dd9cf41d5da993d590ba788befdeb941fbfca7d1aa148e3b9bf81`；diagnostic `ohscanner.cpp.shared_ptr_race:3b7de515ce92c047`；group key `RC-PIP-CONTROLLERS|wm/include/picture_in_picture_controller_ani.h|mainWindowXComponentController_|c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `d1a7f737dd18fe251713ae814bf8d817aaf96e58` source SHA-256 `c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：NAPI/ANI PIP methods and window lifecycle/source-rect/reset callbacks are visible, but all setter/reader paths are not bound to one event runner or proven serial queue; main and PIP controller paths may differ.
- 发布顺序：Start copies main XComponentController from PipOption; reuse can replace it. SetXComponentController writes pipXComponentController_ and attaches it; ResetExtController detaches on stop. Source-rect/reset readers use the same members.
- 共享对象生命周期：PIP/window manager and PipOption share controller shared_ptrs. Reset tears down attachment but does not establish synchronized owner publication/destruction for all fields.
- 触发窗口：Concurrent Start/Update/Stop/SetX while main and PIP windows share a controller. No controlled product interleaving or runner trace.
- 同步协议：No local lock/atomic owner API covers both controller members and observed access paths. Same-runner serialization is possible but unproven.
- 判定理由：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 无法独立证明：same event-runner or queue serialization; feasible main/PIP shared-controller interleaving; reachable trigger and CIA impact
- 证据引用：unable_to_determine=source

### 08. `plausible_unproven` `RC-PIP-CONTROLLERS` `wm/include/picture_in_picture_controller_ani.h:57` `mainWindowXComponentController_`

- candidate `610820828f23db15834dde0632174496f43cf3de75f048e3936d217363e27a7c`；diagnostic `ohscanner.cpp.shared_ptr_race:8aa8bf0d35097509`；group key `RC-PIP-CONTROLLERS|wm/include/picture_in_picture_controller_ani.h|mainWindowXComponentController_|c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `d1a7f737dd18fe251713ae814bf8d817aaf96e58` source SHA-256 `c2b49eea47ec9bc2fb3927e59f9629d5b944cd3fbb2ac360534171fe8138227a`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：NAPI/ANI PIP methods and window lifecycle/source-rect/reset callbacks are visible, but all setter/reader paths are not bound to one event runner or proven serial queue; main and PIP controller paths may differ.
- 发布顺序：Start copies main XComponentController from PipOption; reuse can replace it. SetXComponentController writes pipXComponentController_ and attaches it; ResetExtController detaches on stop. Source-rect/reset readers use the same members.
- 共享对象生命周期：PIP/window manager and PipOption share controller shared_ptrs. Reset tears down attachment but does not establish synchronized owner publication/destruction for all fields.
- 触发窗口：Concurrent Start/Update/Stop/SetX while main and PIP windows share a controller. No controlled product interleaving or runner trace.
- 同步协议：No local lock/atomic owner API covers both controller members and observed access paths. Same-runner serialization is possible but unproven.
- 判定理由：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 无法独立证明：same event-runner or queue serialization; feasible main/PIP shared-controller interleaving; reachable trigger and CIA impact
- 证据引用：unable_to_determine=source

### 09. `plausible_unproven` `RC-PIP-CONTROLLERS` `wm/include/picture_in_picture_controller_base.h:141` `pipXComponentController_`

- candidate `6334c63528ae670fc6f7d17947c9275aa46a4a44e562a3285e0595b1ca9b6652`；diagnostic `ohscanner.cpp.shared_ptr_race:182861cbf5065462`；group key `RC-PIP-CONTROLLERS|wm/include/picture_in_picture_controller_base.h|pipXComponentController_|a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `c634385cff8c3b0f2704ec5d92e278c3c8057d7a` source SHA-256 `a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：NAPI/ANI PIP methods and window lifecycle/source-rect/reset callbacks are visible, but all setter/reader paths are not bound to one event runner or proven serial queue; main and PIP controller paths may differ.
- 发布顺序：Start copies main XComponentController from PipOption; reuse can replace it. SetXComponentController writes pipXComponentController_ and attaches it; ResetExtController detaches on stop. Source-rect/reset readers use the same members.
- 共享对象生命周期：PIP/window manager and PipOption share controller shared_ptrs. Reset tears down attachment but does not establish synchronized owner publication/destruction for all fields.
- 触发窗口：Concurrent Start/Update/Stop/SetX while main and PIP windows share a controller. No controlled product interleaving or runner trace.
- 同步协议：No local lock/atomic owner API covers both controller members and observed access paths. Same-runner serialization is possible but unproven.
- 判定理由：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 无法独立证明：same event-runner or queue serialization; feasible main/PIP shared-controller interleaving; reachable trigger and CIA impact
- 证据引用：unable_to_determine=source

### 10. `plausible_unproven` `RC-PIP-CONTROLLERS` `wm/include/picture_in_picture_controller_base.h:145` `pipXComponentController_`

- candidate `951e6357190d927ffab7a4d1970a623403d3879e6d735343ef99afa480aa04af`；diagnostic `ohscanner.cpp.shared_ptr_race:a9e99a7e0a6f4146`；group key `RC-PIP-CONTROLLERS|wm/include/picture_in_picture_controller_base.h|pipXComponentController_|a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `c634385cff8c3b0f2704ec5d92e278c3c8057d7a` source SHA-256 `a0f47a883e30c7abffbf1fb49bb5f61251869b920b1aefd9a7086cae67327418`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：NAPI/ANI PIP methods and window lifecycle/source-rect/reset callbacks are visible, but all setter/reader paths are not bound to one event runner or proven serial queue; main and PIP controller paths may differ.
- 发布顺序：Start copies main XComponentController from PipOption; reuse can replace it. SetXComponentController writes pipXComponentController_ and attaches it; ResetExtController detaches on stop. Source-rect/reset readers use the same members.
- 共享对象生命周期：PIP/window manager and PipOption share controller shared_ptrs. Reset tears down attachment but does not establish synchronized owner publication/destruction for all fields.
- 触发窗口：Concurrent Start/Update/Stop/SetX while main and PIP windows share a controller. No controlled product interleaving or runner trace.
- 同步协议：No local lock/atomic owner API covers both controller members and observed access paths. Same-runner serialization is possible but unproven.
- 判定理由：Unsynchronized shape exists but evidence gate is incomplete; retain unknown.
- 无法独立证明：same event-runner or queue serialization; feasible main/PIP shared-controller interleaving; reachable trigger and CIA impact
- 证据引用：unable_to_determine=source

### 11. `plausible_unproven` `RC-STREAM-LISTENER` `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67` `streamListener_`

- candidate `1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7`；diagnostic `ohscanner.cpp.shared_ptr_race:3a00ec7ac4a80075`；group key `RC-STREAM-LISTENER|sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h|streamListener_|66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`
- source `openharmony/communication_dsoftbus` commit `652f88e0261ce4d0610f73cc451c26b84d2597af` tree `f8a14c30ef815217fa4d267939cff84db1fd5057` blob `1f8eb2e331021766be3485a3b56746c074be4687` source SHA-256 `66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：Stream setup runs on caller thread. VtpStreamSocket creates detached NotifyStreamListener/DoStreamRecv threads and invokes streamReceiver_ under streamSocketLock_. streamListener_ itself is not shown to be read by callbacks; StreamSocketListener keeps a separate listener_ copy.
- 发布顺序：Constructor initializes streamListener_. Create*Channel calls SetStreamRecvListener(streamListener_), which writes it, creates StreamSocketListener(recvListener) and installs the separate copy on the socket.
- 共享对象生命周期：StreamAdaptor owns StreamManager; StreamManager owns socket map/listener fields; VtpStreamSocket owns streamReceiver_. Release drops socket/listener. Observed callback lifetime is separate from candidate streamListener_.
- 触发窗口：Would require product caller to invoke public SetStreamRecvListener concurrently with Create*Channel or another setter. Production call-site search found setup calls and tests only.
- 同步协议：No manager lock covers streamListener_/socketListener_/socketMap_; VtpStreamSocket::streamSocketLock_ covers streamReceiver_ callback use. Candidate owner protocol incomplete.
- 判定理由：Source provenance and concurrency obligations unresolved; retain unknown.
- 无法独立证明：product caller for public SetStreamRecvListener; same-object post-publication overlap; trigger and CIA impact
- 证据引用：unable_to_determine=source

### 12. `holdout` `RC-CONSTRUCTOR-NOISE` `services/core/ability/status_cache/include/status_cache.h:27` `timeUtilsProxy_`

- candidate `2c7fb8c5e56f8f2488762f1c65dec2f8a2c3cd9fb6f743df83c9e99c4687d679`；diagnostic `ohscanner.cpp.shared_ptr_race:8c59bff727467c96`；group key `RC-CONSTRUCTOR-NOISE|services/core/ability/status_cache/include/status_cache.h|timeUtilsProxy_|cd9dbbd3a2e16405198c2e6bc63f8178d4c45106b5d8a31a00f713d0f66bc6d9`
- source `openharmony/update_updateservice` commit `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` tree `b367991eed0272f54fe5ae712d18e24377d57949` blob `1ab7136b8fcc050976b33febff457fcc9fa04177` source SHA-256 `cd9dbbd3a2e16405198c2e6bc63f8178d4c45106b5d8a31a00f713d0f66bc6d9`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：StatusCache constructor copies TimeUtilsProxy into timeUtilsProxy_; later code only tests/calls pointee.
- 共享对象生命周期：Stable owner after construction; no replacement/reset.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 13. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/cj/accesstoken/include/at_manager_impl.h:115` `data_`

- candidate `b7add44fd9df2d261854292572cc006c1a94a0db75a8338dd8af2162bd455ea6`；diagnostic `ohscanner.cpp.shared_ptr_race:d8af1c4db4ad6579`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/cj/accesstoken/include/at_manager_impl.h|data_|287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `93c786e28ddd7dc390dbe6a2f24c784cb2f9a872` source SHA-256 `287d462edbeb4376031415b0e7171d409f04e4772ab819ad882341a9669a5cb1`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Authorization/request wrapper constructor copies RequestAsyncContext into data_; callback reads stable owner.
- 共享对象生命周期：Callback object retains request context; no owner replacement.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 14. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h:51` `asyncContextPtr`

- candidate `93c2385311e2c10ecbfe8c0f78776474bc6264b5cbd0baeb50e33caaf4aeeb30`；diagnostic `ohscanner.cpp.shared_ptr_race:a2e8ea87344f261f`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/cj/accesstoken/include/request_global_switch_on_setting.h|asyncContextPtr|1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `5ee7e75ff720127386ef77cc515d979613ee81b5` source SHA-256 `1e6804e8f930cab69885c4d8e493768ad2dc5ce33e7faa3e1a92d906e5b4e0b2`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Async-context handle constructor copies local shared_ptr into asyncContextPtr; no observed owner replacement.
- 共享对象生命周期：Handle retains request context through async/callback completion.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 15. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h:49` `asyncContextPtr`

- candidate `a1278c524438add8635a68621e5f4b9d5bd8b9f98775d34ab6f8d39b783dc116`；diagnostic `ohscanner.cpp.shared_ptr_race:089c58a01b3a66a8`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/cj/accesstoken/include/request_permission_on_setting.h|asyncContextPtr|a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `5ac2150911a4e2cc107ce1d28f0553c93bbe0512` source SHA-256 `a8108746a4d3f7817bdf6e95e50df46d56f9cf6871d616abf214af4d0fc62450`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Async-context handle constructor copies local shared_ptr into asyncContextPtr; no observed owner replacement.
- 共享对象生命周期：Handle retains request context through async/callback completion.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 16. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h:61` `asyncContextPtr`

- candidate `16da132f19039393f70288746451ca9bf29f3276beb08e9f4819448d60c6c710`；diagnostic `ohscanner.cpp.shared_ptr_race:d9832942dc24a7fd`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/js/napi/accesstoken/include/napi_open_permission_on_setting.h|asyncContextPtr|01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `2c5c6dcf02cf1ae7e44ff7538055057ba4cf33f9` source SHA-256 `01ff052ab114b27d548c974d522141e6fec8bb142b5e0f4dd27366f5711153b0`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Async-context handle constructor copies local shared_ptr into asyncContextPtr; no observed owner replacement.
- 共享对象生命周期：Handle retains request context through async/callback completion.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 17. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h:68` `asyncContextPtr`

- candidate `25ed03d67f1c9d5397936181c95cf65131311f145f8a9f42cd358eef8b4bf122`；diagnostic `ohscanner.cpp.shared_ptr_race:9f15e9ed288e908f`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/js/napi/accesstoken/include/napi_request_global_switch_on_setting.h|asyncContextPtr|96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `bc968e7ce325261154cc42d57134516a94ae454d` source SHA-256 `96085536e15127518f88dce54536c151531eca8ec19e7fb9bae370e01acd351d`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Async-context handle constructor copies local shared_ptr into asyncContextPtr; no observed owner replacement.
- 共享对象生命周期：Handle retains request context through async/callback completion.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 18. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:72` `asyncContextPtr`

- candidate `2c8c1796905c2ba3189b24ea3fb4537419cfc3fa215adebc63b65a36bffba8bc`；diagnostic `ohscanner.cpp.shared_ptr_race:3b5c55b6b40da278`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h|asyncContextPtr|ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `b6adec200d1500ae4148a5a801364fa38e81a99a` source SHA-256 `ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Async-context handle constructor copies local shared_ptr into asyncContextPtr; no observed owner replacement.
- 共享对象生命周期：Handle retains request context through async/callback completion.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 19. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h:117` `data_`

- candidate `21a7bd798474558ed52232e03e58ace103497d48a30fb6f5b11a0f3cf8df66b4`；diagnostic `ohscanner.cpp.shared_ptr_race:6b05864947153293`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/js/napi/accesstoken/include/napi_request_permission.h|data_|ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `b6adec200d1500ae4148a5a801364fa38e81a99a` source SHA-256 `ffa53ac8eb6aadafce4755afd49c2efc06164cc755e3234ba2492f440ff7a7ed`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Authorization/request wrapper constructor copies RequestAsyncContext into data_; callback reads stable owner.
- 共享对象生命周期：Callback object retains request context; no owner replacement.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 20. `holdout` `RC-CONSTRUCTOR-NOISE` `interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h:63` `asyncContextPtr`

- candidate `cf54aeb9706c25f3043ea685b7cf3ce168c05796cb71cc36d9095d7b2a29e495`；diagnostic `ohscanner.cpp.shared_ptr_race:104a194d0e487cc4`；group key `RC-CONSTRUCTOR-NOISE|interfaces/kits/js/napi/accesstoken/include/napi_request_permission_on_setting.h|asyncContextPtr|c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560`
- source `openharmony/security_access_token` commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0` blob `7828aceaf6d50c98c2b70d49f7ea17bda654a982` source SHA-256 `c1c33169daa4d39acf5ef5f42e72c867f2d1a175e59e4917b54d1abc6b313560`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported sites are constructor/member initialization or stable owner reads. No same-object post-publication writer is observed at the candidate site; pointee behavior is outside this disposition.
- 发布顺序：Async-context handle constructor copies local shared_ptr into asyncContextPtr; no observed owner replacement.
- 共享对象生命周期：Handle retains request context through async/callback completion.
- 触发窗口：No same-object conflicting pair, hence no proven owner-race trigger window.
- 同步协议：No synchronization proof needed to exclude the observed constructor/single-access shape; no same-object mutation pair in reviewed source.
- 判定理由：Constructor/stable-owner shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 21. `holdout` `RC-SCOPE-MOCK` `kvstoremock/external_inner_kit/napi/include/extension_context.h:61` `abilityInfo_`

- candidate `0089d85d5f9004679cf036196674b664847db9ed99f5b1bb4f74803ea2f3f427`；diagnostic `ohscanner.cpp.shared_ptr_race:afde9c16d899ceb8`；group key `RC-SCOPE-MOCK|kvstoremock/external_inner_kit/napi/include/extension_context.h|abilityInfo_|fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`
- source `openharmony/distributeddatamgr_kv_store` commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` tree `3b92c53fde616d5a3f9487b0c295670a42c63023` blob `6454f335e87e326ce97bfc405f15347e814aa700` source SHA-256 `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported source is under kvstoremock/external_inner_kit, a mock/support scope excluded from production scoring by the historical scope rule.
- 发布顺序：Not applicable to production vulnerability truth; retained as out-of-scope control.
- 共享对象生命周期：Mock/support lifetime is not a production component claim.
- 触发窗口：No production trigger in scope.
- 同步协议：Not applicable to production owner-race question.
- 判定理由：Explicit non-production mock/support path; unrelated excludes only a production shared_ptr vulnerability claim.
- 证据引用：unrelated_control=source

### 22. `holdout` `RC-SCOPE-MOCK` `kvstoremock/external_inner_kit/napi/include/extension_context.h:65` `abilityInfo_`

- candidate `de8642d38c52fbba01c43f4d7425d29330fb03e273de8ab740e5b2cc00d2a1d5`；diagnostic `ohscanner.cpp.shared_ptr_race:565571f23fbc00e3`；group key `RC-SCOPE-MOCK|kvstoremock/external_inner_kit/napi/include/extension_context.h|abilityInfo_|fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`
- source `openharmony/distributeddatamgr_kv_store` commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` tree `3b92c53fde616d5a3f9487b0c295670a42c63023` blob `6454f335e87e326ce97bfc405f15347e814aa700` source SHA-256 `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported source is under kvstoremock/external_inner_kit, a mock/support scope excluded from production scoring by the historical scope rule.
- 发布顺序：Not applicable to production vulnerability truth; retained as out-of-scope control.
- 共享对象生命周期：Mock/support lifetime is not a production component claim.
- 触发窗口：No production trigger in scope.
- 同步协议：Not applicable to production owner-race question.
- 判定理由：Explicit non-production mock/support path; unrelated excludes only a production shared_ptr vulnerability claim.
- 证据引用：unrelated_control=source

### 23. `holdout` `RC-SCOPE-MOCK` `kvstoremock/external_inner_kit/napi/include/extension_context.h:81` `abilityInfo_`

- candidate `a662e84f949b68d0fba943db9acf075d1ab54a4b4ff4934608a21a1ea9eebc2d`；diagnostic `ohscanner.cpp.shared_ptr_race:0176c25c2194b0d7`；group key `RC-SCOPE-MOCK|kvstoremock/external_inner_kit/napi/include/extension_context.h|abilityInfo_|fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`
- source `openharmony/distributeddatamgr_kv_store` commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` tree `3b92c53fde616d5a3f9487b0c295670a42c63023` blob `6454f335e87e326ce97bfc405f15347e814aa700` source SHA-256 `fa01c30d76b76bfaf6f4c927d506e8665ee14eae69b6eec6eb1be1134bd60458`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：Reported source is under kvstoremock/external_inner_kit, a mock/support scope excluded from production scoring by the historical scope rule.
- 发布顺序：Not applicable to production vulnerability truth; retained as out-of-scope control.
- 共享对象生命周期：Mock/support lifetime is not a production component claim.
- 触发窗口：No production trigger in scope.
- 同步协议：Not applicable to production owner-race question.
- 判定理由：Explicit non-production mock/support path; unrelated excludes only a production shared_ptr vulnerability claim.
- 证据引用：unrelated_control=source

### 24. `holdout` `RC-WINDOW-SINGLE` `interfaces/innerkits/wm/wm_animation_common.h:220` `animationConfig`

- candidate `3f33ecdd5899ae2cbbff6aae95eeef494c583c294112752e69c72f3ab569dbba`；diagnostic `ohscanner.cpp.shared_ptr_race:ddc2f2c8ccefa542`；group key `RC-WINDOW-SINGLE|interfaces/innerkits/wm/wm_animation_common.h|animationConfig|7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `3c325423cb185f8275e3eb62853ef9c16477aef9` source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 25. `holdout` `RC-WINDOW-SINGLE` `interfaces/innerkits/wm/wm_animation_common.h:261` `animationParams`

- candidate `98a2ac1ba0b1d0501fe6fc17e979d887a2623f843221e9582259eac902cc7e1a`；diagnostic `ohscanner.cpp.shared_ptr_race:88adf81778a285a9`；group key `RC-WINDOW-SINGLE|interfaces/innerkits/wm/wm_animation_common.h|animationParams|7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `3c325423cb185f8275e3eb62853ef9c16477aef9` source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 26. `holdout` `RC-WINDOW-SINGLE` `interfaces/innerkits/wm/wm_animation_common.h:265` `animationSystemParams`

- candidate `96d94fd92a003251ec386f66069c5a52f4bd88f63a0ff30d0679456ae6a3ce84`；diagnostic `ohscanner.cpp.shared_ptr_race:ed042de13472f105`；group key `RC-WINDOW-SINGLE|interfaces/innerkits/wm/wm_animation_common.h|animationSystemParams|7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `3c325423cb185f8275e3eb62853ef9c16477aef9` source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 27. `holdout` `RC-WINDOW-SINGLE` `interfaces/innerkits/wm/wm_animation_common.h:273` `needAnimation`

- candidate `ead5f473d62f6d21712f7eb0ae59bc743f1d7222f5fba437120c4508668ea785`；diagnostic `ohscanner.cpp.shared_ptr_race:506ce95217f58cdd`；group key `RC-WINDOW-SINGLE|interfaces/innerkits/wm/wm_animation_common.h|needAnimation|7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `3c325423cb185f8275e3eb62853ef9c16477aef9` source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 28. `holdout` `RC-WINDOW-SINGLE` `interfaces/innerkits/wm/wm_animation_common.h:289` `excludeFromDock`

- candidate `f6f50c28e7e1dd49302cecc20d4ecbd713d0e5e7f97d0e813bf3aa6c49e633f9`；diagnostic `ohscanner.cpp.shared_ptr_race:36fc4a9919ef311c`；group key `RC-WINDOW-SINGLE|interfaces/innerkits/wm/wm_animation_common.h|excludeFromDock|7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `3c325423cb185f8275e3eb62853ef9c16477aef9` source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 29. `holdout` `RC-WINDOW-SINGLE` `interfaces/innerkits/wm/wm_animation_common.h:297` `excludeFromRecent`

- candidate `48ff783415251c95ed5e93eabe1817f941d11c8f4727222408d25a6480416e20`；diagnostic `ohscanner.cpp.shared_ptr_race:da37107a72040100`；group key `RC-WINDOW-SINGLE|interfaces/innerkits/wm/wm_animation_common.h|excludeFromRecent|7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `3c325423cb185f8275e3eb62853ef9c16477aef9` source SHA-256 `7e61564179c0428936b29d67d556b8c94b78a79849709aa3a807827a291acdcd`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 30. `holdout` `RC-WINDOW-SINGLE` `interfaces/kits/napi/float_view_napi/js_float_view_listener.h:32` `jsCallBack_`

- candidate `a786eb0afcb5cd995219af27c26d2770b3d5e9560a394868769adfdbb3c03fee`；diagnostic `ohscanner.cpp.shared_ptr_race:efd72e030c5373be`；group key `RC-WINDOW-SINGLE|interfaces/kits/napi/float_view_napi/js_float_view_listener.h|jsCallBack_|fe3710593c477a3c4e450eee87e8ab89267a0312738bacece7f34686d7fa2e1b`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `8c6a9f3774155f25d1deb5f431faef5ca26f5f1f` source SHA-256 `fe3710593c477a3c4e450eee87e8ab89267a0312738bacece7f34686d7fa2e1b`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：jsCallBack_ copied into wrapper at construction then read by callback dispatch; no post-publication replacement.
- 共享对象生命周期：Listener/callback capture keeps owner alive for observed flow.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Stable owner initialization/read-only propagation excludes observed owner race.
- 证据引用：unrelated_control=source

### 31. `holdout` `RC-WINDOW-SINGLE` `interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h:33` `jsCallBack_`

- candidate `228aa372f6f5454101891f359b3bedcad2cc55d90afbd43d9c50f8de35f27598`；diagnostic `ohscanner.cpp.shared_ptr_race:2b72311e39c5ba9c`；group key `RC-WINDOW-SINGLE|interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h|jsCallBack_|b2de64e2e5bb197f96b1d7693dbe7aca4c5966cd31c9133b17f412c3615a40bc`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `26e4a721b1f126e33af5c9fba7c908702ea49dbd` source SHA-256 `b2de64e2e5bb197f96b1d7693dbe7aca4c5966cd31c9133b17f412c3615a40bc`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：jsCallBack_ copied into wrapper at construction then read by callback dispatch; no post-publication replacement.
- 共享对象生命周期：Listener/callback capture keeps owner alive for observed flow.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Stable owner initialization/read-only propagation excludes observed owner race.
- 证据引用：unrelated_control=source

### 32. `holdout` `RC-WINDOW-SINGLE` `interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h:32` `jsCallBack_`

- candidate `385d0407467c117c1bc471deaee058fa95493080dc74d75d3b12833bac0a3eff`；diagnostic `ohscanner.cpp.shared_ptr_race:c086123c9d41ee3e`；group key `RC-WINDOW-SINGLE|interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h|jsCallBack_|20706185efad40245b844eb5b1397da2de26a1f42b5d6dc4719ea5520f300348`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `29db5c04bd534bcd029d702e8df7867573b6f35d` source SHA-256 `20706185efad40245b844eb5b1397da2de26a1f42b5d6dc4719ea5520f300348`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：jsCallBack_ copied into wrapper at construction then read by callback dispatch; no post-publication replacement.
- 共享对象生命周期：Listener/callback capture keeps owner alive for observed flow.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Stable owner initialization/read-only propagation excludes observed owner race.
- 证据引用：unrelated_control=source

### 33. `holdout` `RC-WINDOW-SINGLE` `previewer/include/wm_animation_common.h:214` `animationConfig`

- candidate `4e9afc5ec4b9b2c8418de2868780ce9c410e056cda6a5a76c803ad5216b75701`；diagnostic `ohscanner.cpp.shared_ptr_race:71fa65325123bf8b`；group key `RC-WINDOW-SINGLE|previewer/include/wm_animation_common.h|animationConfig|dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `562b504ae819cd154f515bc264038f7f3cd3100c` source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 34. `holdout` `RC-WINDOW-SINGLE` `previewer/include/wm_animation_common.h:253` `animationParams`

- candidate `fc90aa9eaa7a862404445c7a7b340636035341caf97d661223a49f930f6bc5d3`；diagnostic `ohscanner.cpp.shared_ptr_race:893564c6130e3cac`；group key `RC-WINDOW-SINGLE|previewer/include/wm_animation_common.h|animationParams|dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `562b504ae819cd154f515bc264038f7f3cd3100c` source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 35. `holdout` `RC-WINDOW-SINGLE` `previewer/include/wm_animation_common.h:257` `animationSystemParams`

- candidate `8ab1907289a43e543ac716c3db76d8db1e06a9990741d1ecbdee109caf7f739e`；diagnostic `ohscanner.cpp.shared_ptr_race:d5124f0862a6e7c7`；group key `RC-WINDOW-SINGLE|previewer/include/wm_animation_common.h|animationSystemParams|dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `562b504ae819cd154f515bc264038f7f3cd3100c` source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 36. `holdout` `RC-WINDOW-SINGLE` `previewer/include/wm_animation_common.h:265` `needAnimation`

- candidate `3f69ba23ee35ab8b695eb5b3019703343504bae60835da22335e2ab165116dde`；diagnostic `ohscanner.cpp.shared_ptr_race:c51749733cd5316e`；group key `RC-WINDOW-SINGLE|previewer/include/wm_animation_common.h|needAnimation|dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `562b504ae819cd154f515bc264038f7f3cd3100c` source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 37. `holdout` `RC-WINDOW-SINGLE` `previewer/include/wm_animation_common.h:281` `excludeFromDock`

- candidate `0c3d001e4abbb837b5b164bade7dfca901342fca31a94ec355667827f2376e4c`；diagnostic `ohscanner.cpp.shared_ptr_race:6b315ae8b49a0cb4`；group key `RC-WINDOW-SINGLE|previewer/include/wm_animation_common.h|excludeFromDock|dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `562b504ae819cd154f515bc264038f7f3cd3100c` source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 38. `holdout` `RC-WINDOW-SINGLE` `previewer/include/wm_animation_common.h:289` `excludeFromRecent`

- candidate `1e0688494c36112e34cd1f27f9c35be050c26bb3ffec36ed41e8b0de1cb9fa00`；diagnostic `ohscanner.cpp.shared_ptr_race:d2e5434b329e803c`；group key `RC-WINDOW-SINGLE|previewer/include/wm_animation_common.h|excludeFromRecent|dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `562b504ae819cd154f515bc264038f7f3cd3100c` source SHA-256 `dd6c49709e1024485adf138a6994508a54861a757430b734be48f025927cb62e`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Marshalling reads pair with Unmarshalling writes to a fresh object; reported owner is not rewritten in place.
- 共享对象生命周期：Owners are established before publication and not reassigned at reported sites. SurfaceCaptureFuture owner fields are mutex-covered except HDR reset before FutureCall.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Observed sites are not a same-object concurrent owner pair.
- 证据引用：unrelated_control=source

### 39. `holdout` `RC-WINDOW-SINGLE` `utils/include/surface_capture_future.h:73` `hdrPixelMap_`

- candidate `df1d89f286c9727a550f92b5c451d9126cd66adeb96a10be52415868b6fe2eb1`；diagnostic `ohscanner.cpp.shared_ptr_race:10da51cf3210aac9`；group key `RC-WINDOW-SINGLE|utils/include/surface_capture_future.h|hdrPixelMap_|6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `5554d63b22a4de01654c415717b13e9579ba9fdf` source SHA-256 `6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：HDR/error callbacks and GetHDRResult can differ; most accesses use Future::mutex_, but OnSurfaceCapture resets hdrPixelMap_=nullptr before FutureCall locks.
- 发布顺序：Out-of-lock reset can precede FutureCall; timeout GetHDRResult may read/copy the owner.
- 共享对象生命周期：New capture can reset member while timeout caller still reaches GetHDRResult.
- 触发窗口：Potential timeout/reset overlap; exact callback schedule and product trigger unproven.
- 同步协议：Partial: most accesses locked, reset outside mutex_. Repair would move reset under lock or use atomic owner ops.
- 判定理由：Out-of-lock owner write/read remains unresolved; retain unknown.
- 无法独立证明：actual timeout/callback overlap; controlled TSan run for reset; product trigger and CIA impact
- 证据引用：unable_to_determine=source

### 40. `holdout` `RC-WINDOW-SINGLE` `utils/include/surface_capture_future.h:73` `pixelMap_`

- candidate `91a5f46b96a11a6166bccc207946d7524912938daf1cb7058fd89d79cd8ce881`；diagnostic `ohscanner.cpp.shared_ptr_race:9d52151c77a1c9f8`；group key `RC-WINDOW-SINGLE|utils/include/surface_capture_future.h|pixelMap_|6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `5554d63b22a4de01654c415717b13e9579ba9fdf` source SHA-256 `6ddefa22004292cbb0d771f76fc317864493478b2f6366be56c259ff75a57fb7`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `safe`（scope `shared_ptr_owner_race_only`）；机制标签 `safe`；证据处置 `safe_control`；证据完整度 `complete_for_owner_race`
- 线程/事件队列：Callbacks and GetResult/FetchResult may differ, but all observed pixelMap_ owner accesses are serialized by Future::mutex_.
- 发布顺序：OnSurfaceCapture writes through FutureCall(); GetResult/FetchResult read while Future::GetResult holds mutex_.
- 共享对象生命周期：SurfaceCaptureFuture owns pixelMap_ until result retrieval/overwrite; owner access set protected by mutex_.
- 触发窗口：Callback/GetResult may overlap but owner operations are serialized; no owner race window remains.
- 同步协议：Future::mutex_ covers the pixelMap_ owner access set.
- 判定理由：Independent fixed-source check supports safe only for observed owner synchronization.
- 无法独立证明：pointee PixelMap thread safety; product CIA impact
- 证据引用：safe_control=source

### 41. `holdout` `RC-WINDOW-SINGLE` `utils/include/ui_effect_controller_common.h:53` `backgroundFilter_`

- candidate `a652b1b68097421147c0051e3c8f75cd993e286907958c8c40bec5a8a4c8056a`；diagnostic `ohscanner.cpp.shared_ptr_race:c39b27e5285d882f`；group key `RC-WINDOW-SINGLE|utils/include/ui_effect_controller_common.h|backgroundFilter_|1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `eae1ac64199017f10cff98cc2a470a18b7205b41` source SHA-256 `1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：IsEmpty reads after ConvertFromJsValue initializes a fresh local UIEffectParams; Parcel Unmarshalling constructs fresh object.
- 共享对象生命周期：Reported owner attached to fresh local then read; no post-publication mutation.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Fresh-object/sequential shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 42. `holdout` `RC-WINDOW-SINGLE` `utils/include/ui_effect_controller_common.h:53` `effect_`

- candidate `869e521a61c57900b90bc59f13ce6c298aa86da99f03996db8340bfccc09ebe9`；diagnostic `ohscanner.cpp.shared_ptr_race:ef9b55edb54ffcea`；group key `RC-WINDOW-SINGLE|utils/include/ui_effect_controller_common.h|effect_|1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `eae1ac64199017f10cff98cc2a470a18b7205b41` source SHA-256 `1864f6e38e779147011fadcd468da3e2594b3f883f30366f8a7e85b1ac0251cb`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：IsEmpty reads after ConvertFromJsValue initializes a fresh local UIEffectParams; Parcel Unmarshalling constructs fresh object.
- 共享对象生命周期：Reported owner attached to fresh local then read; no post-publication mutation.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Fresh-object/sequential shape excludes observed owner race, not product safety.
- 证据引用：unrelated_control=source

### 43. `holdout` `RC-WINDOW-SINGLE` `wmserver/include/drag_controller.h:68` `vsyncCallback_`

- candidate `a3080f2b2c90a12166ec6d4ad76a3c7886033b47e9356f124a74c00fb1426a80`；diagnostic `ohscanner.cpp.shared_ptr_race:4d4fc419b2328830`；group key `RC-WINDOW-SINGLE|wmserver/include/drag_controller.h|vsyncCallback_|9e59f4470eb1d59efaa1b12643d579b4f5315dc69a61250fbf3a05823f2efa23`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `d0fcbe8d24b7b47d83e2bf6fcf65954aac3e4428` source SHA-256 `9e59f4470eb1d59efaa1b12643d579b4f5315dc69a61250fbf3a05823f2efa23`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Callback/handler owner initialized or captured at construction/registration and stable in bounded source.
- 共享对象生命周期：Owner held by wrapper; no reset at candidate site.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Stable owner initialization/use is not an owner race.
- 证据引用：unrelated_control=source

### 44. `holdout` `RC-WINDOW-SINGLE` `wmserver/include/window_common_event.h:41` `eventHandler_`

- candidate `4e5f35efb3f6c9480e5016776b81acd7e82b5fd3aacbd5aa211c0ed7dda3dc2d`；diagnostic `ohscanner.cpp.shared_ptr_race:d31f8237b87d720d`；group key `RC-WINDOW-SINGLE|wmserver/include/window_common_event.h|eventHandler_|2ff4b5f81e9305bb595477281b49ff744d516c90ac962e4c0baf8f34416eb9af`
- source `openharmony/window_window_manager` commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` tree `24e60146ba2fe4af3aaef20b306a1e306df44617` blob `40fbde49afe414ccb8efd625d05b12a1bc71daae` source SHA-256 `2ff4b5f81e9305bb595477281b49ff744d516c90ac962e4c0baf8f34416eb9af`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unrelated`（scope `shared_ptr_owner_race_shape`）；机制标签 `unrelated`；证据处置 `unrelated_control`；证据完整度 `complete_for_observed_site`
- 线程/事件队列：The source set mixes Parcel/NAPI marshalling, callback wrappers and window helpers. No common cross-thread owner pair is established except the separately noted surface HDR reset.
- 发布顺序：Callback/handler owner initialized or captured at construction/registration and stable in bounded source.
- 共享对象生命周期：Owner held by wrapper; no reset at candidate site.
- 触发窗口：No same-object post-publication mutation window for noise/unrelated sites; HDR has a separate timeout/reset candidate window.
- 同步协议：No synchronization needed for constructor/fresh-object sites. pixelMap_ accesses use Future::mutex_; hdrPixelMap_ reset is outside it.
- 判定理由：Selected nested member is owner-stable in fixed source.
- 证据引用：unrelated_control=source

### 45. `holdout` `RC-STREAM-LISTENER` `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67` `streamListener_`

- candidate `1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7`；diagnostic `ohscanner.cpp.shared_ptr_race:3a00ec7ac4a80075`；group key `RC-STREAM-LISTENER|sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h|streamListener_|66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`
- source `openharmony/communication_dsoftbus` commit `652f88e0261ce4d0610f73cc451c26b84d2597af` tree `f8a14c30ef815217fa4d267939cff84db1fd5057` blob `1f8eb2e331021766be3485a3b56746c074be4687` source SHA-256 `66a2ddb0186f92435d1dbc4e93f8f5161461d69b5661aa33ac98f8ebe23c8100`
- Detector `ohscanner.cpp.shared_ptr_race` version-at-scan `0.4.0` rule `ohcpp-shared-ptr-race-candidate-001` profile `light-ast`
- 真值标签 `unknown`（scope `product_level_security_truth`）；机制标签 `unknown`；证据处置 `unable_to_determine`；证据完整度 `partial`
- 线程/事件队列：Stream setup runs on caller thread. VtpStreamSocket creates detached NotifyStreamListener/DoStreamRecv threads and invokes streamReceiver_ under streamSocketLock_. streamListener_ itself is not shown to be read by callbacks; StreamSocketListener keeps a separate listener_ copy.
- 发布顺序：Constructor initializes streamListener_. Create*Channel calls SetStreamRecvListener(streamListener_), which writes it, creates StreamSocketListener(recvListener) and installs the separate copy on the socket.
- 共享对象生命周期：StreamAdaptor owns StreamManager; StreamManager owns socket map/listener fields; VtpStreamSocket owns streamReceiver_. Release drops socket/listener. Observed callback lifetime is separate from candidate streamListener_.
- 触发窗口：Would require product caller to invoke public SetStreamRecvListener concurrently with Create*Channel or another setter. Production call-site search found setup calls and tests only.
- 同步协议：No manager lock covers streamListener_/socketListener_/socketMap_; VtpStreamSocket::streamSocketLock_ covers streamReceiver_ callback use. Candidate owner protocol incomplete.
- 判定理由：Source provenance and concurrency obligations unresolved; retain unknown.
- 无法独立证明：product caller for public SetStreamRecvListener; same-object post-publication overlap; trigger and CIA impact
- 证据引用：unable_to_determine=source

## 受控证据与签字边界

- JSProxy Harness 测试：8 tests, OK。
- JSProxy PoC：vulnerable race/close_get_entry TSan 各 3/3 触发；fixed_control_mutex/patched_atomic_minimal 各 3/3 clean；single/unrelated control clean。
- Harness 绑定 exact Git blob bytes 和源文件 SHA，但不执行完整 OpenHarmony 产品构建；不升级 confirmed/reportable，不伪造 CVE、受影响版本或产品 CIA。
- 其余 `unknown` 项保留线程/队列、发布顺序、生命周期、触发窗口、同步协议和产品入口/CIA 缺口；`unrelated`/`safe` 仅限 shared_ptr owner-race scope。

## Source/object verification

- source checks: 45/45 Git object provenance verified; commit/tree/blob/source SHA matches recorded.
- project checkout: branch `codex/full-runtime-performance-audit-20261014`, HEAD `0dd71fd78baa01283df081f9bd02fe4b7f2df326`, tree `20ec92e835803f486d088eef183c7db08564926b`, dirty files `339` preserved.
