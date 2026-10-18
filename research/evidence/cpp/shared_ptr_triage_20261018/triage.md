# shared_ptr_race candidate triage (2026-10-18)

> Candidate-only lexical triage; counts are access-point diagnostics,
> not vulnerability, root-cause, or Precision/Recall measurements.

| Component | Files | Candidates | File/symbol groups |
|---|---:|---:|---:|
| `communication_dsoftbus` | 1656 | 87 | 13 |
| `distributeddatamgr_kv_store` | 1446 | 348 | 42 |
| `security_access_token` | 550 | 101 | 30 |
| `update_updateservice` | 219 | 42 | 8 |
| `window_window_manager` | 1112 | 200 | 44 |

## Top members

### `communication_dsoftbus`

- `core/connection/wifi_direct_cpp/entity/p2p_connect_state.cpp` `operation_`: 19 candidate(s)
- `core/connection/wifi_direct_cpp/wifi_direct_executor.cpp` `processor_`: 16 candidate(s)
- `core/connection/wifi_direct_cpp/entity/p2p_create_group_state.cpp` `operation_`: 13 candidate(s)
- `core/connection/wifi_direct_cpp/entity/p2p_destroy_group_state.cpp` `operation_`: 13 candidate(s)
- `sdk/transmission/trans_channel/udp/stream/adaptor/src/stream_adaptor.cpp` `streamManager_`: 7 candidate(s)
- `core/connection/wifi_direct_cpp/data/inner_link.cpp` `channel_`: 4 candidate(s)
- `core/connection/wifi_direct_cpp/command/processor_selector_factory.cpp` `selector_`: 3 candidate(s)
- `core/connection/wifi_direct_cpp/wifi_direct_scheduler_factory.cpp` `scheduler_`: 3 candidate(s)
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp` `socketListener_`: 2 candidate(s)
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp` `streamListener_`: 2 candidate(s)
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h` `msgManager_`: 2 candidate(s)
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/vtp_instance.cpp` `instance_`: 2 candidate(s)

### `distributeddatamgr_kv_store`

- `frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp` `nativeStore_`: 69 candidate(s)
- `frameworks/libs/distributeddb/syncer/src/device/syncer_proxy.cpp` `syncer_`: 65 candidate(s)
- `frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp` `nativeQueryPtr_`: 45 candidate(s)
- `frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp` `nativeResultSet_`: 28 candidate(s)
- `frameworks/ets/taihe/kv_store/src/ohos.data.distributedkvstore.impl.cpp` `kvDataManager_`: 17 candidate(s)
- `frameworks/libs/distributeddb/syncer/src/device/sync_engine.cpp` `subManager_`: 17 candidate(s)
- `frameworks/libs/distributeddb/gaussdb_rd/src/interface/src/result_set.cpp` `context_`: 12 candidate(s)
- `frameworks/innerkitsimpl/kvdb/src/task_executor.cpp` `pool_`: 10 candidate(s)
- `frameworks/libs/distributeddb/common/src/runtime_context_impl.cpp` `dataTranslate_`: 8 candidate(s)
- `frameworks/innerkitsimpl/kvdb/src/single_store_impl.cpp` `syncObserver_`: 7 candidate(s)
- `frameworks/jskitsimpl/distributeddata/src/js_kv_store.cpp` `kvStore_`: 6 candidate(s)
- `frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp` `kvStore_`: 6 candidate(s)

### `security_access_token`

- `frameworks/js/napi/accesstoken/src/napi_open_permission_on_setting.cpp` `reqContext_`: 21 candidate(s)
- `services/el5filekeymanager/src/el5_filekey_manager_service_ability.cpp` `service_`: 10 candidate(s)
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `addTask_`: 6 candidate(s)
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `removeTask_`: 6 candidate(s)
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `updateTask_`: 6 candidate(s)
- `services/tokensyncmanager/src/remote/remote_command_executor.cpp` `ptrChannel_`: 5 candidate(s)
- `services/el5filekeymanager/src/el5_filekey_manager_service.cpp` `subscriber_`: 4 candidate(s)
- `services/el5filekeymanager/src/el5_filekey_manager_service.cpp` `unloadHandler_`: 4 candidate(s)
- `frameworks/ets/ani/accesstoken/src/ani_request_base.cpp` `controllerInstance_`: 3 candidate(s)
- `frameworks/ets/ani/accesstoken/src/ani_request_base.cpp` `handler_`: 3 candidate(s)
- `services/accesstokenmanager/main/cpp/src/clawtoken/claw_ticket_manager.cpp` `appManagerDeathCallback_`: 3 candidate(s)
- `services/accesstokenmanager/main/cpp/src/database/rdb_dlopen_manager.cpp` `eventRunner_`: 3 candidate(s)

### `update_updateservice`

- `services/firmware/upgrade/flow/src/firmware_flow_manager.cpp` `executeMode_`: 15 candidate(s)
- `services/firmware/upgrade/status/src/firmware_status_cache.cpp` `statusCache_`: 5 candidate(s)
- `services/startup/manage/src/schedule_manager.cpp` `accessManager_`: 5 candidate(s)
- `services/startup/manage/src/startup_manager.cpp` `scheduleManager_`: 5 candidate(s)
- `services/core/ability/alarm/src/timer_manager.cpp` `timer_`: 4 candidate(s)
- `services/firmware/upgrade/flow/src/firmware_flow_manager.cpp` `executor_`: 3 candidate(s)
- `services/startup/manage/src/schedule_manager.cpp` `startupSchedule_`: 3 candidate(s)
- `services/firmware/upgrade/executor/src/firmware_download_executor.cpp` `downloadThread_`: 2 candidate(s)

### `window_window_manager`

- `wm/src/window_scene.cpp` `option`: 21 candidate(s)
- `wm/src/picture_in_picture_controller.cpp` `mainWindowXComponentController_`: 14 candidate(s)
- `wm/src/picture_in_picture_controller_ani.cpp` `mainWindowXComponentController_`: 14 candidate(s)
- `interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_listener.cpp` `eventHandler_`: 13 candidate(s)
- `previewer/src/window_scene.cpp` `option`: 9 candidate(s)
- `window_scene/common/src/task_scheduler.cpp` `handler_`: 8 candidate(s)
- `interfaces/kits/ani/float_view/float_view_ani/src/ani_fv_window_listener.cpp` `eventHandler_`: 7 candidate(s)
- `interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_listener.cpp` `eventHandler_`: 7 candidate(s)
- `window_scene/screen_session_manager/src/fold_screen_controller/super_fold_sensor_manager.cpp` `taskScheduler_`: 7 candidate(s)
- `window_scene/common/src/task_scheduler.cpp` `exportHandler_`: 6 candidate(s)
- `window_scene/session/host/src/move_drag_bounds_applier.cpp` `leashWinShadowSurfaceNode_`: 6 candidate(s)
- `interfaces/kits/ani/window_runtime/window_stage_ani/src/ani_transition_controller.cpp` `eventHandler_`: 5 candidate(s)

## Boundary

- Source is read from local pinned Git objects; no fetch or checkout.
- Candidates remain `candidate/unassessed`; no product entry or CIA claim.
- This triage does not rewrite the historical 229/208 records.
