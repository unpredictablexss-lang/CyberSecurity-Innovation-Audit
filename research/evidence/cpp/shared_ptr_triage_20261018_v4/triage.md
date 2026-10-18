# shared_ptr_race candidate triage (2026-10-18)

> Candidate-only lexical triage; counts are access-point diagnostics,
> not vulnerability, root-cause, or Precision/Recall measurements.

| Component | Files | Candidates | File/symbol groups |
|---|---:|---:|---:|
| `communication_dsoftbus` | 1656 | 87 | 13 |
| `distributeddatamgr_kv_store` | 1446 | 179 | 35 |
| `security_access_token` | 550 | 71 | 22 |
| `update_updateservice` | 219 | 24 | 4 |
| `window_window_manager` | 1112 | 143 | 34 |

## Top members

### `communication_dsoftbus`

- `core/connection/wifi_direct_cpp/entity/p2p_connect_state.cpp` `operation_`: 19 candidate(s), reads=15, writes=4, shape=mutable_owner
- `core/connection/wifi_direct_cpp/wifi_direct_executor.cpp` `processor_`: 16 candidate(s), reads=13, writes=2, shape=mutable_owner
- `core/connection/wifi_direct_cpp/entity/p2p_create_group_state.cpp` `operation_`: 13 candidate(s), reads=9, writes=4, shape=mutable_owner
- `core/connection/wifi_direct_cpp/entity/p2p_destroy_group_state.cpp` `operation_`: 13 candidate(s), reads=9, writes=4, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/adaptor/src/stream_adaptor.cpp` `streamManager_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `core/connection/wifi_direct_cpp/data/inner_link.cpp` `channel_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner
- `core/connection/wifi_direct_cpp/command/processor_selector_factory.cpp` `selector_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `core/connection/wifi_direct_cpp/wifi_direct_scheduler_factory.cpp` `scheduler_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp` `socketListener_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp` `streamListener_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h` `msgManager_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/vtp_instance.cpp` `instance_`: 2 candidate(s), reads=2, writes=0, shape=read_only

### `distributeddatamgr_kv_store`

- `frameworks/libs/distributeddb/syncer/src/device/syncer_proxy.cpp` `syncer_`: 65 candidate(s), reads=64, writes=0, shape=read_only
- `frameworks/libs/distributeddb/syncer/src/device/sync_engine.cpp` `subManager_`: 17 candidate(s), reads=16, writes=1, shape=mutable_owner
- `frameworks/libs/distributeddb/gaussdb_rd/src/interface/src/result_set.cpp` `context_`: 12 candidate(s), reads=11, writes=1, shape=mutable_owner
- `frameworks/innerkitsimpl/kvdb/src/task_executor.cpp` `pool_`: 10 candidate(s), reads=10, writes=0, shape=read_only
- `frameworks/libs/distributeddb/common/src/runtime_context_impl.cpp` `dataTranslate_`: 8 candidate(s), reads=8, writes=0, shape=read_only
- `frameworks/jskitsimpl/distributeddata/src/js_kv_store.cpp` `kvStore_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp` `kvStore_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `kvstoremock/external_inner_kit/ipc/mock_ipc.cpp` `rawData_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `frameworks/libs/distributeddb/syncer/src/device/sync_engine.cpp` `metadata_`: 4 candidate(s), reads=1, writes=2, shape=mutable_owner
- `frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp` `param_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `frameworks/libs/distributeddb/storage/src/sqlite/relational/sqlite_single_ver_relational_storage_executor.cpp` `assetLoader_`: 3 candidate(s), reads=2, writes=0, shape=read_only
- `frameworks/libs/distributeddb/storage/src/sqlite/relational/sqlite_single_ver_relational_storage_extend_executor.cpp` `assetLoader_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner

### `security_access_token`

- `services/el5filekeymanager/src/el5_filekey_manager_service_ability.cpp` `service_`: 10 candidate(s), reads=7, writes=2, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `addTask_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `removeTask_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `updateTask_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `services/tokensyncmanager/src/remote/remote_command_executor.cpp` `ptrChannel_`: 5 candidate(s), reads=4, writes=0, shape=read_only
- `services/el5filekeymanager/src/el5_filekey_manager_service.cpp` `subscriber_`: 4 candidate(s), reads=2, writes=2, shape=mutable_owner
- `services/el5filekeymanager/src/el5_filekey_manager_service.cpp` `unloadHandler_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner
- `frameworks/ets/ani/accesstoken/src/ani_request_base.cpp` `controllerInstance_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/clawtoken/claw_ticket_manager.cpp` `appManagerDeathCallback_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/database/rdb_dlopen_manager.cpp` `eventRunner_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/tokensyncmanager/src/service/token_sync_manager_service.cpp` `recvRunner_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/tokensyncmanager/src/service/token_sync_manager_service.cpp` `sendRunner_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner

### `update_updateservice`

- `services/firmware/upgrade/flow/src/firmware_flow_manager.cpp` `executeMode_`: 15 candidate(s), reads=14, writes=1, shape=mutable_owner
- `services/core/ability/alarm/src/timer_manager.cpp` `timer_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner
- `services/firmware/upgrade/flow/src/firmware_flow_manager.cpp` `executor_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/firmware/upgrade/executor/src/firmware_download_executor.cpp` `downloadThread_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner

### `window_window_manager`

- `wm/src/picture_in_picture_controller.cpp` `mainWindowXComponentController_`: 14 candidate(s), reads=12, writes=2, shape=mutable_owner
- `wm/src/picture_in_picture_controller_ani.cpp` `mainWindowXComponentController_`: 14 candidate(s), reads=12, writes=2, shape=mutable_owner
- `interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_listener.cpp` `eventHandler_`: 13 candidate(s), reads=12, writes=1, shape=mutable_owner
- `interfaces/kits/ani/float_view/float_view_ani/src/ani_fv_window_listener.cpp` `eventHandler_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_listener.cpp` `eventHandler_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `window_scene/screen_session_manager/src/fold_screen_controller/super_fold_sensor_manager.cpp` `taskScheduler_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `window_scene/common/src/task_scheduler.cpp` `exportHandler_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `window_scene/session/host/src/move_drag_bounds_applier.cpp` `leashWinShadowSurfaceNode_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `utils/src/ui_effect_controller_common.cpp` `backgroundFilter_`: 5 candidate(s), reads=3, writes=2, shape=mutable_owner
- `utils/src/ui_effect_controller_common.cpp` `effect_`: 5 candidate(s), reads=3, writes=2, shape=mutable_owner
- `window_scene/session/host/src/move_drag_bounds_applier.cpp` `shadowSurfaceNode_`: 5 candidate(s), reads=4, writes=1, shape=mutable_owner
- `window_scene/common/src/extension_data_handler.cpp` `eventHandler_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner

## Boundary

- Source is read from local pinned Git objects; no fetch or checkout.
- Candidates remain `candidate/unassessed`; no product entry or CIA claim.
- This triage does not rewrite the historical 229/208 records.
