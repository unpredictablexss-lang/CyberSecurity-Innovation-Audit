# sample30 diagnostic triage (2026-10-18)

> Delivered diagnostics only; counts are access points, not root causes,
> vulnerabilities or Precision/Recall. Class identity needs the pinned sources.

- Samples: 30 (10 without diagnostics)
- Diagnostics: 345

| Rule | Diagnostics | Repository/file/member groups |
|---|---:|---:|
| `ipc.auth.guard-coverage` | 1 | 1 |
| `ipc.auth.missing` | 4 | 4 |
| `ipc.capability.export` | 14 | 13 |
| `ipc.parcel.copy-range` | 1 | 1 |
| `ipc.relay.descriptor-boundary` | 62 | 43 |
| `ohcpp-shared-ptr-race-candidate-001` | 263 | 72 |

## Top groups

- `openharmony/distributeddatamgr_preferences` `test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp` `preferences_`: 25 diagnostic(s), reads=23, writes=2, samples=[3]
- `openharmony/distributeddatamgr_preferences` `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp` `preferences_`: 25 diagnostic(s), reads=23, writes=2, samples=[3]
- `openharmony/distributeddatamgr_preferences` `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp` `preferences_`: 19 diagnostic(s), reads=17, writes=2, samples=[3]
- `openharmony/distributeddatamgr_preferences` `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp` `Preferences_`: 19 diagnostic(s), reads=17, writes=2, samples=[3]
- `openharmony/arkcompiler_taihe_ffi_gen` `test/ani_image/author/src/ohos.multimedia.image.image.impl.cpp` `m_pdata`: 16 diagnostic(s), reads=11, writes=5, samples=[7]
- `openharmony/hiviewdfx_faultloggerd` `interfaces/innerkits/unwinder/include/dwarf_op.h` `memory_`: 15 diagnostic(s), reads=15, writes=0, samples=[5]
- `openharmony/systemabilitymgr_safwk` `interfaces/innerkits/safwk/expire_lru_cache.h` `data_`: 13 diagnostic(s), reads=13, writes=0, samples=[9]
- `openharmony/hiviewdfx_faultloggerd` `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h` `state_`: 12 diagnostic(s), reads=12, writes=0, samples=[5]
- `openharmony/communication_wifi` `wifi/utils/src/wifi_event_handler.cpp` `eventHandler`: 12 diagnostic(s), reads=10, writes=2, samples=[18]
- `openharmony/distributeddatamgr_preferences` `test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp` `preferences_`: 6 diagnostic(s), reads=4, writes=2, samples=[3]
- `openharmony/communication_wifi` `wifi/utils/src/wifi_event_handler.cpp` `eventRunner`: 6 diagnostic(s), reads=4, writes=2, samples=[18]
- `openharmony/hiviewdfx_faultloggerd` `interfaces/innerkits/backtrace/fp_backtrace.cpp` `maps_`: 5 diagnostic(s), reads=4, writes=1, samples=[5]
- `openharmony/multimedia_camera_framework` `interfaces/kits/js/camera_napi/include/camera_napi_param_parser.h` `asyncFunction_`: 5 diagnostic(s), reads=5, writes=0, samples=[12]
- `openharmony/multimedia_camera_framework` `frameworks/taihe/include/camera_auto_ref_taihe.h` `callbackRef_`: 4 diagnostic(s), reads=2, writes=2, samples=[12]
- `openharmony/multimedia_camera_framework` `moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h` `audioCapturer_`: 4 diagnostic(s), reads=4, writes=0, samples=[12]
- `openharmony/multimedia_camera_framework` `frameworks/taihe/include/camera_event_listener_taihe.h` `eventListenerMap_`: 3 diagnostic(s), reads=3, writes=0, samples=[12]
- `openharmony/multimedia_camera_framework` `interfaces/kits/js/camera_napi/include/camera_napi_event_listener.h` `eventListenerMap_`: 3 diagnostic(s), reads=3, writes=0, samples=[12]
- `openharmony/multimedia_camera_framework` `mediastream/include/buffer/buffer_wrapper_base.h` `encodedBuffer_`: 3 diagnostic(s), reads=1, writes=2, samples=[12]
- `openharmony/ai_intelligent_voice_framework` `services/intell_voice_engine/server/base/engine_util.h` `adapter_`: 3 diagnostic(s), reads=1, writes=2, samples=[14]
- `openharmony/multimedia_player_framework` `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp` `HelperListenerStub::OnRemoteRequest`: 3 diagnostic(s), reads=0, writes=0, samples=[6]

## Boundary

- The 30 pinned source roots are not present locally; no rerun is claimed.
- Grouping uses repository/file/symbol because the delivered diagnostics
  do not carry qualified class identity.
- Candidate counts are not vulnerability counts; `validated_vulnerability=0`.
