# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/multimedia_camera_framework`
- Pinned commit: `35445b57d739a41cb916330935e61f1e83d982ca`
- Git tree: `2907d1748b46897c49c8f8c253c49384294a6a7a`
- Snapshot SHA-256: `5962dc4bec042a75fdb779176bbaf3497c792c545fed86d96203d6e15ab156f9`
- Source files indexed: 13
- Parsing coverage: `{"complete": 13}`
- Detector runs: 1
- Total unverified diagnostics: 13
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | blocked | 13 | 12 | 1 | 0 | 13 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:bcf863af185f0d70` | `frameworks/taihe/include/camera_auto_ref_taihe.h:27` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a2050b7fd2c9175a` | `frameworks/taihe/include/camera_auto_ref_taihe.h:43` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:4d2034de780a2ef1` | `frameworks/taihe/include/camera_auto_ref_taihe.h:48` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ff05e7a3b49ec12d` | `frameworks/taihe/include/camera_auto_ref_taihe.h:52` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2092ac90185d02b3` | `mediastream/include/buffer/buffer_wrapper_base.h:47` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:63d2f5815d82469c` | `mediastream/include/buffer/buffer_wrapper_base.h:122` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:afe5c40a97a3033b` | `mediastream/include/buffer/buffer_wrapper_base.h:127` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:96ac764c4bb65ac3` | `moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h:75` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:95ff2f93c5b57455` | `moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h:81` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a341e991e1a360ea` | `moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h:86` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c92bcec702e1c1ca` | `moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h:87` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ca35dc8f874eef8c` | `services/camera_service/include/camera_rotate_strategy_parser.h:40` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:96922f477e039b6b` | `services/camera_service/include/camera_rotate_strategy_parser.h:48` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.shared_ptr_race`: partial, 12/13 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_auto_ref_taihe.h: frameworks/taihe/include/camera_auto_ref_taihe.h: shared_ptr member 'callbackRef_' occurrence at line 36 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_auto_ref_taihe.h: pairwise analysis of 'frameworks/taihe/include/camera_auto_ref_taihe.h::AutoRef::callbackRef_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_auto_ref_taihe.h: partial; no safety verdict.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_event_listener_taihe.h: modeled non-atomic accesses to 'frameworks/taihe/include/camera_event_listener_taihe.h::Ani::CameraAniEventListener::eventListenerMap_' are read-only and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/picker/camera_picker_taihe.h: modeled non-atomic accesses to 'frameworks/taihe/include/picker/camera_picker_taihe.h::Ani::CameraPickerJsAsyncContextImpl::asyncCtx_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: interfaces/inner_api/native/camera/include/session/capture_session.h: all potential conflicting access pairs to 'interfaces/inner_api/native/camera/include/session/capture_session.h::OHOS::CaptureSession::preconfigProfiles_' share reliable lexical mutex 'preconfigProfilesMutex_'; pairwise suppression is limited to this translation unit and lexical lock model.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/js/camera_napi/include/camera_napi_event_listener.h: modeled non-atomic accesses to 'interfaces/kits/js/camera_napi/include/camera_napi_event_listener.h::OHOS::CameraNapiEventListener::eventListenerMap_' are read-only and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/js/camera_napi/include/camera_napi_param_parser.h: modeled non-atomic accesses to 'interfaces/kits/js/camera_napi/include/camera_napi_param_parser.h::OHOS::CameraNapiParamParser::asyncFunction_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: mediastream/include/buffer/buffer_wrapper_base.h: pairwise analysis of 'mediastream/include/buffer/buffer_wrapper_base.h::OHOS::BufferWrapperBase::encodedBuffer_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h: 1 potential conflicting pair(s) for 'moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h::OHOS::UnifiedPipelineAudioCaptureWrap::audioCapturer_' share reliable lexical mutex 'audioCapturerMutex_'; remaining pairs were not suppressed.
- `ohscanner.cpp.shared_ptr_race`: moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h: modeled accesses to 'moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h::OHOS::MyAudioCapturerMetaDataCallback::wrapPtr_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h: modeled accesses to 'moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h::OHOS::MyAudioCapturerReadCallback::wrapPtr_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h: pairwise analysis of 'moviefile/include/pipeline/producer/unified_pipeline_audio_capture_wrap.h::OHOS::UnifiedPipelineAudioCaptureWrap::audioCapturer_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: services/camera_service/include/camera_rotate_strategy_parser.h: pairwise analysis of 'services/camera_service/include/camera_rotate_strategy_parser.h::OHOS::CameraRotateStrategyParser::curNode_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `135e860a3654395a6d591e9fe7c47ccd94b990a70f2afef6fbbc836dd53bb102`
- Language matching plans attempts; actual coverage remains in the results above.
