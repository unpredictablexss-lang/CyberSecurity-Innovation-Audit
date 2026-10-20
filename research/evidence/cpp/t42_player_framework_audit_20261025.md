# T42 — player_framework IPC candidate audit (CR-0174–CR-0196)

- Scanner baseline: `3ce72e3bcbd0bb534a4daab1bd16fa08bf30bc7e`; component commit/tree: `71ab1e0881e0a79f2b9528742677467e7bb8dde5` / `9cc6c53506a70424485885c4c10b29dfbfaa8d1b`.
- Current production IPC CLI: `completed_with_limitations`, 24 diagnostics, 23/23 exact A0 position matches; parse counts `{'complete': 1, 'partial': 10}`; detector coverage `partial`.
- A0 source IDs: 23/23 source identities verified; every row remains `not_testable / paused_pending_evidence`.
- Source counterevidence: all 23 claimed dispatcher positions have a `ReadInterfaceToken` plus exact `Stub::GetDescriptor()` equality guard before dispatch; the commit-bound `CHECK_AND_RETURN_RET_LOG` macro returns when the condition fails. Thus the specific `descriptor-boundary` root is contradicted by source. This is not product safety confirmation.
- Classification: `PARTIAL/BLOCK`; no vulnerability confirmed. The scanner run is parser-partial (10/11 files), and product inclusion, caller capability/reachability and effective policy are unbound.

## Per-ID current CLI replay

| A0 ID | Source location | Finding | Parse scope | A0 state |
|---|---|---|---|---|
| CR-0174 | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp:55` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:69862a19b285f208` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0175 | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp:69` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:0a18d344f489fdb7` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0176 | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp:75` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:f4a4d04093c25644` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0177 | `services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp:48` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:43e8a27f1a7e651f` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0178 | `services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp:59` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:8ceef15520c9e709` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0179 | `services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp:48` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:e0c83313013ccb3a` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0180 | `services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp:59` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:1a9ffa86a5eac23f` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0181 | `services/services/media_source/ipc/media_source_loader_stub.cpp:61` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:2e6de3ec8ffac2ad` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0182 | `services/services/media_source/ipc/media_source_loader_stub.cpp:75` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:102652a18e89ee97` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0183 | `services/services/media_source/ipc/media_source_loader_stub.cpp:82` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:0e0126085ac28c6a` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0184 | `services/services/pcm_output/ipc/pcm_output_callback_stub.cpp:46` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:c373dccca3e20e34` | `complete/analyzed` | `not_testable / paused_pending_evidence` |
| CR-0185 | `services/services/pcm_output/ipc/pcm_output_callback_stub.cpp:56` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:fc5957497aa904dc` | `complete/analyzed` | `not_testable / paused_pending_evidence` |
| CR-0186 | `services/services/player/ipc/player_listener_stub.cpp:50` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:e7bc1e6ffa196304` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0187 | `services/services/player/ipc/player_listener_stub.cpp:61` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:2554eaead15d2b8f` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0188 | `services/services/player/ipc/player_listener_stub.cpp:67` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:21b90abae1437824` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0189 | `services/services/player/ipc/player_listener_stub.cpp:124` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:fcbf595a7d61885c` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0190 | `services/services/player/ipc/player_service_stub.cpp:376` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:59ec084f0a008f99` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0191 | `services/services/recorder/ipc/recorder_service_stub.cpp:215` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:08c6ca5648a924bf` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0192 | `services/services/recorder/ipc/recorder_service_stub.cpp:218` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:4234f4766d6495bb` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0193 | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp:92` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:c19cba72a935afd6` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0194 | `services/services/transcoder/ipc/transcoder_listener_stub.cpp:47` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:fe6d4c1e8570773c` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0195 | `services/services/transcoder/ipc/transcoder_listener_stub.cpp:53` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:7c9a7ed28819d20d` | `partial/partial` | `not_testable / paused_pending_evidence` |
| CR-0196 | `services/services/transcoder/ipc/transcoder_service_stub.cpp:128` | `ipc.relay.descriptor-boundary` `ohscanner.interface.ipc:81789eae6b5ac2b7` | `partial/partial` | `not_testable / paused_pending_evidence` |

An additional CLI candidate at `services/services/media_source/ipc/media_source_loader_stub.cpp:86` is outside CR-0174–0196 and is not counted as an A0 hit.

## IPC flow and authorization review

The exact reviewed guard macro is defined in the same component commit as an early return on failed condition. Listener/helper/PCM/LPP and MediaSourceLoader client-side endpoints are built into the conditional installable `media_client` target; the service-side Player/Recorder/ScreenCaptureMonitor/Transcoder stubs are conditionally compiled into `media_service`. Paired proxies write their interface descriptor and send transaction codes. Recorder's audio-sensitive requests additionally use caller-token AccessTokenKit verification; player records caller UID/PID but the reviewed dispatch has no equivalent per-call AccessToken verification; transcoder records caller PID/UID but no per-call verification was found; ScreenCaptureMonitor has no explicit per-call AccessToken check in this dispatcher. `media_service.cfg` contains process permissions and a CAPTURE_SCREEN ACL, but product-specific inclusion and effective caller policy are not established.

No caller, permission, registration, build-selection or data-flow inference is promoted to a confirmed issue. The full per-ID source/finding/status map and supporting blob/SHA identities are in [the machine record](t42_player_framework_audit_20261025.json); raw CLI output is [here](t42_player_framework_cli_20261025.json).

Rebuild record: `python research/evidence/cpp/t42_player_framework_independent_audit_20261025.py --git-dir <player_framework.git>`; verify record: `python research/evidence/cpp/verify_t42_player_framework_audit_20261025.py --git-dir <player_framework.git>`.
