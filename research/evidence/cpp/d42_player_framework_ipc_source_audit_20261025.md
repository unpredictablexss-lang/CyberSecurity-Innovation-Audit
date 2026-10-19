# D42 — multimedia_player_framework IPC source audit

- Base: `3ce72e3bcbd0bb534a4daab1bd16fa08bf30bc7e`
- Source: `openharmony/multimedia_player_framework` commit `71ab1e0881e0a79f2b9528742677467e7bb8dde5`, tree `9cc6c53506a70424485885c4c10b29dfbfaa8d1b`
- Scope: 23 A0 IDs in 11 C++ files; production IPC detector 0.12.12.
- Result: 23/23 A0 positions reproduced; 24 total diagnostics (one extra line 86 in media_source_loader_stub.cpp). No vulnerabilities validated.
- Coverage: 1 file complete, 10 partial (`detector_model_incomplete`); `light-ast`, no product build profile.
- Queue remains unchanged: `not_testable / paused_pending_evidence`.

## A0 mapping

| ID | line | current finding | file | blob | SHA-256 |
|---|---:|---|---|---|---|
| CR-0174 | 55 | `ohscanner.interface.ipc:69862a19b285f208` | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp` | `4ba971bc47e269607a7ace05ba6599f9716fb9e6` | `b0abc341d5c0efcabe72bf1b7b82f21288744c31329b09a6c55b202701fc86af` |
| CR-0175 | 69 | `ohscanner.interface.ipc:0a18d344f489fdb7` | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp` | `4ba971bc47e269607a7ace05ba6599f9716fb9e6` | `b0abc341d5c0efcabe72bf1b7b82f21288744c31329b09a6c55b202701fc86af` |
| CR-0176 | 75 | `ohscanner.interface.ipc:f4a4d04093c25644` | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp` | `4ba971bc47e269607a7ace05ba6599f9716fb9e6` | `b0abc341d5c0efcabe72bf1b7b82f21288744c31329b09a6c55b202701fc86af` |
| CR-0177 | 48 | `ohscanner.interface.ipc:43e8a27f1a7e651f` | `services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp` | `e130c8835343f8d9df265bde1c23a6ae86bf0590` | `275ab05c4c017d1b0a583ace2b08d87c327e9d61ca6ffb7b403cd41266ebbe5a` |
| CR-0178 | 59 | `ohscanner.interface.ipc:8ceef15520c9e709` | `services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp` | `e130c8835343f8d9df265bde1c23a6ae86bf0590` | `275ab05c4c017d1b0a583ace2b08d87c327e9d61ca6ffb7b403cd41266ebbe5a` |
| CR-0179 | 48 | `ohscanner.interface.ipc:e0c83313013ccb3a` | `services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp` | `87b2bb47fa59ecf6453db6a25b96208974269a6e` | `56428347857ecd879c68a1d8551efeddbe1d8a2453a971365bc38d20de37b273` |
| CR-0180 | 59 | `ohscanner.interface.ipc:1a9ffa86a5eac23f` | `services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp` | `87b2bb47fa59ecf6453db6a25b96208974269a6e` | `56428347857ecd879c68a1d8551efeddbe1d8a2453a971365bc38d20de37b273` |
| CR-0181 | 61 | `ohscanner.interface.ipc:2e6de3ec8ffac2ad` | `services/services/media_source/ipc/media_source_loader_stub.cpp` | `119887d6560d10115f817e9ddacbc17e971050c5` | `ea101e1addc925f8059104aa706ba585f12e054c8a47209993d7c1ad2eb769ed` |
| CR-0182 | 75 | `ohscanner.interface.ipc:102652a18e89ee97` | `services/services/media_source/ipc/media_source_loader_stub.cpp` | `119887d6560d10115f817e9ddacbc17e971050c5` | `ea101e1addc925f8059104aa706ba585f12e054c8a47209993d7c1ad2eb769ed` |
| CR-0183 | 82 | `ohscanner.interface.ipc:0e0126085ac28c6a` | `services/services/media_source/ipc/media_source_loader_stub.cpp` | `119887d6560d10115f817e9ddacbc17e971050c5` | `ea101e1addc925f8059104aa706ba585f12e054c8a47209993d7c1ad2eb769ed` |
| CR-0184 | 46 | `ohscanner.interface.ipc:c373dccca3e20e34` | `services/services/pcm_output/ipc/pcm_output_callback_stub.cpp` | `f100ad0af6c2d8f889b5424e4ba5e710b595f399` | `0e0292b7e4c28d6d3b63accd8e10f053b224849ebf74edf4f9011318e47d540c` |
| CR-0185 | 56 | `ohscanner.interface.ipc:fc5957497aa904dc` | `services/services/pcm_output/ipc/pcm_output_callback_stub.cpp` | `f100ad0af6c2d8f889b5424e4ba5e710b595f399` | `0e0292b7e4c28d6d3b63accd8e10f053b224849ebf74edf4f9011318e47d540c` |
| CR-0186 | 50 | `ohscanner.interface.ipc:e7bc1e6ffa196304` | `services/services/player/ipc/player_listener_stub.cpp` | `f1e35bca24172ade9b33d5262d923334f7301e08` | `788c307868be7caf7654fcf4b7088b9c3ab10374881912c9e92c62c23d1d7c2e` |
| CR-0187 | 61 | `ohscanner.interface.ipc:2554eaead15d2b8f` | `services/services/player/ipc/player_listener_stub.cpp` | `f1e35bca24172ade9b33d5262d923334f7301e08` | `788c307868be7caf7654fcf4b7088b9c3ab10374881912c9e92c62c23d1d7c2e` |
| CR-0188 | 67 | `ohscanner.interface.ipc:21b90abae1437824` | `services/services/player/ipc/player_listener_stub.cpp` | `f1e35bca24172ade9b33d5262d923334f7301e08` | `788c307868be7caf7654fcf4b7088b9c3ab10374881912c9e92c62c23d1d7c2e` |
| CR-0189 | 124 | `ohscanner.interface.ipc:fcbf595a7d61885c` | `services/services/player/ipc/player_listener_stub.cpp` | `f1e35bca24172ade9b33d5262d923334f7301e08` | `788c307868be7caf7654fcf4b7088b9c3ab10374881912c9e92c62c23d1d7c2e` |
| CR-0190 | 376 | `ohscanner.interface.ipc:59ec084f0a008f99` | `services/services/player/ipc/player_service_stub.cpp` | `2c2c0c6ca1bc22be74b45fd3689c3069c428e912` | `479d554f58f059143ce595521d6c6e40f832b6b49b673ba836cf363ce09de746` |
| CR-0191 | 215 | `ohscanner.interface.ipc:08c6ca5648a924bf` | `services/services/recorder/ipc/recorder_service_stub.cpp` | `86a0a21d700fa7a7db5ad0a063c31c155eed9477` | `30ca38f8cb2372ed82bb666714593a629dc929bc67c5b4c21edc5bf3ed2f84ad` |
| CR-0192 | 218 | `ohscanner.interface.ipc:4234f4766d6495bb` | `services/services/recorder/ipc/recorder_service_stub.cpp` | `86a0a21d700fa7a7db5ad0a063c31c155eed9477` | `30ca38f8cb2372ed82bb666714593a629dc929bc67c5b4c21edc5bf3ed2f84ad` |
| CR-0193 | 92 | `ohscanner.interface.ipc:c19cba72a935afd6` | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp` | `5ed6d58d83bc4202640a47f54fe9745a75c0c87b` | `17e35cd20fdfe6bdff9710244067b1f18b994c476e89816d4cf0b6accf2aa196` |
| CR-0194 | 47 | `ohscanner.interface.ipc:fe6d4c1e8570773c` | `services/services/transcoder/ipc/transcoder_listener_stub.cpp` | `aaf0f3d72f625ed46742ba01915af4c31fb7e8e9` | `7b53294897ae58d20c047c705f62b1d7ad45d8140bbbf5a0db455ecf409c65fd` |
| CR-0195 | 53 | `ohscanner.interface.ipc:7c9a7ed28819d20d` | `services/services/transcoder/ipc/transcoder_listener_stub.cpp` | `aaf0f3d72f625ed46742ba01915af4c31fb7e8e9` | `7b53294897ae58d20c047c705f62b1d7ad45d8140bbbf5a0db455ecf409c65fd` |
| CR-0196 | 128 | `ohscanner.interface.ipc:81789eae6b5ac2b7` | `services/services/transcoder/ipc/transcoder_service_stub.cpp` | `02c7ef4401b40b16418f28ad060f0c3236c968a9` | `4dc2a6b1513194f574d5bb8920d056fd95701a6a32b2d5e8bd4e8b9d626ee452` |

## Source review

All 11 scoped Stub implementations read the interface token and compare against the class GetDescriptor before dispatch. Their headers derive from IRemoteStub<IStandard...>. A second CLI run including those 11 headers retained the same 24 diagnostics. This contradicts the missing-descriptor wording of the candidate, but does not establish caller authorization or exploitability.

Recorder OnRemoteRequest checks calling-token permissions for AUDIO_REQUEST and conditional COMMON_REQUEST, returning MSERR_NO_PERMISSION on denial. CR-0191/0192 are CheckPermission callsites.

Module source creates several service Stub objects, returns AsObject(), and tracks creating PID/UID; listener objects can be installed through SetListenerObject/SetPCMCallback. Product SA publication/configuration and shipped build reachability remain unknown.

Listener transactions read payload fields and call registered callbacks after token/code dispatch. Service Stubs dispatch transaction maps to member functions. Parcel input order is transaction-specific; no runtime malformed-input validation performed.

No CanRequest occurrence in the 11 A0-selected files.

## Disposition

`PARTIAL/BLOCK`. No fixed-source pair or product-level caller/SA/build/reachability/impact evidence is bound. Do not change A0 statuses. The explicit token checks conflict with the finding text, so request IPC owner review; this A line did not alter B-owned detector code. The extra line 86 remains an out-of-A0 observation.

## Artifacts

- Primary raw CLI JSON: `research/evidence/cpp/d42_player_framework_cli_20261025.json`
- Headers-context raw CLI JSON: `research/evidence/cpp/d42_player_framework_cli_with_headers_20261025.json`
- Structured report: `research/evidence/cpp/d42_player_framework_ipc_source_audit_20261025.json`
- Structured task prompt: `research/evidence/cpp/d42_player_framework_ipc_prompt_20261025.md`
- Verify: `python research/evidence/cpp/verify_d42_player_framework_ipc.py --git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/multimedia_player_framework.git`
