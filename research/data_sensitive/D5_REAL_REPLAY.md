# D5 fixed-source replay

## Current reproduction

D13 retrieved only the manifest-pinned files into the isolated partial clone /tmp/ohscanner-dsoftbus-source and verified both commit/tree objects plus all 44 manifest rows (22 per revision). The D5 replay now reads its exact ten model files directly from this local Git object database; it does not fetch or move refs.

Run once for each commit, using the exact ten --target paths in this document's history and select the matching pinned commit:

    python research/data_sensitive/d5_replay.py --repository openharmony/communication_dsoftbus --commit COMMIT --local-git-store /path/to/communication_dsoftbus/.git --model-version 0.2.0-historical.1 --parser-profile tree-sitter-c-cpp-from-requirements-web --build-profile source-only-no-build-graph --target core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c --target core/transmission/common/src/softbus_message_open_channel.c --target core/transmission/common/include/softbus_message_open_channel.h --target core/transmission/common/include/softbus_app_info.h --target core/common/log/softbus_log.c --target core/common/include/softbus_log.h --target adapter/common/log/softbus_adapter_log.c --target adapter/common/include/softbus_adapter_log.h --target core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_sessionconn.c --target core/common/softbus_property/softbus_feature_config.c --output OUTPUT.json

The report verifies commit/tree, exact target scope, each Git blob, size and SHA-256, and records hashes of both detector implementation files. It cannot silently substitute another source or algorithm.

## Latest exact-object result

- Before d33177135ec6c6aaf4a4c42de1f6878652b330e3: detector 0.4.0 / historical model 0.2.0-historical.1, 1 candidate at trans_tcp_direct_message.c:671; 4 files complete and 6 partial; execution status blocked.
- After 63efce3ff7f2708527eb29216decaf5fe2dc33d0: 0 candidates; 4 complete and 6 partial; execution status blocked.
- Both used the same frozen 10-file profile, parser dependencies, and detector implementation hashes. D11's separate manifest-wide 11-source replay still reproduces 1/0 with 5 complete/6 partial per revision.

This is a candidate delta in fixed historical source, not a vulnerability or fix confirmation. The public Runner was not invoked, and partial files keep the aggregate result blocked. validated_vulnerability=0; product H01-H08 remain unproven/not_run.
