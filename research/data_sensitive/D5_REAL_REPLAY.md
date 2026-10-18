# D5 fixed-source replay

## Intended invocation

`d5_replay.py` is an offline research runner. Invoke it once per commit with
the matching reviewed model version and the exact ten model paths. Example:

```bash
python research/data_sensitive/d5_replay.py \
  --repository openharmony/communication_dsoftbus \
  --commit d33177135ec6c6aaf4a4c42de1f6878652b330e3 \
  --local-git-store /path/to/local/communication_dsoftbus.git \
  --model-version 0.2.0-historical.1 \
  --parser-profile tree-sitter-c-cpp-from-requirements-web \
  --build-profile source-only-no-build-graph \
  --target core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c \
  --target core/transmission/common/src/softbus_message_open_channel.c \
  --target core/transmission/common/include/softbus_message_open_channel.h \
  --target core/transmission/common/include/softbus_app_info.h \
  --target core/common/log/softbus_log.c \
  --target core/common/include/softbus_log.h \
  --target adapter/common/log/softbus_adapter_log.c \
  --target adapter/common/include/softbus_adapter_log.h \
  --target core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_sessionconn.c \
  --target core/common/softbus_property/softbus_feature_config.c \
  --output research/data_sensitive/outputs/d5-old.json
```

Repeat with commit `63efce3ff7f2708527eb29216decaf5fe2dc33d0` and output
`d5-new.json`. The script verifies the requested commit and tree against the
source model, enforces the exact required path set, and verifies each Git blob,
size, and SHA-256 before parsing. It writes a blocked JSON record and exit code
2 for missing objects, input/model mismatch, or Git command failure. It does
not access the network or move a repository ref. The report labels results
`offline_research_only` and explicitly records that the public Runner was not
invoked.

## Current execution status

The source cache `/home/audit/openharmony-targets/communication_dsoftbus` is a
shallow clone at `9f922677e147b939d6db899bde181d609d64711b` and does not contain
the two historical commits. The D5 script has therefore not been able to
replay either revision in this worktree. A separate bare-cache fetch was
attempted from the public upstream and interrupted after the connection
remained pending; no target checkout or ref was changed. The D4 historical
result (old candidate=1, new candidate=0, both blocked/partial) remains prior
evidence, not a D5 rerun. Current D5 dual-version replay is `blocked`, not
passed. Re-run only after an operator supplies or restores a local Git object
store containing both exact commits.

This does not alter the candidate boundary: the historical source trace is
conditional, no product build/runtime was executed, no unauthorized reader was
demonstrated, and `validated_vulnerability` remains 0.
