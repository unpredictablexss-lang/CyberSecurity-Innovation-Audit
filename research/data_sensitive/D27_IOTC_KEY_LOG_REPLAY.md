# D27: IoT Connect derived session key reaches public INFO log

Date: 2026-10-19
Detector: `ohscanner.data.sensitive_exposure` 0.15.0
Classification: source-bound candidate; OpenHarmony product vulnerability remains unknown

## Source and finding

The scan used repository `openharmony/communication_iot_connect` at commit `d8c0aef305601770c912dbdedc58a3f1e6efd30c`, tree `78db4611e16df5ee92328ceecf6c14baef8cb1a3`. The scanned Git blob for `core/wifi/application/local_control/local_ctl_coap_api.c` is `5b4a715c7ce7906460d2f1d0e089082cd7a92315`, SHA-256 `a3787e925f011e33c1c7f5458c536dd36920f6f1e708ae98cc47f21a6cd897de`. The G-drive worktree has a local modification to this path; the replay reads only the immutable pinned Git commit/blob and does not use or modify the working file.

In `localCtlSessKeyGen`, the pinned source calls `IotcPkcs5Pbkdf2Hmac(&param, localCtlKey, ...)`, converts `localCtlKey` into `localCtlKeyStr` with `UtilsHexify`, then emits `localCtlKeyStr` through `IOTC_LOGI("%s localCtlKey:[%s]", ...)` at line 602. The pinned adapter implements `IOTC_LOGI` through `IotcLogOutputImpl`; the HiLog adapter sends the formatted buffer using `%{public}s`. This is evidence that the exact source path can place the derived bytes in a public INFO log when the relevant build/runtime log levels enable it.

The new exact-revision model treats PBKDF2 argument 1 as key material, follows the reviewed `UtilsHexify` input argument 0 to output argument 2, and recognizes `IOTC_LOGI` only at this file. Same-file definitions invalidate the API summary; wrong arity remains unknown. The change is in `models.py` and the bounded local-flow analyzer; it adds no global frontend facts.

## Validation

The new tests include a positive derived-key-to-public-log case and controls for removed logging, unrelated public identifiers, mismatched commit, and wrong API arity. A repeatable Workbench replay runs the pinned Git source through Catalog, API, Worker, report generation, and source viewing twice. Both runs produced the same candidate identity, source blob/hash, tree, and snapshot. The retained result is one `data.log.sensitive-value` candidate at `local_ctl_coap_api.c:602`; detector status is `blocked`, job status is `completed_with_limitations`, and `validated_vulnerability=0`. Details and raw hashes are in [D27_IOTC_PANEL_REPLAY.json](D27_IOTC_PANEL_REPLAY.json); reproduce with [d27_iotc_panel_replay.py](d27_iotc_panel_replay.py).

## Conclusion and remediation

The source-to-log relation is a confirmed fact for this pinned component source. This does **not** confirm a product vulnerability: the audit found that the logged key uses `ctx->authCodeInfo.authCode`, while the actual `transKey` uses a separate `DevSvcProxyGetAuthInfo()` result. Equality of those authCode values is unknown. Product inclusion, INFO build/runtime configuration, collection/reader permissions, whether the logged value is usable as the session key, and security impact remain unknown. No exploit PoC was run or is claimed.

Recommended remediation for this source shape is to remove the derived-key log statement. If operational diagnostics are required, emit only non-secret event metadata (for example success/failure and a constant operation name), and verify the INFO-disabled and INFO-enabled product builds contain no recoverable key bytes. A product remediation claim still requires the exact product build, caller/path evidence, access-control assessment, and a before/after controlled regression.

Sources: [pinned local-control API](https://gitcode.com/openharmony/communication_iot_connect/blob/d8c0aef305601770c912dbdedc58a3f1e6efd30c/core/wifi/application/local_control/local_ctl_coap_api.c), [pinned HiLog adapter](https://gitcode.com/openharmony/communication_iot_connect/blob/d8c0aef305601770c912dbdedc58a3f1e6efd30c/adapter/log/hilog/iotc_log.c), [pinned logging macro header](https://gitcode.com/openharmony/communication_iot_connect/blob/d8c0aef305601770c912dbdedc58a3f1e6efd30c/adapter/include/iotc_log.h), [OpenHarmony G-drive source review](</mnt/e/读研/网络安全创新大赛/OHScanner_G盘源码漏洞审查记录_20261018.md>).
