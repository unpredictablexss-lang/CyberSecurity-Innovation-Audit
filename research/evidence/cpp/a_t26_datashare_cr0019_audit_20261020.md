# T26 independent audit: DataShare CR-0019

## Result

The queue-bound source identity matches the frozen A0 row: `openharmony/distributeddatamgr_data_share`, commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`, tree `f731230c116c94d7619f5514c828b33ffac69924`, source blob `fa48e35a0fab0dbc776fb98b7f162c6f62432842`, SHA-256 `0b48c5461891d336a34d6d0f2e458ed3f2d175aaa1980fe7c351080c0e5cc6e2`.

`ProxyDataObserverStub` implements `IRemoteStub<IProxyDataObserver>`, whose declared descriptor is `OHOS.DataShare.IProxyDataObserver`. In `OnRemoteRequest`, however, the token is compared against `PublishedDataObserverStub::GetDescriptor()` (`OHOS.DataShare.IDataProxyPublishedDataObserver`) before request-code and payload checks. The two interface descriptors differ. The current IPC detector independently emitted a syntax candidate at line 222 with rule `ipc.relay.descriptor-boundary`.

This establishes a source-level interface-token mismatch candidate. The manager constructs this stub as an `IProxyDataObserver` and the service proxy registers its remote object. The same-commit decoder bounds payload length and checks failed raw-data reads; callback use is protected by a mutex. These facts do not establish a reachable exploit or concrete CIA impact. In particular, there is no bound product profile, live observation of the callback token sent by the remote peer, complete service authorization chain, build, or runtime test. The CLI selected five source files, four parsed completely and `data_proxy_observer.h` parsed partial. No fixed object is bound. Disposition remains `PARTIAL/BLOCK`; original A0 states remain `not_testable / paused_pending_evidence`.

## Reproduction and checks

- CLI command and raw reports: `a_t26_datashare_cr0019_cli_20261020.json` and `.md`.
- Source/queue/CLI verifier: `python research/evidence/cpp/verify_a_t26_datashare_cr0019_audit.py --source-git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_data_share.git --queue-json research/deliveries/cpp/a0_triage_20261019/queue.json --cli-json research/evidence/cpp/a_t26_datashare_cr0019_cli_20261020.json`.
- Original A0 verifier: `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`.
- Scope: `python scripts/check_change_scope.py --base 536fd14547ffb825e3c6f3f6f1871b7d8bc2b2bd --lane cpp`.

The audit does not alter detector code, fixtures, or the frozen queue.
