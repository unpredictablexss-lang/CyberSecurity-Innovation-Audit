# D47 current 0.21.0 cross-component repeatability replay

Date: 2026-10-19. Classification: **development regression/performance evidence, not an independent holdout**.

## Frozen scanner and scope

The scan used D branch commit 1f170e0810405974d613bd43e1a5d62817d215a6 with ohscanner.data.sensitive_exposure 0.21.0; source model 0.4.0, source-profile catalog 0.2.0, sink model 0.8.0. Detector and model SHA-256 values are in the machine-readable JSON. All repositories were read at exact Git commits from local object stores or the G-drive mirror. No target source worktree was changed.

| Component | Commit | C/C++ scope files | Candidates | Detector status | Two-run seconds | Peak RSS |
|---|---|---:|---:|---|---:|---:|
| openharmony/communication_dsoftbus | 9f922677e147 | 6 | 5 | blocked | [0.5759576339987689, 0.5498420750009245] | 41,680 KiB |
| openharmony/security_access_token | 3be426c55861 | 440 | 0 | blocked | 3.5496 | 65,772 KiB |
| openharmony/communication_iot_connect | d8c0aef30560 | 542 | 9 | blocked | 6.6539 | 68,876 KiB |
| openharmony/communication_wifi | e336c82b3b10 | 761 | 21 | blocked | 31.6241 | 160,136 KiB |

Every direct scan repeated two rounds with identical source snapshot, finding signature, and coverage. All runs remained blocked; validated_vulnerability=0.

## Observations

- DSoftBus: five unresolved candidates over six selected files; all six files partial. The candidate trace and queue boundary are described in [D46](D46_DSOFTBUS_CROSSFILE.md).
- Wi-Fi: 21 unresolved candidates over the 761-file fixed scope, 31.6241 seconds for two runs and 160,136 KiB peak RSS. The separate Workbench API → Worker → persisted report → source viewer replay repeated twice and retained the data.log.sensitive-value CWE-532 candidate at wifi/services/wifi_standard/wifi_framework/wifi_toolkit/utils/softap_parser.cpp:93; source and viewer SHA-256 both equal 8f4e84d7eb5f86d892b15a2c1423db3260713ae0cf31a36621869321f9eb2388.
- AccessToken: zero candidates across 440 files, but the run is blocked. This is not a clean result or a false-negative label.
- IoT Connect: nine unresolved candidates across 542 files. They are review leads, not nine confirmed vulnerabilities:
- adapter/crypto/mbedtls/iotc_md.c:54 — IsMdLenValid
- adapter/crypto/mbedtls/iotc_md.c:82 — IotcHmacCalc
- adapter/crypto/mbedtls/iotc_md.c:85 — IotcHmacCalc
- core/ble/application/base/ble_session_mngr.c:184 — BleSessKeyGen
- core/ble/application/base/ble_session_mngr.c:310 — BleSessCalHmac
- core/infrastructure/security/security_sess_key.c:119 — SecuritySessKeyGenTransKey
- core/infrastructure/security/security_sess_key.c:121 — SecuritySessKeyGenTransKey
- core/infrastructure/security/security_sess_key.c:164 — SecuritySessKeyGenAuthKey
- core/infrastructure/security/security_sess_key.c:166 — SecuritySessKeyGenAuthKey

## Interpretation and limits

The Wi-Fi rule, AccessToken profile, IoT Connect profile, and DSoftBus profile were all previously used in D development or calibration. These results measure current-version repeatability, execution coverage, workload, and panel source binding; they do not meet D4/D5's independent-label holdout requirement. Candidate-count deltas are not TP/FP/FN. No independent labels were collected, so precision and recall are not estimable.

The findings remain candidate/unknown. The runs do not establish product build inclusion, actual entry/reachability, attacker control, log visibility, CIA impact, affected product versions, or fixed-product retest. The isolated Workbench replay proves the page's API/Worker/report/source-viewer path for the fixed Wi-Fi source, not product vulnerability behavior.

## Reproduction

Run from the repository root with local checkouts containing these pinned commits and the project Python environment:

    .venv-web/bin/python research/data_sensitive/d19_unreviewed_replay.py --repo-dir /path/to/communication_wifi --repository openharmony/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --output-dir /tmp/d47-wifi
    .venv-web/bin/python research/data_sensitive/d19_unreviewed_replay.py --repo-dir /path/to/security_access_token --repository openharmony/security_access_token --commit 3be426c558613e7c7af92a591c2bfaeb6af06b60 --output-dir /tmp/d47-access-token
    .venv-web/bin/python research/data_sensitive/d19_unreviewed_replay.py --repo-dir /path/to/communication_iot_connect --repository openharmony/communication_iot_connect --commit d8c0aef305601770c912dbdedc58a3f1e6efd30c --output-dir /tmp/d47-iot-connect
    PYTHONPATH=. .venv-web/bin/python research/data_sensitive/D40_WIFI_PRESHAREDKEY_PANEL_REPLAY.py --repo-dir /path/to/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --output /tmp/d47-wifi-panel.json

Exact snapshot identities, file-level candidate observations, run hashes, and panel replay signatures are recorded in [D47 JSON](D47_CURRENT_CROSS_COMPONENT_REPLAY.json).
