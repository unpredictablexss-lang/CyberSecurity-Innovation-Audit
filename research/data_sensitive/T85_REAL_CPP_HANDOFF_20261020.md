# T85 real C++ structural replay — 2026-10-20

Frozen integrated target: `1e3b4c0cf02a1d5b0a817cc86dc746d28751b1e8`, sensitive detector `0.21.2`. Existing T83/D85 worktree was inspected first: only `records/` public-source cache was untracked; no teammate edits were overwritten. The detector/model/common source at that target matches the test tree. Dynamic detector bodies are read directly from exact Git commits while the common frontend/model runtime stays fixed.

## Search and actual selection

Searched existing public OpenHarmony source under `foundation/communication` and `base/security` for password/key/credential combined with `.c_str()`, then for sensitive-name `+=` expressions. This covered DSoftBus, Wi-Fi, NetStack, Bluetooth, certificate framework/manager and DLP code. Many initial hits were fuzz inputs, direct parameter conversions, metadata lengths or anonymization wrappers. Selected complete, unmodified source files with the actual new structures, rather than injecting logs or renaming variables in synthetic derivatives.

| Component | Commit | Tree | Selected scope |
|---|---|---|---|
| `openharmony/communication_wifi` | `e336c82b3b107d87f68c5e0448cc246b50b53b38` | `edd28e23c84d17fa072f8501d7fe3dfbfa55498f` | `wifi_asset_manager.cpp` + its logger header, 27,560 bytes |
| `openharmony/security_certificate_framework` | `e270363a042bf8f0126881c76d1341ad457cc187` | `e69153afa89928e1318d8b36cf37c65386465fe7` | `napi_cert_utils.cpp`, `napi_cert_defines.h`, `cf_log.h`, 81,770 bytes |

`T85_SOURCE_MANIFEST.json` records every full path, Git blob, byte count and SHA-256. Replay resolves each commit tree, each path blob and the actual source bytes independently against that manifest. Repository names come from the existing public-project mapping; exact local objects are verified, not authenticated against a newly contacted remote. Git network/lazy fetch is disabled. No third-party source copy is committed. Headers carry Apache-2.0 notices.

## Same-source comparison

Versions: `6cbec8428a5c6c1ca86aa27b62ddc4ff2d06159f` (0.21.0), `e72855e970405bb8043cf4bb961207848c957a97` (0.21.1), integrated target above (0.21.2).

| Scope | 0.21.0 | 0.21.1 | 0.21.2 | Actual difference |
|---|---:|---:|---:|---|
| Wi-Fi two files | 3 | 3 | 3 | Two candidate source traces improve; no site added/removed |
| Certificate three files | 21 | 21 | 21 | Findings and per-file outcomes identical |

All are default production-detector invocations with unknown-profile heuristic behavior, without adding reviewed sources or alternate logging models. Full findings, obligations, per-file coverage, implementation SHA-256 and source structure locations are in `T85_REAL_CPP_REPLAY.json`.

The Wi-Fi function `WifiAssetAttrAdd` declares `std::string secretWifiDevice` at line 186, performs ten real compound assignments at 187–198 (including `StringToHex(config.preSharedKey)` at 189), then calls `.c_str()` at 205 while constructing an `AssetValue`, and calls `AssetAdd(attr, ...)` at 216. Before D85, the 205/216 candidate chain starts at a heuristic suspected return API named `secretWifiDevice.c_str`. After D85, it retains the source field `config.preSharedKey`, compound assignments, the explicit string receiver, and `secret`/`attr` assignments through the terminal storage call. The corresponding candidate at 189 remains. The rule/file/line sites are unchanged, but the evidence source changes from a guessed API-return origin at 205 to a material-field origin at 189 plus its explicit dependency chain. This direct-detector replay does not calculate Runner diagnostic/occurrence identities. It does not establish that the old heuristic was a true or false vulnerability. This is concrete source-to-sink evidence improvement despite an unchanged count. `AssetAdd` is a storage interface; this replay does not establish that storing a secret there is a security violation.

The certificate sample supplies a useful different semantic control: `CERT_PASSWORD` is defined as the NAPI property key `"password"` in `napi_cert_defines.h:203`. `napi_has_named_property` at utils line 342 and a `LOGE` error at 349 consume that property name. Both still produce unresolved-escape candidates from the heuristic `CERT_PASSWORD.c_str` source. The property key is not the property value. This exact object-bound observation was sent to D86; it is a future binding/triage question, not permission to suppress arbitrary hardcoded-password content. The short `LOGE` macro is not a configured generic log sink; the 349 finding is explicitly an unresolved-call escape. Its actual wrapper and format position are preserved in the selected `cf_log.h`.

## Coverage and interpretation

Wi-Fi frontend: 2 complete files; certificate frontend: 2 complete / 1 partial. Every detector file outcome remains partial and both aggregate statuses remain `blocked`. The model is unknown-profile heuristic; preprocessing, overloaded/indirect calls, helper/type identity and boundaries remain incomplete. Whole-file inclusion is not whole-component/build coverage. There are no independent vulnerability labels, no precision/recall figures, and no target build, device execution or product-impact claim.

## Reproduce

Python: `D:/openHarmonyScanner/.venv-c-line/Scripts/python.exe` (3.13.9). From this test worktree:

```text
research/data_sensitive/T85_real_cpp_replay.py --wifi-git-dir D:/openHarmonyScanner/tmp/t53-wifi-source-20261028/.git --cert-git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/security_certificate_framework.git --output research/data_sensitive/T85_REAL_CPP_REPLAY.json
```

The script accepts `--extra-detector-commit <full SHA>` to compare a subsequent fixed development body on the same verified inputs. It refuses source/tree/blob drift or shared-runtime changes relative to the frozen integrated target. Existing Git objects are required; it does not silently fetch missing objects or execute the analyzed source.
