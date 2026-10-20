# D26 — Preferences CR-0020–CR-0021 shared_ptr race replay

## Disposition

**No detector change.** The production M2 CLI emits both source-bound candidates at `js_proxy.h:37` (`SetInstance` write) and `:42` (`GetInstance` read). A bounded replay including both N-API implementation translation units remains complete and emits the same two diagnostics. There is no demonstrated production-path miss for this A0 family.

The findings are syntax candidates only. The source does not establish that a write and read overlap unsynchronized on the same live `PreferencesProxy` object. Both A0 rows remain `not_testable / paused_pending_evidence`; neither candidate is promoted to a confirmed race or safe result.

## Frozen source and A0 rows

- Repository: `openharmony/distributeddatamgr_preferences`
- Commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Tree: `7761d9e273ae7007046ae115797f255e554523ae`
- File: `frameworks/js/napi/common/include/js_proxy.h`
- Blob: `abdd7b2ce3f69528bdaf7234746ca335f329485e`
- SHA-256: `1109ad9bb63edf57c6fd22558cc87b98fea9692889bca6ec4c75269b83339958`
- A0 CR-0020 binds line 37; CR-0021 binds line 42. Both rows retain original `not_testable`, queue `paused_pending_evidence`.

The host component checkout's `.git` metadata is unusable. Replays read only the local project object database at `D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_preferences.git` using `GIT_DIR`; no fetch was used. The current CLI independently reports the frozen commit and tree and the hash above.

## Production M2 replay

Both replays used `ohscanner.cpp.shared_ptr_race` 0.5.1, profile `light-ast`, build profile `none`, through `python -m src.cli.main ohscan-run`.

| Scope | Parse coverage | Diagnostics | Outcome |
|---|---:|---:|---|
| `js_proxy.h` | 1/1 complete | 2 | line 37 write; line 42 read |
| `js_proxy.h` + preferences and sendable Preferences N-API implementations | 3/3 complete | 2 | same two header candidates, no extra member candidate |

The raw results are [header replay](d26_preferences_header_20261020.json) and [bounded replay](d26_preferences_bounded_20261020.json). The snapshot SHA-256 values are recorded in those files; both are tied to the exact commit/tree above.

## Source access and build context

- `JSProxy<T>::SetInstance` assigns the `instance_` shared pointer; `GetInstance` returns a copy. These operations are the actual syntax represented by CR-0020 and CR-0021.
- The pinned `PreferencesProxy` implementation calls `SetInstance(value)` from `NewInstance` after allocating a new proxy, and calls `SetInstance(nullptr)` during destruction. `GetSelfInstance` unwraps the N-API object and returns `obj->GetInstance()`; asynchronous callbacks capture a weak pointer and later call `lock()`.
- Both `frameworks/js/napi/preferences/BUILD.gn` and `frameworks/js/napi/sendable_preferences/BUILD.gn` include their respective `napi_preferences.cpp` in production targets. Thus the bounded replay includes both direct consumer implementation files; it is not a runtime schedule or product build validation.
- No clear later reassignment to an already published proxy instance was established in the reviewed source. Whether finalization can overlap a native method, N-API environment/thread affinity, object publication/lifetime, cross-thread use of one proxy, and the shipped product configuration remain unverified. The source replays cannot prove a race or its absence.

## Verification and remaining evidence

- Source/A0/replay verifier: `python research/evidence/cpp/verify_d26_preferences_race.py --source-git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_preferences.git --queue-json research/deliveries/cpp/a0_triage_20261019/queue.json`.
- Focused tests: `python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector tests.detectors.test_cpp_shared_ptr_guard_lifetime -v`.
- Change scope: `python scripts/check_change_scope.py --base 536fd14547ffb825e3c6f3f6f1871b7d8bc2b2bd --lane cpp`.
- The remaining case work is to bind product build/configuration and N-API thread/finalizer lifetime evidence, then use a realistic TSan/runtime harness if source/build facts justify it. Until then the two A0 statuses remain unchanged.

## Reproduction commands

Run from the D26 scanner worktree in PowerShell (the local component checkout has unusable `.git/config`; use its local object database through `GIT_DIR`):

```powershell
$env:GIT_DIR = 'D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git'
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\openharmony\foundation\distributeddatamgr\preferences --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include frameworks/js/napi/common/include/js_proxy.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d26_preferences_header_20261020.json
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\openharmony\foundation\distributeddatamgr\preferences --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include frameworks/js/napi/common/include/js_proxy.h --include frameworks/js/napi/preferences/src/napi_preferences.cpp --include frameworks/js/napi/sendable_preferences/src/napi_preferences.cpp --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d26_preferences_bounded_20261020.json
Remove-Item Env:GIT_DIR
```
