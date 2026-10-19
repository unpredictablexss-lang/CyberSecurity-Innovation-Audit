# D25 — DataShare CR-0013–CR-0015 shared_ptr race replay

## Disposition

**No production detector change.** The current M2 CLI emits candidates for CR-0013 and CR-0015 at their exact `uvQueue_` constructor assignments. CR-0014 binds to the `extension_` constructor initializer, for which the CLI emits no candidate at that line. Source cross-reference found no later assignment to either member in the bounded component search. `uvQueue_` is read by provider methods and `extension_` is read by `GetOwner()`, but the pinned source does not establish a conflicting post-construction write, a same-object race, or product thread/lifetime facts. The A0 candidates remain unvalidated syntax candidates.

All three original queue rows remain `not_testable / paused_pending_evidence`. This review makes no race-existence, safety, runtime, attacker-control, or CIA-impact claim. The bounded four-file CLI replay has one partial-parsed support file; findings are reported only from the complete scoped header. That limitation remains explicit.

## Frozen source identity

- Repository: `openharmony/distributeddatamgr_data_share`
- Commit: `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`
- Tree: `f731230c116c94d7619f5514c828b33ffac69924`
- A0 rows CR-0013–CR-0015 all bind to `frameworks/native/provider/include/datashare_stub_impl.h`, blob `b3cc65d4a39b596cad57477e30e06bc7a673b37c`, SHA-256 `81df12f7bf672ed146509837fc73c7ad857237d08f47cb4af54341311ebc284c`.
- The local OpenHarmony synchronized checkout had unusable component `.git` links on this host. The replay used the local project object database at `.repo/project-objects/distributeddatamgr_data_share.git`, with no fetch. The verifier independently checks commit, tree, row fields, Git blob IDs, source SHA-256, and bound source lines.

## Current CLI replay

Both replays used `ohscanner.cpp.shared_ptr_race` **0.5.1**, `light-ast`, through the production `ohscan-run` M2 adapter. M2 invokes this detector independently for each complete C++ source file; it does not combine declaration and implementation accesses into one detector invocation.

| Scope | Parse coverage | Candidates | Elapsed |
|---|---:|---:|---:|
| Target header only | 1/1 complete | 2 | 0.0048 s |
| Header, provider implementation, queue header and queue implementation | 3 complete, 1 partial | 2 | 0.0405 s |

Both candidate locations are `datashare_stub_impl.h:35` and `:42`, symbol `uvQueue_`, exactly matching CR-0013 and CR-0015. CR-0014 is `:40`, `extension_` constructor initialization; it is not reported in current output. The bounded run reports the same two header findings and no additional candidate. Raw results: [header baseline](d25_shared_ptr_cr0013_15_header_20261020.json), [bounded replay](d25_shared_ptr_cr0013_15_bounded_20261020.json).

## Source access review

- `DataShareStubImpl` initializes `extension_` in each constructor initializer and initializes `uvQueue_` in the constructor body (`datashare_stub_impl.h:32–42`). A component-wide search of the pinned native provider sources found no later assignment to either member. `GetOwner()` reads `extension_`; provider methods read `uvQueue_` for `JsSyncCall`/`StsSyncCall`.
- The queue implementation synchronizes its per-call `TaskEntry` using that entry's mutex and condition variable. This is not evidence that calls on the same `DataShareStubImpl` cannot overlap, nor is it a guard around a write to the `uvQueue_` member. Conversely, the selected source shows no post-construction member write to conflict with the reads.
- Whether destruction overlaps a method call, when the object is published, and the target service threading/build configuration are not established by these source files. A0 remains `not_testable`; absence of a demonstrated conflict is not a safety result.
- CR-0013/0015 current rule regression: **candidate replay PASS** (the exact source-bound constructor writes are found). Full case disposition: **PARTIAL/BLOCK**. CR-0014 candidate replay: **no candidate at the bound constructor initializer**; case disposition remains **PARTIAL/BLOCK** because the A0 record lacks concurrency, build, reachability, and impact proof.

## Verification

- Source/queue/replay verifier: `python research/evidence/cpp/d25_datashare_cr0013_15_replay_20261020.py --source-git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_data_share.git --queue-json research/deliveries/cpp/a0_triage_20261019/queue.json` — passed.
- `python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector tests.detectors.test_cpp_shared_ptr_guard_lifetime -v` — 49 passed.
- Change scope and `git diff --check` are recorded in the D25 addendum at handoff.

## Reproduction commands

```powershell
python -m src.cli ohscan-run --repo-dir <pinned-local-git-repo> --repository openharmony/distributeddatamgr_data_share --commit 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd --include frameworks/native/provider/include/datashare_stub_impl.h --detector ohscanner.cpp.shared_ptr_race --json-out d25_header.json
python -m src.cli ohscan-run --repo-dir <pinned-local-git-repo> --repository openharmony/distributeddatamgr_data_share --commit 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd --include frameworks/native/provider/include/datashare_stub_impl.h --include frameworks/native/provider/src/datashare_stub_impl.cpp --include frameworks/native/provider/include/datashare_uv_queue.h --include frameworks/native/provider/src/datashare_uv_queue.cpp --detector ohscanner.cpp.shared_ptr_race --json-out d25_bounded.json
```
