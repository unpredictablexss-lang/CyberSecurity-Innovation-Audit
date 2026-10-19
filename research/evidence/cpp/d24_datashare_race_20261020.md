# D24 — DataShare shared_ptr race replay

## Result

**No detector change.** The source-bound A0 family does not establish unsynchronized concurrent access to the same `std::shared_ptr` object. The current M2 adapter executes the C++ detector per source file, so declaration and access patterns split between headers and implementation files are not combined by the production CLI. A standalone direct call over combined units is outside that execution path and produced broad lexical candidates; it is not valid evidence to widen the production rule.

All eight A0 rows remain `not_testable / paused_pending_evidence`. This replay does not establish race existence, safety, thread routing, a target build, attacker-controlled scheduling, or CIA impact.

## Source and queue binding

- Project: `openharmony/distributeddatamgr_data_share`
- Commit: `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`
- Tree: `f731230c116c94d7619f5514c828b33ffac69924`
- Queue rows: CR-0005–CR-0012 from the frozen A0 queue. The exact row fields, blob IDs, SHA-256 values, and unchanged statuses are in [machine-readable evidence](d24_datashare_race_20261020.json).
- The project checkout's `.git/config` and object symlinks are unusable on this Windows host. The commit/tree and all five target header blobs were verified through the local repo object database at `.repo/project-objects/distributeddatamgr_data_share.git`; a temporary checkout was created from that object database and removed after replay. All eight target files in the synchronized source checkout also matched the A0 blob IDs and SHA-256 values.

## CLI replays

Both runs used `ohscanner.cpp.shared_ptr_race` **0.5.1**, profile `light-ast`, at the pinned commit. The CLI explicitly reports candidates only.

| Scope | Files | Parsing | Candidates | Time |
|---|---:|---:|---:|---:|
| Five A0 header files | 5 | 5 complete | 5 | 0.0313 s |
| Five headers plus five implementation files | 10 | 10 complete | 5 | 0.1509 s |

The five header candidates were at `datashare_ani.h:84,90,91` and `datashare_stub_impl.h:35,42`. The latter two are `uvQueue_` initializations and are outside the CR-0012 target member (`extension_`, line 33); they are incidental findings in the selected header. The bounded replay retained these same five findings. None demonstrates a conflicting same-object access pair. Exact CLI JSON outputs are [header baseline](d24_datashare_race_headers_20261020.json) and [bounded replay](d24_datashare_race_bounded_20261020.json).

The source audit found:

- `ANIDataShareObserver::observer_`, `NAPIDataShareObserver::observer_`, and `ObserverImpl::dataShareObserver_` are initialized in constructors and read from callbacks; no assignment/reset to the same shared pointer was found in the selected implementation files. Callback thread context is not established.
- `DataProxyHandleHolder` initializes its two pointers, then resets them in its destructor. ANI bridge methods later read them through an opaque holder pointer. Whether destruction can overlap a bridge call depends on wrapper lifetime/thread scheduling not established by this source-only review.
- `ResultSetHolder::resultSetPtr_` is initialized in the header, read by many ANI methods, and reset by `Close()` in `datashare_ani.cpp`. These accesses split across two files. The current M2 adapter analyzes each file separately, so the CLI does not report a combined access pair. Cross-language wrapper lifetime and whether calls can overlap were not verified.
- `DataShareStubImpl::extension_` is constructor-initialized and returned by `GetOwner()`; no mutation of the member was found. Its method calls are protected by other per-call mutex uses in selected operations, but construction/destruction ordering and complete product threading remain outside this bounded source review.

These are source-level access facts, not race findings or safety conclusions. No target-derived harness or TSan run was performed because the target scheduling/build facts needed to construct one are absent.

## Verification

- `python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -v`: **39 passed** before edits; no detector or test changes retained.
- Source commit/tree, target blob IDs, source hashes, and original queue statuses: verified by [D24 verifier](verify_d24_datashare_race.py).
- Change-scope and `git diff --check` results are recorded at handoff after the evidence files are frozen.

## Reproduction commands

The CLI runs used an exact temporary checkout populated from the local project object database; that scratch checkout was removed after capture. With a normal local checkout of the pinned commit, the commands are:

```powershell
python -m src.cli ohscan-run --repo-dir <pinned-data-share-checkout> --repository openharmony/distributeddatamgr_data_share --commit 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd --include frameworks/ets/ani/include/ani_observer.h --include frameworks/ets/ani/include/datashare_ani.h --include frameworks/js/napi/dataShare/include/napi_datashare_observer.h --include frameworks/native/consumer/include/datashare_helper_impl.h --include frameworks/native/provider/include/datashare_stub_impl.h --detector ohscanner.cpp.shared_ptr_race --json-out d24_headers.json
```

The bounded replay additionally included `frameworks/ets/ani/src/cxx/ani_observer.cpp`, `frameworks/ets/ani/src/cxx/datashare_ani.cpp`, `frameworks/js/napi/dataShare/src/napi_datashare_observer.cpp`, `frameworks/native/consumer/src/datashare_helper.cpp`, and `frameworks/native/provider/src/datashare_stub_impl.cpp`.

The next evidence needed before target-derived concurrency validation is product build configuration and wrapper/ANI scheduling or lifetime guarantees for the opaque holder calls. Keep the queue obligations open until that evidence exists.
