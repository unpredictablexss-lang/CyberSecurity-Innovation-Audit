# T24 DataShare race source audit

## Disposition

Source mapping is **PASS** for the eight requested A0 rows: each row binds to the pinned DataShare repository commit/tree and one of five exact blobs. The race cases remain **PARTIAL/BLOCK**. This source review did not establish a same-object cross-thread unordered access pair, but it also did not establish callback teardown quiescence, ANI/Rust opaque-pointer ownership, product thread affinity, or a target runtime profile. The source-only negative is not a safe verdict.

Every source queue row remains `original_status=not_testable` and `queue_status=paused_pending_evidence`. No source status was changed. No TSan or product runtime was built or run.

## Frozen source identity

- Repository: `openharmony/distributeddatamgr_data_share`
- Project path: `foundation/distributeddatamgr/data_share`
- Commit: `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`
- Tree: `f731230c116c94d7619f5514c828b33ffac69924`
- The exact blob and raw SHA-256 for each of the five source files are recorded in the adjacent JSON. They were read from the pinned repo project object database, not copied from a working file.
- The frozen A0 queue is supplied as an external `--queue` argument. It is intentionally not copied into this evidence package.

## Per-row source mapping and concurrency evidence

| A0 row | Source member / operation | Source-level synchronization and current result |
|---|---|---|
| CR-0005 | `ANIDataShareObserver::observer_`; constructor initializes, callback methods read | No post-construction field write was found. Object lifetime through callback teardown and ANI thread affinity remain unknown. No conflicting access evidenced. |
| CR-0006 | `DataProxyHandleHolder::dataProxyHandle_`; constructor initializes, destructor resets, native operations use the opaque holder | No field lock/atomic. ETS DataProxyHandle operations are dispatched through `taskpool.execute`; task scheduling and close/destruction overlap for the same object are unproven. Source-level reset/use edge, not a confirmed race. |
| CR-0007 | `DataProxyHandleHolder::jsProxyDataObsManager_`; initialized and used in observer registration/removal, destructor resets | No field lock/atomic. Callback and teardown ordering needs ANI runtime ownership evidence. Source-level reset/use edge, overlap unproven. |
| CR-0008 | Same `dataProxyHandle_` reset location as CR-0006 | Retain as a separate original row; do not claim an independent defect from a duplicate location. Same unresolved task/lifetime edge. |
| CR-0009 | `ResultSetHolder::resultSetPtr_`; constructor initializes and native result methods read | `Close` assigns null at `datashare_ani.cpp:301`, creating a same-member read/write pair. The reviewed direct result-set wrapper does not establish whether calls can overlap on distinct threads. |
| CR-0010 | `NAPIDataShareObserver::observer_`; constructor initializes, callback methods read | No post-construction write found. NAPI callback lifetime/unregister ordering is not fully established. No conflicting access evidenced. |
| CR-0011 | `ObserverImpl::dataShareObserver_`; constructor initializes, `OnChange` methods read | Observer registry operations use `observerMutex_` and a `ConcurrentMap`; callback/disposal overlap remains unresolved. No conflicting access evidenced. |
| CR-0012 | `DataShareStubImpl::extension_`; constructors initialize, `GetOwner` and request handlers read/use | Request dispatch methods lock `mutex_` around `uvQueue_` calls and use `flag_`; no post-construction `extension_` write found. Queue and destruction semantics still require product evidence. |

The `shared_ptr` control block supports concurrent ownership operations on distinct `shared_ptr` instances; it does not make unsynchronized read/write of the same member object safe. The source contains a concrete `ResultSetHolder::resultSetPtr_` read/write pair and reset/use edges for DataProxyHandleHolder, but the taskpool's same-object scheduling, object lifetime, and actual cross-thread overlap are not proven. Therefore this review records the pair as a race candidate requiring runtime/thread-model evidence, not as a confirmed race.

The ETS helper and DataProxyHandle APIs call `taskpool.execute`; this proves asynchronous dispatch for those entrypoints but not that two calls on the same object run concurrently. The reviewed result-set wrapper directly invokes native methods, so taskpool concurrency is not evidence for CR-0009. In the native provider, `DataShareStubImpl` request methods hold `mutex_` while calling `JsSyncCall`/`StsSyncCall`; the queue routes JS work through `napi_send_event` and STS work through the main `EventRunner`/`EventHandler`, with per-task condition-variable completion and an atomic reference count. These are concrete queue and synchronization facts, not a whole-object thread-safety proof.

## Product and test declarations

At the pinned revision, `interfaces/inner_api/BUILD.gn` includes the native consumer/provider implementation sources in `ohos_shared_library` targets. `frameworks/js/napi/dataShare/BUILD.gn` includes the NAPI observer implementation in the `datashare` shared library. Separate `testonly` / `ohos_unittest` targets include helper, stub, and holder tests. These declarations establish product/test source placement, not runtime concurrency or sanitizer coverage. ANI source inclusion was found in `frameworks/ets/ani/BUILD.gn`; exact runtime profile and thread affinity were not established.

## Continuous test objective and next evidence

Maintain the independent evidence objective: keep these eight source identities and original queue states stable; extend the read/write/lifetime map when new pinned product evidence arrives; only promote a race hypothesis after identifying same-object conflicting accesses and a plausible concurrent schedule; then run the exact product target under a source-bound TSan profile. Until then, `not_testable / paused_pending_evidence` remains the correct queue state.

Required follow-up: bind product build/runtime profiles; establish ANI/Rust holder ownership, taskpool scheduling and destruction ordering (CR-0006–0009); callback-thread and unregister quiescence contracts (CR-0005, 0010, 0011); and `DataShareUvQueue` serialization plus stub destruction behavior (CR-0012). If same-object overlap is excluded by the runtime contract, preserve that as source-bound negative evidence without relabeling the original row as safe.

## Reproduction

Run the source verifier against the full frozen queue and the local OpenHarmony repo object database:

```powershell
python research\evidence\cpp\verify_a_t24_datashare_race_source_audit.py `
  --queue D:\openHarmonyScanner\worktrees\a-t3-acceptance-pr30-20261019\research\deliveries\cpp\a0_triage_20261019\queue.csv `
  --git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_data_share.git
```

The A0 verifier is a separate read-only check of the 345-row frozen queue package. The source verifier validates this audit's eight source identities and state preservation; it does not claim TSan/runtime execution.
