# JSProxy shared_ptr / lifetime candidate evidence bundle

## Status

- selected group: `RC-JSPROXY`
- candidate IDs: `7aa20f345a3a8e08566e1b7d2187ff5652e709007c2f1dcae385ce39256548ef, 844d11acd6b225eb4782a2b67c1e8fcc3f5b3c3483d9cbcdf454e821ff9e148c`
- final status: `candidate/unknown`; `validated_vulnerability=0`
- A-line closure: detection facts, source binding, real call path, Harness, PoC, minimal patch and repeated revalidation complete; no confirmed/reportable upgrade.

## Fixed source identity

- repository `openharmony/distributeddatamgr_kv_store`
- commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` / tree `3b92c53fde616d5a3f9487b0c295670a42c63023`
- vulnerable source `frameworks/common/js_proxy.h` blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`

## Real call path

- ArkTS/JS SingleKVStore.getResultSet -> JsSingleKVStore::GetResultSet -> NapiQueue::AsyncWork execute -> ctxt->resultSet->SetInstance(kvResultSet) [js_single_kv_store.cpp:1190-1203]
- ArkTS/JS KVStoreResultSet.getEntry -> JsKVStoreResultSet::GetEntry -> GetInstance() [js_kv_store_resultset.cpp:269-277]
- ArkTS/JS SingleKVStore.closeResultSet -> JsSingleKVStore::CloseResultSet -> NapiQueue::AsyncWork execute -> GetInstance(); SetInstance(nullptr); kvStore->CloseResultSet(resultSet) [js_single_kv_store.cpp:1239-1247]
- NapiQueue::AsyncWork schedules execute through napi_create_async_work and napi_queue_async_work_with_qos [napi_queue.cpp:100-123]
- JSProxy<T>::SetInstance writes instance_ and GetInstance copies instance_ without synchronization [js_proxy.h:35-42]

## Entry, trigger, sensitive operation and CIA

- entry: same application's ArkTS/JS SingleKVStore and KVStoreResultSet API; object is produced by getResultSet and used by synchronous result-set methods
- permission boundary: partial (not proven; the observed owner object is process-local)
- sensitive operation: kvStore->CloseResultSet(resultSet) races the result-set read path through the same JSProxy owner; this reaches the native result-set lifetime/close operation.
- availability: candidate: process-level undefined behavior or denial of service; TSan race proven, stable crash not proven
- integrity: unknown: shared_ptr/control-block corruption or incorrect result access is possible but not demonstrated
- confidentiality: not claimed: no cross-app or cross-device data exposure evidence

## CWE / CVE

- primary: CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization
- possible consequence: CWE-416: Use After Free (only a possible consequence; no product UAF proof)
- CVE: none identified/assigned in the local evidence; no CVE mapping fabricated

## Scope and handoff

- modules: frameworks/common/js_proxy.h, frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp, frameworks/jskitsimpl/distributedkvstore/src/js_kv_store_resultset.cpp, frameworks/jskitsimpl/distributedkvstore/src/napi_queue.cpp
- branches: unknown; local refs do not prove branch membership
- versions: affected version/branch claim not upgraded; audited snapshot is exact
- A-line detection facts, Harness, PoC, patch revalidation and method notes are complete; confirmed/reportable status, final report merge and cross-module conclusions remain for project owner review.

## Limitations

- PoC is a self-contained workload around exact Git-blob JSProxy bytes and modeled async CloseResultSet versus sync getEntry; it is not a full OpenHarmony build or a live distributed KV store run.
- ThreadSanitizer proves unsynchronized shared_ptr owner accesses in the modeled call patterns; it does not prove a stable crash, memory corruption, data disclosure, privilege escalation, or exploitable stability.
- The source-visible ArkTS/JS entry is partial; runtime permission enforcement, product module resolution, deployed image/version scope and cross-app/remote attacker control remain unknown.
- fixed_control_mutex is an independently authored safe control; patched_atomic_minimal is a proposed local patch, not an upstream fix.
- CWE-416 is only a possible consequence and remains unproven without product-level use-after-free evidence.
- Git blob payload SHA-256 is canonical; checkout SHA-256 is separately recorded because repository line-ending filters change working-tree bytes.
