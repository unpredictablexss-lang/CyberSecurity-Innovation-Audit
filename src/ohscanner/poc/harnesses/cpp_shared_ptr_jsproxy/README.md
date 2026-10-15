# JSProxy shared_ptr race PoC

This harness mirrors the source-visible `JSProxy<T>::SetInstance` / `GetInstance`
owner pair and the asynchronous `CloseResultSet` versus synchronous `getEntry` access
pattern from `distributeddatamgr_kv_store`.

The runner verifies the exact target repository commit/tree/blob plus canonical Git-blob payload and checkout hashes,
builds three source variants, and repeats ThreadSanitizer runs:

- `vulnerable`: exact `frameworks/common/js_proxy.h`;
- `fixed_control_mutex`: independently authored mutex control;
- `patched_atomic_minimal`: proposed `std::atomic_load` / `std::atomic_store` patch.

The result remains `candidate/unknown`; it must not be upgraded to `confirmed/reportable` by this Harness. The workload is local and isolated;
it does not prove product-level privilege escalation, data disclosure, or a
stable exploitable memory-corruption path.


The close_get_entry mode explicitly models the source-visible window where CloseResultSet async execute clears the owner while synchronous getEntry copies it. A clean run is only a narrow repair control; the current component checkout cannot build the complete OpenHarmony product, so product permissions, concrete CIA impact, stable exploitability and cross-module impact remain unknown.
