# T46 — safwk ExpireLruCache independent acceptance CR-0241–CR-0243

All three rows bind to `openharmony/systemabilitymgr_safwk` commit `21c83c874a34e8d28e6a355a3b56e5167252ed27`, tree `e115202d315867371b3b7c885b4f017e10cb163f`, and `interfaces/innerkits/safwk/expire_lru_cache.h` blob `3e004bca071eb51d0e108845addf5ec3e25dbc65`, SHA-256 `9eb5ce4db56c91311de4351d639949d56566733ede610f5039a39ff0148265e3`.

An independent current CLI replay of `ohscanner.cpp.shared_ptr_race` 0.5.1 analyzed the exact header: complete parse, 1/1 file, 194 LOC, zero diagnostics. None of the three A0 lines has a current finding. Raw outputs: [JSON](t46_safwk_expire_lru_cache_cli_20261027.json), [Markdown](t46_safwk_expire_lru_cache_cli_20261027.md).

The A0 rows point to three `data_` mutations: CR-0241 `data_.erase(key)` in `DoRemove` (line 165), CR-0242 `data_.clear()` in `DoClear` (line 171), and CR-0243 `data_.erase(iter->first)` in `DoClearExpiredCache` (line 183). `Remove`/`Clear` take `lock_` before calling their helpers; `DoClearExpiredCache` is called only by `DoAdd`, reached from `Add` after taking the same per-instance mutex. This is source call/lock evidence only; it does not establish product scheduling or a runtime result.

Disposition: `PARTIAL/BLOCK`. The zero findings are not a safety conclusion, and the source review does not establish an unsynchronized same-object race. Preserve all three A0 rows as `not_testable / paused_pending_evidence`. See the [machine audit](t46_safwk_expire_lru_cache_audit_20261027.json), [T45 family audit](t45_safwk_expire_lru_cache_audit_20261027.md), and [verifier](verify_t46_safwk_expire_lru_cache_audit_20261027.py).

Verifier command: `python research/evidence/cpp/verify_t46_safwk_expire_lru_cache_audit_20261027.py --source-repo <safwk exact commit checkout>`.
