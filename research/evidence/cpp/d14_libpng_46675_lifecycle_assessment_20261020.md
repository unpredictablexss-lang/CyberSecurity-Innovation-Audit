# D14 libpng CVE-2026-46675 lifecycle model assessment

Date: 2026-10-20 (Asia/Shanghai)  
Baseline: `a374fc81b3dc07d7e78471cea08bf34b87e2d01e`  
Detector: `ohscanner.cpp.resource_lifetime` `0.4.0`  
Disposition: `PARTIAL/BLOCK`; no detector change justified by available evidence.

## Source-bound root and model boundary

The vulnerable `pngrutil.c` is bound to upstream commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, blob `a4eda54c8cb3d36cf1651dba159067b65030e3aa`, SHA-256 `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e`. The fixed file is bound to commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`, blob `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a`, SHA-256 `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`. The commit parent is `4eeb825ab26605ed34cd74495d4cce920939fe9f`; official commit tree identity is unavailable in this environment. Both byte hashes were rechecked by the D13 full-file replay and the D12 fragment runner. No third-party source is included in this change.

The disclosed state transition is specific: chunk decompression claims `png_ptr->zstream`, feeds input from temporary/read buffers, then releases ownership by setting `zowner` to zero while the zlib stream's `next_in` / `avail_in` may still describe the previous buffer. Later `png_read_IDAT_data` can observe nonzero `avail_in`, skip its refill path and pass a stale input pointer to inflate when `png_read_end` happens before row reads. The fix adds `png_inflate_detach_buffers` and invokes it during claim/release, clearing `next_in`, `avail_in`, `next_out`, and `avail_out`.

This is a cross-function state/ordering bug. The existing A-RES-01 method is local lexical allocation/release/alias state within a function; its evidence contract explicitly leaves cross-function/container transfer unknown. A root-specific interprocedural rule would need to bind zstream field state, ownership changes, caller ordering, the conditional read-before-rows path and the buffer's storage lifetime. The current evidence does not provide a parser-complete or reviewed local contract for that sequence. A generic stale-pointer/field-clearing heuristic would exceed the requested narrow model and could not establish the later use-after-release relation.

## Replay on this baseline

Commands:

```powershell
python research/evidence/cpp/d13_libpng46675_fullfile_replay_20261020.py
python research/evidence/cpp/d12_libpng_function_fragments_20261020.py `
  --33416-vulnerable D:/openHarmonyScanner/tmp/libpng-runtime-cve-2026-33416-20261019/vulnerable `
  --33416-fixed D:/openHarmonyScanner/tmp/libpng-runtime-cve-2026-33416-20261019/fixed `
  --46675-vulnerable D:/openHarmonyScanner/tmp/libpng-ghsa-qvg3-source-20261019/vulnerable-1.6.55 `
  --46675-fixed D:/openHarmonyScanner/tmp/libpng-d13-fixed-source-20261020 `
  --output research/evidence/cpp/d14_libpng_46675_fragment_replay_20261020.json
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v
```

The full-file replay reports `pngrutil.c` partial on both variants (72 parser issues each), detector run `blocked`, zero findings; elapsed times were approximately 0.110s vulnerable and 0.102s fixed. The paired function replay reports six of seven fragments complete and `png_handle_iCCP` partial on each variant; all fragments emitted zero findings. This does not demonstrate a candidate or fixed differential. The full-file JSON is `d14_libpng_46675_fullfile_replay_20261020.json`; fresh paired fragment results are `d14_libpng_46675_fragment_replay_20261020.json`.

The existing focused resource-lifetime suite passed 8/8. Its positive/fixed/safe/unrelated/partial fixtures validate existing local rules only; they are not labeled libpng controls and do not close this case. No libpng-specific synthetic controls were added because no detector rule change or source-derived candidate contract was validated.

## Decision and minimum unblock

No-change is the evidence-supported decision: the exact vulnerable source does not produce a root-cause candidate, but current parse/context limits prevent attributing the miss to a narrow detector-model defect. The exact fixed source's zero findings are not a safe result. Preserve `CVE-2026-46675` as `PARTIAL/BLOCK`.

Next evidence needed before a rule change: (1) complete parse or reviewed bounded-fragment contract for `png_handle_iCCP` and its relevant declarations; (2) source-bound, call/order-aware representation of chunk-buffer release through `png_read_IDAT_data`, including the read-end-before-rows condition; (3) exact vulnerable/fixed, read-rows, malformed-chunk, safe and unrelated controls; and (4) independent replay. Product applicability remains separate and requires selected build and reachable application call path.
