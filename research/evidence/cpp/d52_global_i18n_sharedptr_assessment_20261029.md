# D52 — global_i18n CR-0255–CR-0256 shared_ptr assessment

## Result

**No detector change. Case disposition: PARTIAL/BLOCK.** The two original A0 rows remain `not_testable / paused_pending_evidence`. The current rule did not reproduce a concrete, generalized detector gap, and the source review does not establish a same-object unordered concurrent access.

## Bound source and replay

- Declared repository: `openharmony/global_i18n`
- Commit: `5e1210b17e720af2748685ee65bd480709c08a52`
- Tree: `80d9a2200344cf348f3dd582c74e8c4aa7ed2969`
- A0 `CR-0255`: `interfaces/ets/ani/i18n/include/simple_number_format_addon.h:35`; blob `23803c9108c4e4c6b88a92ad366b600108a16317`; SHA-256 `588f5783b8be2b3c1b49874e43464dce8c750cb340437f334053b57a665d4289`.
- A0 `CR-0256`: `interfaces/ets/ani/intl/include/number_format_addon.h:38`; blob `216b68e9e1ba22c1c478b5966ebc713fe00e5bfe`; SHA-256 `a2548ed27d5e424132a1ed16cde48fdedb1e85dc89f504ab86f7267f57a20389`.
- Detector: `ohscanner.cpp.shared_ptr_race` 0.5.1.
- Header-only CLI: both files parse completely; 0 diagnostics. Snapshot SHA-256 `5e939a0ba39ed1044cc83ea79e0530a40716d505ba34773d9d53421ef7ac8e8f`. See [raw CLI JSON](d52_global_i18n_cli_20261029.json).
- Extended CLI including each header and its implementation: all four files parse completely; 0 diagnostics. Snapshot SHA-256 `0c3cb2d64e581d9ba8ff6c82adb851f6cb12b270bb17873f7a4e0fa6b5e84607`. See [extended CLI JSON](d52_global_i18n_cli_wide_20261029.json).

## Access and build context

`I18nSimpleNumberFormatAddon::simpleNumberFormat_` is initialized once in `GetSimpleNumberFormatBySkeleton` when the addon object is created, then read by `Format`. `NumberFormatAddon::numberfmt_` is initialized in the two factory methods and read by `NumberFormat_Format`, `NumberFormat_FormatRange`, and `NumberFormat_ResolvedOptions`. The headers expose accessors returning a copied `shared_ptr`; no later member reset or reassignment was found in the scoped implementation files. This source pattern alone does not prove object confinement or concurrency safety.

The corresponding GN declarations include the implementation files in `ohos_shared_library("i18n_ani")` and `ohos_shared_library("intl_ani")`; neither target is marked `testonly`. This identifies declared component targets only. Product configuration, inclusion in a shipping image, ANI object lifetime/thread-affinity guarantees, cross-thread sharing, attacker-controlled overlapping calls, and concrete impact were not established.

## Disposition and reproduction

No rule change or detector regression test was justified: the A0 locations are accessor declarations, while the complete scoped production implementations showed construction-time initialization followed by reads and no conflicting later write. Zero diagnostics are not a safety conclusion. Keep both original A0 IDs and states unchanged; the required missing evidence is product/build selection plus ANI lifetime/threading and same-object overlap/impact evidence.

```powershell
python -m src.cli.main ohscan-run --repo-dir <global_i18n-checkout> --repository openharmony/global_i18n --commit 5e1210b17e720af2748685ee65bd480709c08a52 --include interfaces/ets/ani/i18n/include/simple_number_format_addon.h --include interfaces/ets/ani/intl/include/number_format_addon.h --detector ohscanner.cpp.shared_ptr_race --json-out <header.json> --md-out <header.md>
python -m src.cli.main ohscan-run --repo-dir <global_i18n-checkout> --repository openharmony/global_i18n --commit 5e1210b17e720af2748685ee65bd480709c08a52 --include interfaces/ets/ani/i18n/include/simple_number_format_addon.h --include interfaces/ets/ani/intl/include/number_format_addon.h --include interfaces/ets/ani/i18n/src/simple_number_format_addon.cpp --include interfaces/ets/ani/intl/src/number_format_addon.cpp --detector ohscanner.cpp.shared_ptr_race --json-out <wide.json> --md-out <wide.md>
```

The machine-readable source-binding record is [D52 assessment JSON](d52_global_i18n_sharedptr_assessment_20261029.json); [verifier](verify_d52_global_i18n_sharedptr_assessment.py) checks the pinned objects, source hashes, CLI outcomes, and original A0 rows. This review does not modify the A0 ledger or claim safety.
