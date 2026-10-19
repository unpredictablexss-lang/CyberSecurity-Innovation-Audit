# A-line parallel queue addendum — D52

### D52 — global_i18n CR-0255–CR-0256 shared_ptr assessment (development)

```text
Role: A-line C/C++ shared_ptr race detector developer.
Continuous goal: assess the bound shared_ptr candidates and improve generalized rule coverage only when a concrete miss reproduces.
Input: frozen A0 CR-0255/CR-0256; global_i18n commit/tree/blob/source hashes; current shared_ptr_race CLI.
Steps: bind both reported headers, replay the detector on headers and production implementation context, inspect initialization/mutation/access and ANI target context, then classify any apparent miss as an actual rule gap or unresolved concurrency/build evidence.
Done when: source identity, current CLI outcomes and access model are independently reproducible; A0 remains immutable; unresolved product/runtime proof remains PARTIAL/BLOCK.
Boundary: no API/schema/Catalog/A0 edits; no detector change absent generalized repro; zero findings are not safety evidence.
```

D52 completed a no-change source-bound review. The exact A0 rows are `not_testable / paused_pending_evidence`. Both reported headers parse completely with `ohscanner.cpp.shared_ptr_race` 0.5.1 and produce zero diagnostics; a second replay including their production ANI implementations also parses all four files completely and produces zero diagnostics. The member assignments occur during object creation and the inspected methods subsequently read them. No concrete generalized detector gap was reproduced. GN names `i18n_ani` and `intl_ani` shared-library targets, but product selection, ANI lifetime/threading, unordered same-object overlap, and impact remain unknown. Preserve PARTIAL/BLOCK.

See [D52 assessment](d52_global_i18n_sharedptr_assessment_20261029.md), [machine record](d52_global_i18n_sharedptr_assessment_20261029.json), [header CLI](d52_global_i18n_cli_20261029.json), [wide CLI](d52_global_i18n_cli_wide_20261029.json), and [verifier](verify_d52_global_i18n_sharedptr_assessment.py).
