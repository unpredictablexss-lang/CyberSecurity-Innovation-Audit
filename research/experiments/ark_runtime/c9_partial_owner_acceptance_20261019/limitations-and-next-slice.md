# C9 partial-owner limitations

- The regression was in the focused bound-target test: a configured but missing external source escaped as `FileNotFoundError`. `parse_functions` itself performs no external source I/O. The test now classifies that condition as `owner_identity=None`, `owner_status=limitation`, `owner_not_visible_in_translation_unit`, `external_context_status=unknown`, and `qualified_name_status=source_spelling_unverified`.
- A missing include is not expanded. The new fixture keeps its owner unresolved; no declaration is guessed from the include name.
- Function-like owner macros, macro-produced qualifiers and conditional compilation remain unknown. The current parser marks macro owner tokens and conditional directives as limitations and never expands them.
- Cross-TU ownership is not inferred. A definition with an owner declaration outside the visible TU remains unknown/limitation.
- Ambiguous namespace/class qualifiers remain unknown/limitation. AST/pattern visibility is not ownership proof.
- Positive namespace/class/function qualifier recovery is source-bound to complete visible AST and source token hashes. It does not prove external declaration ownership, product impact or exploitability.
- `scripts/check_docs_context_budget.py` is absent from this worktree; the attempted command and exact error are retained rather than recorded as a pass.
- The remote-ref `syntax.py`/`unseen_*` code was compared read-only and not imported. Current parser semantics were validated in the current worktree only.
- The source-audit original is now located and hash-bound as a remote pinned object. Its prose rows are reconciled to source identity/rule/control metadata in `source-audit-entry-reconciliation.json`; structured machine import remains `blocked_no_entries` because no explicit `c8-audit-entries` JSON block exists.
- No product vulnerability, validated vulnerability, CIA impact, supported CWE/CVE, Precision/Recall, FP/FN or zero-error metric is claimed.

## Next macro / cross-TU slice

1. Add a function-like owner macro fixture and a conditional-compilation fixture that produce `macro_owner_expansion_unknown` / `conditional_compilation_unknown` without owner guesses.
2. Add two pinned sibling TU fixtures with exact commit/tree/blob/source hashes and include/compile configuration. Resolve owner only when the declaration, include closure and macro configuration are all bound; otherwise retain `owner_not_visible_in_translation_unit` and `external_context_status=unknown`.
3. Add an ambiguous alias/namespace/class qualifier fixture and verify `ambiguous_owner_qualifier`.
4. Keep fixed, safe and unrelated controls adjacent to each new family and retain all source hashes and exact commands.
## Baseline update and migration boundary (2026-10-19)

- The reconciliation ledger now binds all of the following local pinned objects without fetch/checkout: review original `e4e0761501a83ac25cc67d04c527eefe9f4a1b50` / tree `307ac8237263db793028e0bf34a82a85f60821a5` / blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea` / SHA-256 `732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240`; current HEAD `7af25f5ced471e5d6acc8cf5efd4c696275ce940` / tree `11f53fe00d79d477c383e7e9b49ad3b1adcae86c`; latest static baseline `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457` / tree `d15b91627c94d9c3043d7d58d47fcf9af7e42454`; and `origin/main` known-CVE baseline `db77164fdc2af0da02e4d3efc056d84694fd68e8` / tree `8c5a296d8304d98193a29a4695aaf61ca0c0996c` / `known_cves.py` blob `a2ddd5ff2afc2f6fb0f1677ea3ffbbfc580a195b`.
- `known_cves.py` 0.16.0 contains source-signature rules for 17 of the 20 CVEs mentioned across the review and C-line addendum. `CVE-2025-24304`, `CVE-2026-33416`, and `CVE-2026-34757` are explicitly unknown/not covered by that detector. The first has an alternate Ark TypeOrigin mapping; the other two are patch-list-only mentions. Rule presence is not a scan result or product vulnerability claim.
- The full source-audit map contains 36 rows: 17 public CVE sections, 2 patch-list-only CVEs, 4 manual candidates, 5 negative/unestablished controls, and 8 C-line Ark Runtime rows. All rows bind an exact original-line excerpt hash. External G: source identities remain partial and strict-ineligible because full commit/tree/blob/source hashes were not present in the original.
- `IAO7GO` is explicitly `miss_coverage_selector_not_applicable`; `I7W51D` is `miss_rule_length_narrowing_uncovered`; `IB8BCA` is `miss_rule_dataview_boundary_uncovered`. Their 0-to-0 results are not safe/miss conclusions.
- Migration to `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457` has one semantic conflict: `tests/detectors/ark_runtime/test_parser_owner.py` expects lexical owner recovery in the target, while this slice requires fail-closed source-bound ownership and a classified missing-external-source path. Keep the current test semantics. The target tree also omits `src/ohscanner/detectors/ark_runtime/syntax.py` even though its test imports it; carry the current file as a required dependency. See `migration-conflicts-09ba5ab.json`.

## Next minimal slices

1. Migrate the current fail-closed `syntax.py`, owner tests and fixtures onto `09ba5aba...`; resolve the test semantic conflict in favor of source-bound unknown/limitation and rerun the 14 focused controls.
2. Extend IAO7GO applicability to `native_inline_lowering.cpp` without filename-based ownership guesses; keep selector misses blocked/unknown until the semantic selector and exact source identity are bound.
3. Add independent rules and positive/fixed/safe/unrelated/unknown controls for I7W51D length narrowing and IB8BCA DataView/Atomics boundaries. Do not reuse multiplication or TypeOrigin results as proof.
4. Expand the source-audit input with explicit source-bound entries for `CVE-2026-33416` and `CVE-2026-34757`, then decide whether they belong in known-CVE rules; keep them unknown until exact affected source and fix semantics are available.
5. Re-run known-CVE source-signature controls for all 17 covered CVEs only on pinned component sources. Product reachability, CIA impact, and confirmed/reportable status remain separate evidence gates.
