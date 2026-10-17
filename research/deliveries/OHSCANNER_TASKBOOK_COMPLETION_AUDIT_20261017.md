# OHScanner taskbook completion audit, 2026-10-17

Source: `C:\Users\work_work\Downloads\OHScanner最新代码审查与AB检测器研发方案.md`.
Remote push/pull was rechecked first; branch `codex/full-runtime-performance-audit-20261014` and remote both resolve to `acec73267590eebda9a16f405141c9161f2d4cfa` before this audit.

## Verdict

The taskbook is **not fully complete**. Automatic selection, v2 fact slots, Codex 0 reconciliation, a controlled cross A/B case and bounded ArkTS/JS rules were added in the follow-up pass; product-scale and real-product closure remain open. The A memory-safety slice and historical CVE replay are implemented, but the taskbook also requires Codex 0 branch/PR reconciliation, Codex 1 shared facts plus automatic detector selection, B/Parcel/ArkTS follow-through, Codex 3 cross A/B integration, and broader experiment/performance evidence. This audit preserves that full scope.

## Requirement ledger

| Taskbook requirement | Current authoritative evidence | Status |
|---|---|---|
| Pull latest remote and use real current SHA | `git push/pull` output; local=remote `acec732...` | Complete for current branch |
| Codex 0: audit PR #8-#14 and three research branches | `CODEX0_BRANCH_RECONCILIATION_20261017.md` now records local ref/module deltas; live PR API and missing `work/ipc-20261017` ref remain open | Partial |
| A-0 stable owner/constructor/cross-file semantics | Existing `shared_ptr_race` 0.5.0 and `lifetime` 0.4.0 tests plus historical replay | Substantially complete |
| A-1 bounds/length detector | `ohscanner.cpp.bounds` 0.2.0, specs, controls, historical CVE-2025-23420 5->0 | Complete for bounded lexical scope |
| A-2 integer/size detector | `ohscanner.cpp.integer_bounds` 0.2.0, CVE-2025-0587 1->0 | Complete for bounded lexical scope |
| A-3 null/UAF/double-free/resource | null 0.2.0, lifetime, resource 0.1.0, unsafe calls 0.1.0 | Substantially complete; leak/interprocedural summaries incomplete |
| A-4 expose A facts to B Parcel/Native Bridge | v2 fact view plus controlled A/B Parcel case now exists; real product Parcel/Native Bridge integration remains open | Partial |
| B-0 six-family IPC closure | Interface models/analysis exist; migration/census comparison with missing `work/ipc-20261017` is not closed | Partial |
| B-1 Parcel bounds/lifecycle | `ipc.parcel.*` rules and tests exist; no taskbook-complete real vulnerable/fixed Parcel case | Partial |
| B-2 authorization/identity/sensitive flow | `ipc.auth.*`, consequence model and tests exist; no complete product authorization PoC | Partial |
| B-3 ArkTS/JS frontends and four rule families | `language.py` lexical frontend and `script_security_detector.py` rules exist with controls and pinned scan; product/manifest semantics remain open | Partial |
| Public contracts and v2 compatibility | v1 preserved; `build_fact_view_v2` exports symbol/CFG/range/call/taint/unknown slots and shared facts now carry v2 | Partial |
| Automatic detector selection | Catalog/API/Web/CLI omit selection to auto-select approved security detectors; example remains opt-in | Complete for ordinary scan entry |
| Repository/all-community/15-day/807-scale plan | Existing batch/halfyear/perf components only; no current all-community/recent-15-day execution | Incomplete |
| Agent/tool evidence foundation | Historical R0/R1/R2 artifacts exist; no new taskbook-wide Agent completion | Partial |
| E1 rule controls | New A detectors have positive/fixed/safe/unrelated/unknown controls | Complete for A detectors |
| E2 real fixed-source comparison | 5 pinned components and old/new comparison exist | Partial for A only |
| E3 independent holdout metrics | 6 historical cases / 4 applicable, 4 vulnerable hits, 3 fixed misses, 1 residual; too small for published Precision/Recall | Partial |
| E4 vulnerable/fixed/patched + harmless isolated verification | Historical CVE mechanism PoCs and controls exist; direct product builds absent | Partial |
| Performance metrics | 5-component wall/RSS plus older 11-component baseline exist; hardware/LOC/coverage/timeout matrix incomplete | Partial |
| Competition report | A delivery report exists; full taskbook A+B+platform report absent | Incomplete |

## Immediate next work

1. ~~Implement automatic default detector selection without enabling the example detector.~~ Completed in this pass.
2. Save a Codex 0 module-difference/PR reconciliation report from available refs and explicitly record the missing `work/ipc-20261017` ref.
3. ~~Build the first cross A/B fixed-sample case using the existing IPC Parcel model plus A length/integer facts.~~ Controlled synthetic case completed; product case remains next.
4. Add machine-readable taskbook completion metrics so later work cannot mistake partial coverage for completion.
