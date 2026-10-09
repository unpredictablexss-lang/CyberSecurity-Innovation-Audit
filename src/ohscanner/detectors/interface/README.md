# Interface detector module

`IpcPermissionDetector` (`ohscanner.interface.permission`) is B's adapter for
the implemented contracts at core commit `8c5c9d9b77857d9ccf41d101be6068f287453e81`.
The core is currently on `feat/ohscanner-core`, not merged to this main-based branch.
Do not import replacement/fake contracts or edit the global catalog to bypass review.

- `ipc_repository.py`: source dispatch, observed permissions and bounded helper trace.
- `cpp_permission.py`: limited function-local syntax candidate analysis.
- `cpp_macros.py`: explicit-header limited macro expansion and source-line mapping.
- `permission_prototype.py`: original synthetic graph research, separate from source analysis.
- `detector.py`: actual core `DetectorRun`/finding/obligation adapter; no network or tool execution.

Core runner enforces snapshot binding and whole-scope AST eligibility. The adapter
independently checks detailed syntax because existing core outlines omit dispatch
and branch nodes. Completed means eligible syntax was examined; unresolved callees,
macros, normative permission requirements and path feasibility remain obligations.

Method/source provenance and design fixtures are in `research/methods/interface`
and `research/corpus/interface`. No independent holdout or real vulnerability
fix-pair validation is claimed. Generated artifacts and original third-party
sources are ignored. Findings remain syntax candidates with unassessed confidence.

For Ubuntu migration and the current actual verification results, read
`docs/reviews/interface_attack_surface/branch_integration.md` and `PROGRAM_STATUS.md`.

## Web family lexical prototypes

See `web_patterns.py` for BridgeInjectionDetector, WebUrlDetector and SensitiveDisclosureDetector. These provide pattern review only, not complete vulnerability detection. WebEngineDetector is explicitly blocked and implements no memory-safety algorithm. All reuse real core contracts with deferred imports. No global registration added. Frontend requests and detailed limitations are recorded in `docs/reviews/interface_attack_surface/web_families_frontend_request.md`.

Run lexical tests: `.venv/bin/python -m unittest tests.detectors.interface.test_web_patterns -v`. Run real adapter tests only in a core-compatible worktree using `tests.detectors.interface.test_web_core_adapter`; main explicitly skips these while core is absent.
