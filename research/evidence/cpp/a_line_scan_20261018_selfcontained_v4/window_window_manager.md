# A memory-safety pinned scan: window_window_manager

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/window_window_manager`
- Commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `b528cb54ffd2e4007bc3ae64b9cb06002bd7228fe8cc304cd1eeb9c457b836d9`
- Scope manifest SHA-256: `cf4b29be492c671369efbf8fd0e5c1959c08243841d43e0b70bc9189efb3c94f`
- Selected files/bytes: 1112/20206691
- Wall seconds: 25.303935
- Candidate findings/groups: 2/1

## Detector runs

### `ohscanner.cpp.bounds` 0.3.2 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.integer_bounds` 0.2.3 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.resource_lifetime` 0.1.3 (blocked)

- `snapshot/src/snapshot_utils.cpp:300:17` `ohcpp-resource-lifetime-use-after-free-candidate-002` `CWE-416` Candidate only: `*rgb888` uses `rgb888` after a modeled release. Reallocation, alias recovery, destructor timing and path feasibility remain unknown.
- `snapshot/src/snapshot_utils.cpp:343:17` `ohcpp-resource-lifetime-use-after-free-candidate-002` `CWE-416` Candidate only: `*rgb888` uses `rgb888` after a modeled release. Reallocation, alias recovery, destructor timing and path feasibility remain unknown.

### `ohscanner.cpp.unsafe_memory_call` 0.1.2 (blocked)

- No candidate emitted in the analyzed lexical scope.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- This run uses local pinned Git objects only; no fetch, checkout or external scanner is invoked.
