# A memory-safety pinned scan: update_updateservice

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/update_updateservice`
- Commit: `e4942a33cc5ed29040e5c720bea3b2a8e4a79221`
- Git tree: `b367991eed0272f54fe5ae712d18e24377d57949`
- Snapshot SHA-256: `3eac699e183d0c08368ce18374ba039fbf4a165cb6f9ac56e43f65a9a774c6c3`
- Scope manifest SHA-256: `33f9ce2aab5d118c91cd3ec485987bf00e350b3f753270d735f64014c01d4e11`
- Selected files/bytes: 219/851345
- Wall seconds: 1.173055
- Candidate findings/groups: 3/2

## Detector runs

### `ohscanner.cpp.bounds` 0.2.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.integer_bounds` 0.1.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.resource_lifetime` 0.1.0 (blocked)

- `frameworks/js/napi/base/include/client_helper.h:100:13` `ohcpp-resource-lifetime-double-free-candidate-001` `CWE-415` Candidate only: `delete result` releases `result` again after a modeled release. Aliases, ownership transfer and conditional paths remain unknown.
- `services/firmware/upgrade/flow/src/firmware_manager.cpp:196:5` `ohcpp-resource-lifetime-use-after-free-candidate-002` `CWE-416` Candidate only: `flowManager->` uses `flowManager` after a modeled release. Reallocation, alias recovery, destructor timing and path feasibility remain unknown.
- `services/firmware/upgrade/flow/src/firmware_manager.cpp:208:5` `ohcpp-resource-lifetime-use-after-free-candidate-002` `CWE-416` Candidate only: `flowManager->` uses `flowManager` after a modeled release. Reallocation, alias recovery, destructor timing and path feasibility remain unknown.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- This run uses local pinned Git objects only; no fetch, checkout or external scanner is invoked.
