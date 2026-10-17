# A memory-safety pinned scan: update_updateservice

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/update_updateservice`
- Commit: `e4942a33cc5ed29040e5c720bea3b2a8e4a79221`
- Git tree: `b367991eed0272f54fe5ae712d18e24377d57949`
- Snapshot SHA-256: `3eac699e183d0c08368ce18374ba039fbf4a165cb6f9ac56e43f65a9a774c6c3`
- Scope manifest SHA-256: `33f9ce2aab5d118c91cd3ec485987bf00e350b3f753270d735f64014c01d4e11`
- Selected files/bytes: 219/851345
- Wall seconds: 1.047291
- Candidate findings/groups: 0/0

## Detector runs

### `ohscanner.cpp.bounds` 0.1.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.integer_bounds` 0.1.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- This run uses local pinned Git objects only; no fetch, checkout or external scanner is invoked.
