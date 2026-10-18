# A memory-safety pinned scan: security_access_token

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/security_access_token`
- Commit: `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- Git tree: `4621b3e40b31a958a4bbe9be87690afb6cec44b0`
- Snapshot SHA-256: `ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d`
- Scope manifest SHA-256: `efe84b4b11aa36a4bf072438acd1171dd6769be1877fdfd1f8f4897b66cffe4e`
- Selected files/bytes: 550/3484891
- Wall seconds: 6.643786
- Candidate findings/groups: 5/3

## Detector runs

### `ohscanner.cpp.bounds` 0.3.2 (blocked)

- `interfaces/innerkits/token_setproc/src/spm_setproc.c:147:15` `ohcpp-memory-bounds-copy-candidate-001` `CWE-119` Candidate only: `memcpy_s` copy length `nameSize` is not proven <= allocation capacity `totalSize * 1` for `combinedBuf`; aliases, guards and reachability remain unknown.

### `ohscanner.cpp.integer_bounds` 0.2.3 (blocked)

- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:210:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:340:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:425:30` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `sendlen + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:469:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.

### `ohscanner.cpp.resource_lifetime` 0.1.6 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.unsafe_memory_call` 0.1.3 (blocked)

- No candidate emitted in the analyzed lexical scope.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- This run uses local pinned Git objects only; no fetch, checkout or external scanner is invoked.
