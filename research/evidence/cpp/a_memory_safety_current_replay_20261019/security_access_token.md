# A memory-safety pinned scan: security_access_token

> Candidate-only report; `validated_vulnerability=0`.

- Repository: `openharmony/security_access_token`
- Commit: `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- Git tree: `4621b3e40b31a958a4bbe9be87690afb6cec44b0`
- Snapshot SHA-256: `ed782acd6668c44b92c66e1dfa27e2641c8abfb5bc2bd4d5af4a274377332a8d`
- Scope manifest SHA-256: `d9dbb5791f6a6fed8207aa6ed31e0fd35b35d8cf56d80a7d353b9c746b67b3e6`
- Selected files/bytes: 550/3484891
- Wall seconds: 6.082746
- Candidate findings/groups: 9/7

## Detector runs

### `ohscanner.cpp.bounds` 0.2.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.integer_bounds` 0.2.0 (blocked)

- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:210:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:340:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:425:30` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `sendlen + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.
- `services/tokensyncmanager/src/remote/soft_bus_channel.cpp:469:26` `ohcpp-integer-bounds-arithmetic-candidate-001` `CWE-190` Candidate only: array allocation size `len + 1` uses `+` without a modeled checked-arithmetic guard; overflow may yield an undersized allocation.

### `ohscanner.cpp.resource_lifetime` 0.1.0 (blocked)

- No candidate emitted in the analyzed lexical scope.

### `ohscanner.cpp.unsafe_memory_call` 0.5.0 (blocked)

- `interfaces/innerkits/analysis_model/src/analysis_model_log.h:41:35` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `printf` receives a non-literal format expression `"[%s] debug: " fmt "\n"`. Control, intended format ownership and concrete impact remain unknown.
- `interfaces/innerkits/analysis_model/src/analysis_model_log.h:42:34` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `printf` receives a non-literal format expression `"[%s] info: " fmt "\n"`. Control, intended format ownership and concrete impact remain unknown.
- `interfaces/innerkits/analysis_model/src/analysis_model_log.h:43:34` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `printf` receives a non-literal format expression `"[%s] warn: " fmt "\n"`. Control, intended format ownership and concrete impact remain unknown.
- `interfaces/innerkits/analysis_model/src/analysis_model_log.h:44:35` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `printf` receives a non-literal format expression `"[%s] error: " fmt "\n"`. Control, intended format ownership and concrete impact remain unknown.
- `interfaces/innerkits/analysis_model/src/analysis_model_log.h:45:35` `ohcpp-format-string-candidate-002` `CWE-134` Candidate only: `printf` receives a non-literal format expression `"[%s] fatal: " fmt "\n"`. Control, intended format ownership and concrete impact remain unknown.

## Limitations

- Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.
- No product build, permission boundary, attacker control, trigger trace or CIA impact is established.
- Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.
- Source objects were acquired before analysis and their remote/ref are recorded separately; analysis reads only the verified local pinned Git objects, performs no checkout, and invokes no external scanner.
