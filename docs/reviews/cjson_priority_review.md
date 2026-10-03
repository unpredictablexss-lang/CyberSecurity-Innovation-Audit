# cJSON priority-candidate review

> Target: `openharmony/third_party_cJSON`  
> Commit: `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`  
> Scope: `cJSON.c`, `cJSON_Utils.c`
>
> This document records a second-pass source review of the candidates previously marked `needs_context` or `interesting`. It is not a vulnerability report.

## Summary

| Location | Current review | Evidence summary | Decision |
|---|---|---|---|
| `cJSON.c:367` | likely_safe_static | temporary destination is allocated from the same counted number length, allocation failure is checked, and the copy length matches the counted span | deprioritize runtime |
| `cJSON.c:570` | likely_safe_static | print-buffer invariants are checked, expansion failure returns NULL, and the manual reallocation copy uses the existing offset range | deprioritize runtime |
| `cJSON.c:1021` | needs_context_low_priority | the matched memcpy executes only in the no-escape path; the more relevant remaining question is surrounding size arithmetic, not the API name itself | keep for later integer/length analysis |
| `cJSON_Utils.c:234` | runtime_worthy_quality_issue | an allocation result is used without an explicit NULL check before formatting output | controlled robustness validation |
| `cJSON_Utils.c:245` | same_root_cause | the object path uses the same unchecked allocation-result pattern before writing through the returned pointer | group with :234 |

No candidate is promoted to `validated vulnerability`.

## cJSON.c:367

The number parser counts bytes while iterating inside the parse-buffer access condition, allocates a temporary buffer using the counted length plus terminator space, checks allocation failure, copies exactly the counted length, and writes the terminator at the following byte.

Current conclusion: the direct memcpy candidate is not a priority finding under the documented input-buffer contract. A caller that supplies an invalid buffer/length pair would be a separate contract problem.

## cJSON.c:570

The `ensure` helper verifies the print-buffer offset/length relation, rejects unsupported requested sizes, handles allocation failure, and only then copies the existing `offset + 1` bytes during its manual reallocation path. Public initialization paths also begin with bounded buffer lengths.

Current conclusion: the direct memcpy candidate is low priority unless later whole-program analysis finds a caller that violates the print-buffer invariants.

## cJSON.c:1021

The matched memcpy occurs only when no escaping is required. In that branch, the copied length corresponds to the input-string span and `ensure` must succeed first.

The remaining interesting question in this function is broader size arithmetic around input length, escape expansion, and the requested output size. That is a future integer/length-analysis question and should not be conflated with the presence of memcpy itself.

Current conclusion: keep as `needs_context_low_priority`; do not use it as the first runtime case.

## cJSON_Utils.c:234 and :245

Both locations are inside `cJSONUtils_FindPointerFromObjectTo` and share one root-cause family: a `cJSON_malloc` result is consumed without an explicit NULL check in the corresponding array/object branch.

The fixed source also exposes allocator hooks through the cJSON API, so this behavior can be evaluated in a controlled component-level robustness test without modifying the library source.

Current conclusion:

- treat the two locations as one root-cause family for deduplication;
- use them to exercise the runtime-evidence pipeline;
- keep `security_impact = unknown`;
- do not call a reproduced allocation-failure crash a competition vulnerability unless a realistic OpenHarmony input/control path and meaningful security impact are separately established.

## Next gate

The next experiment should remain narrowly scoped to component robustness:

1. keep the cJSON target pinned and unmodified;
2. establish normal controls for the same public utility API paths;
3. exercise allocator-failure handling in a controlled test environment;
4. collect sanitizer/runtime evidence and repeatability;
5. classify the result as `validated_component`, `quality_issue`, `inconclusive`, or `blocked` based on evidence;
6. do not claim OpenHarmony-system exploitability from a host-side component test.

After that, the project should decide whether this root cause deserves any further security work or whether effort should shift to the first-party `c_utils` target.
