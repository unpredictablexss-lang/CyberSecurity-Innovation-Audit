# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `pnggroup/libpng`
- Pinned commit: `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`
- Git tree: `e01f5780f93eaa6d74cca003bb39b427c8f1e910`
- Snapshot SHA-256: `f80ae78bc09612fd5b8c5a925f858b41e15711319d0a794cafeb4764f7ec73d9`
- Source files indexed: 4
- Parsing coverage: `{"partial": 4}`
- Detector runs: 1
- Total unverified diagnostics: 32
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 4 | 0 | 4 | 0 | 32 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:92b0e61cc23afdf0` | `pngrtran.c:812` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0f4a7c238e4ca5ff` | `pngrtran.c:1187` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:da81f06fd67ef49b` | `pngrtran.c:1189` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0a2fa5fe1ecec1bd` | `pngrtran.c:1228` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:7b7de28508b8e7d4` | `pngrtran.c:1230` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:5098e7afd3c70a32` | `pngrtran.c:1232` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:5012196fa681b95c` | `pngrtran.c:1245` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0394abdc92e94d9f` | `pngrtran.c:1246` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:3700bcd9e1a845c0` | `pngrtran.c:1776` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:182b62868be1f215` | `pngrtran.c:1778` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:cd2614db2ce841ba` | `pngrtran.c:1793` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:dc235d0aef96bffc` | `pngrtran.c:1798` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0abc0a3c7a9290ec` | `pngrtran.c:1803` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:b32cdd65f71b1cbf` | `pngrtran.c:1816` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:b43633e3342f06b2` | `pngrtran.c:1821` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:dafa2ee47f0d0d37` | `pngrtran.c:1826` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:f1803aed409eba82` | `pngrtran.c:1985` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:6e655b3be74115b9` | `pngrtran.c:1990` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0600e268ea3ebd9c` | `pngrtran.c:1994` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:325450800b8551a1` | `pngrtran.c:1997` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:2a67b7906a80d967` | `pngrtran.c:2000` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:8bd8845d7650a929` | `pngrtran.c:2026` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:487cf34572e98062` | `pngrtran.c:2029` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:904a1a8f8531b0af` | `pngrtran.c:2036` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:ee0385c407f37e4a` | `pngrtran.c:2039` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:f124dafc59827004` | `pngrtran.c:2046` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:aa6621f9584773b2` | `pngrtran.c:2049` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:bdaa048a954278ac` | `pngrtran.c:2082` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:551cc8812c2c1c07` | `pngrtran.c:4907` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:88386300974b739a` | `pngrtran.c:4907` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:d0e287df5a5f890b` | `pngset.c:795` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:015d28271e0deb3a` | `pngset.c:1173` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: partial, 0/4 applicable files examined; unexamined=4

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: png.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngread.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngrtran.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngset.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `0ceb501728d8d6d5effcfe154590ac7191c943e31dba6755a35d10925db32add`
- Language matching plans attempts; actual coverage remains in the results above.
