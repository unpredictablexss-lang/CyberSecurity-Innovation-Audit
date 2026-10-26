# CVE-2026-67215 upstream remediation status and current production replay (2026-10-19)

## Official status checked

- Red Hat's CVE record continues to describe the JSON Patch add/copy subtree-amplification path and states there is no upstream fix as of cJSON 1.7.19: https://access.redhat.com/security/cve/cve-2026-67215
- GitHub advisory GHSA-5q3m-r3x7-8phg lists patched versions as unknown: https://github.com/advisories/GHSA-5q3m-r3x7-8phg
- Upstream issue #1073, “Remediate cJSON vulnerabilities CVE-2026-67215 and CVE-2026-67216,” is open and shows no linked branch or pull request. Its text says no confirmed fix version: https://github.com/DaveGamble/cJSON/issues/1073
- PR #1064 remains open and targets issue #995's `cJSONUtils_MergePatch` recursion; it adds depth checks to merge patch, merge-patch generation and comparison helpers. It does not bound `cJSON_Delete` after JSON Patch subtree amplification: https://github.com/DaveGamble/cJSON/pull/1064
- PR #1078 remains open and adds depth counters for recursive comparisons / related merge-patch generation. It is related to issue #1073 but does not establish a JSON Patch delete-recursion fix or a confirmed release: https://github.com/DaveGamble/cJSON/pull/1078

Therefore, neither PR is accepted as a vulnerable/fixed pair for CVE-2026-67215. The JSON Patch `add`/`copy` -> amplified owned tree -> recursive `cJSON_Delete` root remains without a confirmed upstream fix control as of the verification date.

## Current production replay

The previously named synthetic source repo `D:\openHarmonyScanner\tmp\cjson-oh-baseline-20261019-retry` was absent, so the first revalidation command failed before scanning with `source repository must be an existing non-symlink directory`. No source synchronization or fetch was attempted.

A new isolated local Git snapshot was then created from the byte-hash-matched OpenHarmony checkout files only:

- `third_party/cjson/cJSON.c`: 80,529 bytes, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`
- `third_party/cjson/cJSON_Utils.c`: 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`
- Synthetic commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`, snapshot SHA-256 `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`. This is a byte-bound scan container, not an upstream commit; original OH component commit remains `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`.
- Current production entry `python -m src.cli ohscan-run`, detector `ohscanner.cpp.resource_lifetime` v0.1.9, exact two-file scope, no CVE metadata: 0 diagnostics, `blocked`, parse counts 1 complete / 1 partial, detector time 0.10035 s. `cJSON.c` partial parsing still prevents a valid static miss or safety conclusion; `cJSON_Utils.c` parses completely.
- Raw reports: `revalidation-current.json/.md`. The earlier component runtime reproduction and its thread-stack controls remain described in this folder's README; this turn did not rerun binaries.

## Root-cause and detector boundary

Attacker control in the disclosed scenario is an untrusted JSON Patch document applied through cJSON-Utils. `add`/`copy` can graft duplicated subtrees parsed below the parser limit into a resulting tree deeper than the parser limit; recursive `cJSON_Delete` then consumes stack proportional to the resulting depth. Static proof would need the mutation path, resulting ownership/tree-depth amplification, and recursive delete reachable on the error/cleanup path. The current production parser is partial at the `CJSON_CDECL` function-pointer declarations and missing trailing nodes, and the detector has no mutation-depth model. Do not infer a finding from a recursive delete alone.

Status: public disclosure verified; local source and bounded component reproduction verified; current static detection blocked/partial; upstream fixed control absent; OpenHarmony product caller/build/impact unknown.


## Additional official upstream census (2026-10-19)

- The GitHub advisory remains marked **Unreviewed** and lists no patched version. This establishes disclosure metadata, not maintainer confirmation or remediation.
- Current upstream pull-request index and issue list were checked again. Issue #1073 remains the exact remediation thread without a confirmed fixed release. Issue #995 and open PR #1064 concern MergePatch recursion, while PR #1078 concerns recursive comparison/merge-patch generation. None establishes a fix for JSON Patch `add`/`copy` subtree amplification followed by `cJSON_Delete`.
- Other current ApplyPatches reports include a use-after-free when a patch removes the patch array (#1082/#1084), and issue #1093 concerns parser deep nesting/ASan behavior. They are distinct mechanisms and are not fixed or safe controls for this CVE.
- No fixed commit, fixed regression, or fixed-version source was found. Thus a vulnerable/fixed static differential cannot be honestly run for this case today. Component runtime reproduction on the pinned local 1.7.19 source remains evidence of behavior under the explicitly recorded thread-stack conditions; it does not replace the missing fixed control or complete static parse.

Sources checked: https://github.com/advisories/GHSA-5q3m-r3x7-8phg ; https://github.com/DaveGamble/cJSON/issues/1073 ; https://github.com/DaveGamble/cJSON/issues/995 ; https://github.com/DaveGamble/cJSON/pull/1064 ; https://github.com/DaveGamble/cJSON/pull/1078 ; https://github.com/DaveGamble/cJSON/issues/1082 ; https://github.com/DaveGamble/cJSON/issues/1093 ; https://github.com/DaveGamble/cJSON/pulls .
