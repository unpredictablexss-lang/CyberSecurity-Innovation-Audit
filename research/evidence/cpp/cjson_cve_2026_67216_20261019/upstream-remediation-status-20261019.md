# cJSON CVE-2026-67216 upstream remediation status

Verified: 2026-10-19. A-line source review only; this is not a detector result or product verdict.

## Disclosure and local source

- GitHub Advisory Database record GHSA-ff2v-f99f-wm3f identifies CVE-2026-67216 in cJSON through 1.7.19, describing exponential CPU cost in `cJSON_Compare()` from recurring nested comparison of shared subtrees without a depth guard. The advisory lists patched versions as unknown: https://github.com/advisories/ghsa-ff2v-f99f-wm3f
- Local OpenHarmony cJSON 1.7.19 source and bounded component cost measurements are recorded in the adjacent case README and the coverage ledger. Static production parse of `cJSON.c` remains partial/blocked; no CVE-specific detector was run or implemented against that incomplete parse.

## Upstream remediation check

- Upstream remediation issue #1073 remains open and states that no confirmed upstream fix version was identified: https://github.com/DaveGamble/cJSON/issues/1073
- Pull request #1078 remains open, unmerged, base `fb16e5cf358798aabb049655975cde8427101056`, head `d18fad4ae9c743ebe493135dc8576ac1e4521969` (head repository `atharvmantri/cJSON`). GitHub connector metadata retrieved 2026-10-19. The PR title is “guard recursive comparisons against stack exhaustion.”
- PR description and diff thread a `depth` counter through `cJSON_Compare` and JSON Patch `compare_json`, rejecting when `depth >= CJSON_NESTING_LIMIT`. It does not change the symmetric nested subtree traversal or impose a CPU/work budget below that limit. Since the CVE-2026-67216 advisory describes exponential work at comparatively shallow nesting (around depth 40), this PR is not a verified fix/control for that algorithmic-complexity root cause. It is an open proposal and must not be presented as an upstream fixed commit.
- PR author reports focused regression tests and native build, but those results belong to the unmerged branch; A-line has not fetched/built that branch and does not treat them as local test results.

## Classification and next action

Keep the advisory/source-root cause as disclosed and locally measurable, static detection blocked by parser coverage, and product exposure unknown. No genuine upstream fixed version/test was found in this audit, so no vulnerable/fixed production CLI comparison is valid yet. Next A-line case: review libpng CVE-2026-33416, whose official 1.6.55/1.6.56 source pair, registered lifetime candidates, component ASan results, and OpenHarmony install-generated results are already pinned; determine whether an A-line-owned safe-control or source-provenance refinement can improve its detector without changing shared parser interfaces.
