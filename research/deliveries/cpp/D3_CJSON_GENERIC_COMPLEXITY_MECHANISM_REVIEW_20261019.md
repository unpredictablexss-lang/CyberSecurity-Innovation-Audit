# D3 generic recursive complexity mechanism review — 2026-10-19

## Scope and result

This isolated D3 prototype addresses two structural mechanisms described in the A-line source review: recursive tree comparison with repeated linear lookup (the mechanism discussed for CVE-2026-67216), and recursive copy/expansion followed by recursive destruction (the mechanism discussed for CVE-2026-67215). CVE numbers, cJSON identifiers, source paths, and function names are not detector triggers. The rules are candidate signals and do not establish that either is a confirmed OpenHarmony product vulnerability.

The implementation is a standalone module, `src/ohscanner/detectors/cpp/algorithmic_complexity_detector.py`. It is deliberately not registered in the shared catalog or runner. The direct unit fixtures use generic structures and names. The detector reports partial identity and keeps recurrence, depth bounds, attacker control, product build/reachability, and impact as unresolved obligations.

## Mechanism coverage

| Mechanism | Current structural signal | Positive/control evidence | Limits |
| --- | --- | --- | --- |
| Recursive comparison + repeated lookup | Self-recursive function containing a loop that calls a local helper whose body contains a loop. | `recursive_lookup_positive.c` hits; `fixed_safe.c` uses direct indexed lookup and stays quiet; `unrelated.c` separates simple recursion from unrelated nested loops. | No complexity proof, key uniqueness proof, input-size recurrence, memoization analysis, or indirect-call support. A generic recursive walk with a loop may be missed if parser shapes are incomplete. |
| Recursive copy/tree expansion + recursive cleanup | Recursive function allocates and assigns its recursive result to a member; another local recursive function releases nodes; loop-driven caller repeats copy invocation. | `recursive_growth_positive.c` hits; `recursive_growth_bounded.c` has an explicit depth cap and iterative teardown and stays quiet. | Does not prove exponential growth, unbounded tree size, alias ownership, allocation success handling, cleanup reachability, or that the repeated copy expands rather than duplicates a bounded tree. Cleanup pairing is same-translation-unit and lexical. |
| Partial/unknown behavior | Candidate can remain in findings while run status is blocked whenever parse status is not complete. No finding remains unknown under partial parsing. | Two unit controls assert candidate retention and blocked empty result. | This direct detector is unregistered; production profile coverage is not established. |

## Test result

`python -m unittest tests.detectors.test_cpp_algorithmic_complexity_detector -v` passes 8 mechanism/control tests. Controls include positive, bounded/fixed, unrelated, and partial-input cases. A Runner regression verifies that a bounded candidate from a partial unit is retained while aggregate status stays blocked and coverage stays partial.

### Pinned component replay addendum

A direct DetectorRegistry/Runner replay was run against local pinned cJSON snapshot `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`, snapshot SHA-256 `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`, selecting `third_party/cjson/cJSON.c` and `third_party/cjson/cJSON_Utils.c`. The files bind to blobs `152b2caa479c9f448001652913c980a6dafb82e0` / SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb` (partial parse) and `8fa24f8e9bf452cf1ba49d1325c85423ce742c74` / SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9` (complete parse). `ohscanner.cpp.algorithmic_complexity` v0.1.0 returned `blocked`, retained 3 unassessed candidates in `cJSON_Utils.c`, and Runner coverage was 0 complete / 2 partial / 0 unexamined. Raw normalized output: `research/evidence/cpp/d3-cjson-complexity-runner-replay.json`.

This is a local source-snapshot candidate replay only. It is not an exact vulnerable/fixed CVE pair, does not establish that the three findings are the disclosed root cause, and leaves product build, call path, attacker control, recurrence and impact unknown. The detector is intentionally absent from CLI/catalog registration and production profiles; production scanning coverage is therefore not claimed. The earlier “synthetic-only” statement applies to pre-addendum calibration and is superseded by this limited local replay.

## Source identity and CVE boundary

The controlling source is `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\cpp\源漏洞审查记录_20261018_A线整合版.md`:

- Lines 58–63 describe CVE-2026-67216, local component candidate/strong source match at `third_party_cJSON`, master `0c2c9dff82cc`, version 1.7.19; the report says product use of the comparison entry is unknown and the observed timing is a component experiment. It notes the advisory requires the host to compare attacker supplied data with a structurally matching reference document.
- Lines 65–70 describe CVE-2026-67215 as candidate/code-path match in local cJSON 1.7.19; JSON Utils is only compiled in an `ohos_lite` configuration, while standard configuration mainly compiles `cJSON.c`. Product profile/call entry and confirmed fixed source remain unknown.
- Lines 241–242 of the consolidated matrix explicitly say no production rule currently exists and `cJSON.c` parsing is partial/blocked; zero findings cannot be interpreted as safe or as a proven miss. For 67215, `cJSON_Utils.c` is complete but zero findings are likewise not a safety conclusion. The report documents a local harness reproduction, not product impact.

The referenced component checkout is outside this D2 worktree and was not used as a detector fixture or tuning target. Before promoting the candidate rules, acquire and record exact full Git commit, source file SHA-256, upstream affected/fixed revisions, product profile/build flags (especially JSON Utils inclusion), parser status, and caller/entry evidence. Do not infer a fixed control from the separate depth-limit change: the report says that change does not establish a fix for the comparison CPU mechanism. Neither CVE is labeled a confirmed product defect here.

## Minimal implementation review

- `RULE_RECURSIVE_LOOKUP` has the conservative shape `recursive function -> loop -> local loop-based helper`. It is intended to generalize repeated per-node linear search without semantic names. A future implementation should improve AST/CFG and recurrence modeling rather than add component names or CVE signatures.
- `RULE_RECURSIVE_GROWTH` requires syntactic recursive allocation/linkage, recursive release, and repeated copy calls. This is only a coarse intersection of the reported copy-expansion and cleanup mechanism. It does not demonstrate the resulting tree depth or that JSON Patch operations can repeatedly copy a growing subtree.
- Both rules emit CWE-674 candidates with identity_quality `partial`, and obligations for algorithm model/depth bounds/attacker control/build reachability/availability impact. A completed run means lexical analysis completed, not that a vulnerability was confirmed.
- Catalog and runner registration requires a separate shared-owner review. No shared files were edited.

## Executable next task queue

1. **Pin exact source and controls.** Use the reported cJSON master object `0c2c9dff82cc` to obtain a full commit and hash `cJSON.c`/`cJSON_Utils.c`; identify advisory affected revisions and a vendor/upstream fixed revision from primary evidence. Preserve full patch/source and record SHA-256. Do not use CVE text or function names as matching features.
2. **Comparison mechanism calibration.** Against exact affected source and an independently sourced safe/fixed algorithm control, test arbitrary renames, wrapper helpers, structurally equivalent nested inputs, and unrelated recursive comparison. Demonstrate that repeated linear lookup is actually nested under the recursive branch and model the recurrence; keep unknown when parser evidence is partial.
3. **Patch/expansion calibration.** Establish whether each copy operation can copy a node from the already-grown destination tree or only from the original tree. Build separate expandable-tree, fixed-size/rejecting, shallow-input, and unrelated recursive-release controls. Verify any fix against code diff and bounded runtime/stack experiments.
4. **Product applicability.** Resolve whether the OpenHarmony product profile compiles JSON Utils, enumerate callers and data sources, and establish parser/build provenance, reachable entry, attacker control, depth/size bounds, and isolated impact. Until then retain `candidate`/`unknown` component status.
5. **Integration proposal.** Request shared-owner catalog/profile registration only after source-calibrated precision and regression evidence exists; decide default enablement and coverage semantics from results, not from the advisory severity.

## Files added

- `src/ohscanner/detectors/cpp/algorithmic_complexity_detector.py`
- `tests/detectors/test_cpp_algorithmic_complexity_detector.py`
- `tests/detectors/fixtures/cpp_algorithmic_complexity/`
- This dated review.

No edits were made to Catalog, Runner, API, existing resource-lifetime implementation, known-CVE signatures, or D1 path detector.
