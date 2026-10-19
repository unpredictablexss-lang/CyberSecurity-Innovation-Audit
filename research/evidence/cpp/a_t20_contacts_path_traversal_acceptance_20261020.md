# T20 Contacts path traversal independent acceptance

Date: 2026-10-20  
Lane: independent testing/evidence  
Checkout: clean detached worktree at D1 head `24b114094886b8d3e606afbbcd7b64af1dfa69ac`, based on PR #30 head `8ec5f56a12e90bba56953b39eb17faa20e154da9`. No detector, test, fixture, or Catalog file was changed.

## Source identity and baseline

The A0 Contacts object in `applications/standard/contacts_data` was independently read from the local bare project-object database, without checkout or newline conversion. OpenHarmony `OpenHarmony-6.1-LTS` commit `b02aadfc2d801ee30573fcb2d13490298e146fea` resolves to tree `ef183625ccbc842f47b076eb75e68b665d7c21c6`; path `dataBusiness/contacts/src/contacts_data_ability.cpp` resolves to blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. These values match the pinned identity in the D1 replay and Catalog request. The distinct `master` object listed in those records is not substituted for A0.

I read `research/methods/cpp/PATH_TRAVERSAL_METHOD_CARD_20261019.md` and `research/deliveries/cpp/CONTACTS_PATH_TRAVERSAL_CATALOG_REQUEST_20261019.md`. The method card describes a bounded lexical may-flow candidate rule, not full taint/path semantics. The checked-in `research/data_sensitive/method_card.md` describes CWE-532 and is unrelated to this rule; it is not used as its method card.

## Independent replay

Command (Python 3.10, Tree-sitter 0.26.0 / C 0.24.2 / C++ 0.23.4 installed into a temporary ignored-from-report target directory):

```powershell
$env:PYTHONPATH='D:/openHarmonyScanner/worktrees/a-t20-contacts-acceptance-20261020/.t20-python-packages'
py -3.10 research/evidence/cpp/contacts_path_traversal_20261019/direct_replay.py `
  --git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/applications_contacts_data.git `
  --commit b02aadfc2d801ee30573fcb2d13490298e146fea `
  --source-path dataBusiness/contacts/src/contacts_data_ability.cpp `
  --parse-status auto `
  --json-out research/evidence/cpp/contacts_path_traversal_20261019/contacts_61lts_exact_object_replay_T20_20261020.json
```

Result: detector `ohscanner.cpp.path_traversal`, version `0.3.0`; rule `ohcpp-path-traversal-source-to-file-sink-candidate-001`; completed run; file outcome `complete`; parser `src.parser.ast.parse_source`, `light-ast`, `complete`, 0 issues. Three candidates were reproduced in `HandleContactPortrait`: line 789 `DeleteFile(srcFilePath)`, line 790 `DeleteFile(filePath)`, and line 794 `DeleteFile(srcFilePath)`. Each finding is bound to the exact source SHA and has `identity_quality=complete`. This identity quality describes finding identity for the parsed syntax only.

Source inspection confirms `PortraitFileName`, `contactId`, and `rawContactId` are read from the supplied data-share bucket; the local helper checks field lookup validity/type and non-empty strings. The visible function joins `groupPath + portraitFileName` and `groupPath + contactId + "_" + rawContactId`, then passes those paths into portrait processing and deletion. I found no slash/backslash, dot-segment, basename, or canonical-containment check in the reviewed methods. This supports source-to-sink candidates, but does not establish caller trust/reachability, actual root semantics, filesystem impact, product build inclusion, or exploitability.

The D1 head's `direct_replay.py` accepts the command above, validates the canonical repository-relative source path, and this invocation succeeded. History inspection found that an earlier draft at `52d57f1` accepted only positional `SOURCE`, so the pinned-object command was incompatible with that earlier draft. The mismatch is resolved in D1 history from `7abd4fb` onward. As extra reproducibility evidence, I also ran the later owner-review branch script at `6167cf6` against the same bare Git object; it independently returned the same tree/blob/SHA, parser status and three candidate locations. Its JSON is `contacts_path_traversal_20261019/contacts_61lts_exact_object_replay_T20_owner_review_20261020.json`. The earlier script limitation is not a current-head replay failure.

## Controls and test results

Independent focused run:

```powershell
$env:PYTHONPATH='D:/openHarmonyScanner/worktrees/a-t20-contacts-acceptance-20261020/.t20-python-packages'
py -3.10 -m unittest tests.detectors.test_cpp_path_traversal_detector -v
```

Result: 12/12 passed. The suite exercised a cross-function positive; synthetic basename and `starts_with` containment controls; direct separator rejection; no-sink/unrelated API and unrelated field controls; presence-only and reversed-polarity checks; late guard, unrelated receiver, per-sink ordering; and partial-parse retention. The safe-shaped controls are synthetic mechanism tests, not a trusted Contacts fix. The partial control retains findings, sets file outcome `partial`, and run status `blocked`; it is not treated as safe.

The new source verifier independently resolved the pinned commit tree, target blob, byte length, and SHA-256 from the bare repository and passed:

```powershell
py -3.10 research/evidence/cpp/verify_a_t20_contacts_path_traversal.py `
  --git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/applications_contacts_data.git
```

The `cpp` scope check against full PR #30 base `8ec5f56a12e90bba56953b39eb17faa20e154da9` also passed with 0 violations. The check covered 13 changed paths in this worktree, including the existing D1 implementation/test paths and the T20 evidence additions.

I independently queried `catalog_metadata()` and attempted `build_registry(["ohscanner.cpp.path_traversal"])`: the detector is absent from Catalog and selection raises `ValueError: unknown or not-yet-approved detector`. Therefore production CLI coverage is unavailable on this checkout. The direct class replay is prototype evidence only.

## Disposition

- Rule mechanism regression: **PASS** for the submitted bounded prototype against its dedicated synthetic positive/negative/partial controls and the exact A0 object replay.
- A0 case acceptance: **BLOCK**. No trusted fixed Contacts source was found in the request's recorded local object search; no fixed differential can be independently evaluated. Catalog admission and production CLI replay are also outstanding. Caller trust/reachability and filesystem-root semantics remain unknown.
- Claim boundary: these observations establish source-bound static candidates only. They do not establish a confirmed vulnerability, exploitability, accuracy, or product exposure.

Machine-readable record: `a_t20_contacts_path_traversal_acceptance_20261020.json`. Exact replay outputs: `contacts_path_traversal_20261019/contacts_61lts_exact_object_replay_T20_20261020.json` (D1 checkout) and `contacts_path_traversal_20261019/contacts_61lts_exact_object_replay_T20_owner_review_20261020.json` (later owner-review script).

## T20 queue entry

```text
Role: independent A-line C/C++ source and regression acceptance reviewer.
Continuous goal: independently verify D1 Contacts path-traversal candidate behavior against the exact A0 source object and preserve all source, parser, fixed-source, and Catalog limitations.
Inputs: clean PR #30/D1 checkout; A0 pinned Contacts object; path-traversal method card; Catalog request; detector replay and dedicated controls.
Steps: verify repo/commit/tree/blob/SHA; replay the exact vulnerable object using the submitted pinned-object command; inspect candidate locations and source semantics; rerun basename, containment, field, no-sink, separator and partial controls; verify Catalog/CLI selection behavior; record rule regression separately from case disposition.
Done when: source identities, commands, rule version, locations, parse coverage, controls, blockers, and claim boundary are independently recorded; A0/source verification and cpp change-scope checks pass.
Boundaries: do not edit detector, tests, fixtures, or Catalog; do not call synthetic controls a trusted fix; do not promote PARTIAL/BLOCK or infer vulnerability from candidate presence.
```

T20 completed this independent replay on D1 head `24b1140`; rule mechanism regression is PASS and the Contacts case remains BLOCK for missing trusted fix, Catalog admission, and production CLI replay. See the linked report and JSON above.
