# Contacts path traversal detector replay (D1)

Date: 2026-10-19. Base: PR #30 head `8ec5f56a12e90bba56953b39eb17faa20e154da9`.

## Exact target identity

The exact A0 vulnerability source is repository `applications/standard/contacts_data`, OpenHarmony `OpenHarmony-6.1-LTS` commit `b02aadfc2d801ee30573fcb2d13490298e146fea`, tree `ef183625ccbc842f47b076eb75e68b665d7c21c6`, path `dataBusiness/contacts/src/contacts_data_ability.cpp`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, Git-object SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. D1 independently retrieved and scanned these exact bytes from the local bare object database.

The earlier D1 draft incorrectly associated this A0 blob with current `master` commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`; master has tree `2054824c04bb403eeea128a9262edfb3001efa4f`, but its target-file blob is `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`, 85,339 bytes, SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`. It is not the A0 6.1-LTS source object.

Exact bytes are read without checkout or line-ending conversion using `direct_replay.py --git-dir ... --commit ... --source-path ...`. The structured result is `contacts_61lts_exact_object_replay_20261019.json`.

## Detector result

- Detector/rule: `ohscanner.cpp.path_traversal` / `ohcpp-path-traversal-source-to-file-sink-candidate-001` / `0.2.0` (D5).
- Scope: one exact Git object translation unit. `src.parser.ast.parse_source` using the `light-ast` profile reports `complete`, with 0 parse issues. Parse completeness is syntax coverage only; macros are not expanded and no product build profile is locked.
- Result before D5: detector run `completed`, file outcome `complete`; 3 candidates at lines 789, 790 and 794 in `HandleContactPortrait`, with finding identity `partial`.
- Result after D5: same three sink locations and source SHA; `identity_quality=complete` for this parsed source because the finding symbol scope, sink call shape and deterministic expression fingerprint are now supplied. This is identity completeness for the syntax observation only; it does not mean a confirmed vulnerability, resolved source trust, path semantics, or control-flow proof.
- Lines 789 and 794 are `fileUtils.DeleteFile(srcFilePath)` on Save failure and success paths. Line 790 is `DeleteFile(filePath)`, where `contactId` and `rawContactId` also flow into the constructed path. Review of the exact A0 source shows `GetStringValueFromDataShareValue` sets `isValid` based on bucket field lookup and non-empty values. `GetPortraitValue` checks each lookup result; `HandleContactPortrait` checks `isValid` and `.empty()`. Neither routine checks slash/backslash, dot segments, basename, or canonical containment for either identifier. Thus the visible bucket checks do not protect `filePath` from path components. Upstream caller semantics and actual filesystem root behavior remain unknown, so line 790 remains a candidate, not a confirmed issue. The helper's `open(srcFilePath.c_str(), O_RDONLY, ...)` is not separately emitted because helper-parameter mapping is outside the current bounded path summary; this remains a known limitation.
- Main root chain: `PortraitFileName` is read as a string field, used in `srcFilePath = groupPath + portraitFileName`, then reaches file deletion without canonical containment in the reviewed method.
- Command: `python research/evidence/cpp/contacts_path_traversal_20261019/direct_replay.py --git-dir 'D:\openHarmonyScanner\openharmony\.repo\project-objects\applications_contacts_data.git' --commit b02aadfc2d801ee30573fcb2d13490298e146fea --source-path dataBusiness/contacts/src/contacts_data_ability.cpp --parse-status auto --json-out research/evidence/cpp/contacts_path_traversal_20261019/contacts_61lts_exact_object_replay_20261019.json`.
- Exact-source detector runtime was 0.177284 seconds in the recorded run (not a performance benchmark). Parser environment: Python 3.13.9, tree-sitter 0.26.0, tree-sitter-c 0.24.2, tree-sitter-cpp 0.23.4; profile `light-ast`, no macro expansion, build profile `none`.
- D1 focused tests: 6 passed; full C++ detector suite: 147 passed. D5 focused tests: `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v` — 9 passed; full C++ detector suite — 150 passed. The refreshed exact-object replay remains parser-complete and has three candidates at lines 789/790/794 with identity complete for these syntax observations.
- The production `ohscan-run` CLI cannot select this detector because Catalog is owner-controlled and unchanged in this branch.

## Fixed-source search and controls

A bounded local bare-object search enumerated 660 commit objects; 659 contained the target file path and the path had 32 distinct blobs. No commit descendants of the pinned 6.1-LTS commit were present. Every non-A0 target blob checked still contained `groupPath + portraitFileName` without a recognized validation marker. This search does not establish the state of unavailable upstream refs; no trusted fixed Contacts source was found locally, so the real fixed comparison remains `BLOCK`.

Synthetic fixed-shaped basename, explicit `starts_with` containment, direct slash/backslash component rejection, unrelated API, and no-sink controls produce no finding. A presence/non-empty-only check and reversed-polarity separator check still report candidates. A deliberately partial input preserves candidates with `partial` identity and reports `blocked`/`partial`; zero findings never imply safety. Separator rejection is recognized only when direct `find`/`find_first_of != npos` means a separator was found and causes an early return/throw in the same function as the sink. Validation in callers or callees is not propagated as a proof. These synthetic controls are mechanism tests only. No precision/recall or product-security claim is made.

Catalog registration requires owner acceptance of `research/deliveries/cpp/CONTACTS_PATH_TRAVERSAL_CATALOG_REQUEST_20261019.md` and a later production CLI integration replay. Case-level acceptance remains `BLOCK` until a trusted fixed source and production Catalog admission/integration are independently verified.
