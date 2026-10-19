# T5 Contacts source-only semantic review — 2026-10-19

## Disposition

**PARTIAL.** The exact A0 source object is verified, and the target C++ file parses completely. The source contains a direct `PortraitFileName`-to-delete chain matching the disclosed root cause. This is a source review only: D5 is not frozen in this checkout, and this review did not run D5 through the production CLI or its fixtures. No exact fixed source or independently bound safe/unrelated controls were established here.

## Source identity and coverage

- Repository: `openharmony/applications_contacts_data`, component `applications/standard/contacts_data`
- Commit: `b02aadfc2d801ee30573fcb2d13490298e146fea`
- Tree: `ef183625ccbc842f47b076eb75e68b665d7c21c6`
- Target: `dataBusiness/contacts/src/contacts_data_ability.cpp`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`
- The bytes came from official GitHub fetch at the exact commit and were checked against the local `.repo/project-objects` commit, tree, and blob.
- On 2026-10-19, the parent reviewer recorded a read-only `git ls-remote --heads` observation for `https://gitcode.com/openharmony/applications_contacts_data`: `OpenHarmony-6.1-LTS` pointed to `b02aadfc2d801ee30573fcb2d13490298e146fea`; `master` and `weekly_20261019` both pointed to `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`. T5 did not fetch or checkout remote refs.
- The exact target-file object previously verified at `341cc3bf...` is tree `2054824c04bb403eeea128a9262edfb3001efa4f`, blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`, 85,339 bytes, SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`. This differs from A0's `32c6a26...` blob, so the observed `master` and `weekly_20261019` heads do not bind the A0 source or provide a fixed comparison for this case.
- This is only a snapshot of the observed heads and the compared file identities. It does not establish that every historical branch, tag, or commit lacks a fix.
- Parser command: `python -c "from pathlib import Path; from src.parser.ast import parse_source; p=Path(r'D:/openHarmonyScanner/tmp/contacts-t5-b02aadfc-20261019/contacts_data_ability.cpp'); x=parse_source(p.read_text(encoding='utf-8'),language='cpp'); print(x.parse_status, len(x.issues), len(x.functions), len(x.calls))"`
- Result: `complete`, 0 issues, 57 functions, 525 calls for this file. This is file-level parse coverage, not proof of application reachability.

## Two distinct source paths

### A0 disclosed `PortraitFileName` path

At lines 852–889, the bucket extraction accepts a nonempty string after type checking. It does not check path separators, `..`, absolute paths, normalization, or containment. `HandleContactPortrait` (767–797) obtains `portraitFileName`, checks validity/nonempty values, then constructs `srcFilePath = groupPath + portraitFileName` at line 783. It calls `SavePortraitFileAndBlob` at line 787. On failure, line 789 calls `DeleteFile(srcFilePath)`; the success cleanup also calls `DeleteFile(srcFilePath)` at line 794. The implementation of `FileUtils::DeleteFile` in the same commit (`ability/common/utils/src/file_utils.cpp`, blob `7d39485e3b3f253d474d8e49952e16ced7ccd605`, SHA-256 `4de09b2a9de7ad538044e1e0b9f2ea84cc8acf9bf6a5cd1b7431c861a59d181f`) calls `unlink(filePath.c_str())` at lines 208–215 without checking containment.

This is the chain corresponding to the A0 disclosed root cause. `BatchInsert` calls `HandleContactPortrait` through `ProcessSingleInsert` before `InsertExecute` (lines 693–741); later database handling therefore does not guard this file operation. The helper attempts image decoding and can return an error before the caller’s error-path delete. The source supports a candidate chain; product build, permission assignment, and filesystem reachability remain unknown.

### Separate `contactId` / `rawContactId` path

At lines 783–784, `filePath` is constructed as `groupPath + contactId + "_" + rawContactId`. On the failure branch, line 790 passes this separate value to `DeleteFile`. The strings share the type/nonempty extraction helper, but the fields and derived path differ from `PortraitFileName`. A0’s IDs are `1` and `1`, so they do not establish traversal through this secondary path. Keep it as a separate, unproven candidate; do not attribute it to the disclosed A0 root cause.

## Guard polarity probe

The current dirty D1 helper was probed in memory, without changing source, tests, or fixtures:

- `if (path.find_first_of("/\\") != std::string::npos) { return; }` produced `reject_separators_before_io -> ['path']`.
- `if (path.find_first_of("/\\") == std::string::npos) { return; }` produced `[]`.

At that probe instant, the helper classified the reject-when-found guard as safe and did not classify the reversed early-return condition as safe. This is preliminary only: D1 was dirty and still changing, and a helper probe is not production CLI or fixture acceptance. After D5 freezes, independently exercise both guard polarities, a safe filename/containment control, and a no-sink/unrelated control through the CLI and fixtures, recording the frozen commit and rule version.

## Follow-up and minimum missing evidence

T3 should independently rerun after D5 freezes. Bind the frozen D5 commit, rule version, exact input hashes, CLI command, finding locations, and parse status. Until that replay and control evidence exist, keep the overall disposition **PARTIAL**. A fixed source is currently missing; do not treat this as a fixed-pass. Product-level claims also need build/signature/permission and filesystem reachability evidence.
