# A-line first-wave independent acceptance (T3)

Date: 2026-10-19 (Asia/Shanghai)

## Checkout and frozen inputs

- Independent validation checkout started at PR #30 base `8ec5f56a12e90bba56953b39eb17faa20e154da9`.
- Frozen commits replayed without conflict, in order: D1 `d556cb079dcc97d39947b661120c4510c044abae`, D2 `e3e8507f47dd6030a32c5c529679ad915662ffa1`, T1 `a4b819419d7e38cd973ba0f4ce93ed05a485bef1`.
- Validation checkout HEAD after cherry-pick: `90d8260` (local cherry-pick IDs differ; the frozen commit contents were not edited).
- The original dirty A-line checkout was not accessed for writing.

## Independent checks

1. `python -m unittest tests.detectors.test_cpp_path_traversal_detector tests.detectors.test_cpp_memory_safety_detectors -v`: **23/23 passed**.
2. Re-ran D1 direct replay against `D:\openHarmonyScanner\openharmony\applications\standard\contacts_data\dataBusiness\contacts\src\contacts_data_ability.cpp`, explicitly passing `--parse-status partial`. It reproduced three path-to-file-sink candidates at lines 792, 793 and 797, detector/rule `ohscanner.cpp.path_traversal` / `ohcpp-path-traversal-source-to-file-sink-candidate-001` version `0.1.0`; run was `blocked`, file outcome `partial`, source hash `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`.
3. Independently reran D2 production CLI on exact local Ark Runtime objects in `D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git`, writing only under `%TEMP%\t3-ark`. Results matched D2's recorded semantic outcome and source identities: CVE-2025-0587 vulnerable/fixed **1/0**, complete parsing, candidate line 71, detector `integer_bounds` 0.2.0; CVE-2025-23420 vulnerable/fixed **5/0**, complete parsing, candidates lines 650, 653, 665, 666, 668, detector `bounds` 0.2.0. Both fixed versions had zero diagnostics. Raw JSON file hashes differ because execution timestamps/run IDs are regenerated; counts, commits, trees, source hashes, diagnostics and coverage were verified from the new outputs.
4. `python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp --repo .`: exit 0, no violations across all committed paths. Initial attempt with `--lane A` returned `unknown lane`; the base policy defines the A-line C/C++ owner lane as `cpp`.

## Case dispositions

| Work | Disposition | Independent evidence and remaining limit |
|---|---|---|
| D1 Contacts `PortraitFileName` path traversal | **PARTIAL** | Initial first-wave replay used a checkout copy, not the exact pinned source. A subsequent T3 follow-up retrieved the specified A0 blob, verified commit/tree/blob/SHA-256, independently established complete parser coverage (0 issues; 57 functions, 525 calls), and reproduced three candidates on those exact bytes. The detector's finding identity remains `partial`; no trusted fixed source is bound; Catalog is not registered and production CLI integration has not been demonstrated. The candidate at `DeleteFile(filePath)` also depends on bucket-field validation semantics. |
| D2 CVE-2025-0587 | **PASS (static regression acceptance)** | Exact pinned vulnerable/fixed commits and complete parsing independently replayed at 1/0; two separately source-bound synthetic safe/unrelated controls independently replayed complete with 0/0. Controls are synthetic and do not prove product safety or precision/recall. |
| D2 CVE-2025-23420 | **PASS (static regression acceptance)** | Exact pinned vulnerable/fixed commits and complete parsing independently replayed at 5/0; two separately source-bound synthetic safe/unrelated controls independently replayed complete with 0/0. Controls are synthetic and do not prove product safety or precision/recall. |
| D2 libtiff CVE-2025-9900 | **PARTIAL** | Frozen evidence reports exact commits and scope but 0/0 with both files partial. This remains unknown, not a safe result. |
| D2 web_webview CVE-2026-27648 | **BLOCK** | Frozen evidence has only a fixed-source replay; vulnerable full translation unit is unavailable and prior full-TU parsing was partial. No differential acceptance is possible. |
| T1 13-row baseline matrix | **PASS as a status/evidence inventory; case outcomes remain mixed** | 13 rows reconcile 12 ledger cases plus Contacts. Distribution is 3 BLOCK, 8 PARTIAL, 2 N/A. Missing exact objects, parser partial, absent fixes and N/A exclusions are explicitly retained; curl's complete-parse baseline miss remains BLOCK, not silently called a detector success. The 0587/23420 PARTIAL values are the unchanged before-baseline statuses, recorded before their synthetic controls were added. |

## Overall first-wave decision

**PARTIAL.** The branch-scope check and focused tests pass. D2's two complete vulnerable/fixed historical pairs independently reproduce. The first wave does not establish end-to-end production coverage for Contacts, and the matrix intentionally retains blocked and partial cases. Do not describe these results as product vulnerability validation, scanner precision/recall, or a completed A-line coverage goal.

## Minimal follow-up items

1. Review the `DeleteFile(filePath)` bucket inputs and obtain a trusted fixed source or retain BLOCK for the fixed comparison.
2. Owner review and, if accepted, Catalog registration for the Contacts rule; then run the production `ohscan-run` path and recheck scope.
3. Keep the D2 synthetic controls labeled synthetic; do not use them to infer project-level safety, precision, or recall.
4. Recover the vulnerable full web_webview translation unit and establish adequate parsing before a differential verdict.
5. Keep T1's missing dsoftbus object pair and all partial/N/A cases in the validation queue; do not translate zero findings under partial coverage into safe.

## D3 incremental audit queue (completed)

This was the first-wave handoff checklist. D3 and T2 were independently replayed below after their frozen commits were provided. Remaining partial/blocked cases and their minimum follow-up actions are listed in the consolidated section.

## Second-wave independent acceptance (D3 and T2)

Date: 2026-10-19 (Asia/Shanghai). The following commits were introduced into this independent checkout from PR #30 base without conflict:

- D3 `d8c7a49860cb5635632f76be7319cf38e2129179` (local cherry-pick `3e76360`).
- T2 `75df609f7f76f11dd31faa695eb3d6e549d02729` (local cherry-pick `b87e2d4`).

### D3 replay and fixture results

- Independently reran production `ohscan-run` on local pinned curl objects from `D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git`, explicit `light-ast` default profile and one-file scope `lib/mime.c`, detector `ohscanner.cpp.resource_lifetime` 0.2.0. Vulnerable commit/tree `01346829096c61b372692f6dc43ffa778c6caccd` / `6ae23d9333713707a02588b44ed238a50e8b3bde`: complete parse, 1 candidate at `lib/mime.c:1118`, rule `ohcpp-resource-lifetime-recursive-cleanup-candidate-003`, source SHA-256 `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d`. Fixed commit/tree `d7546809d5bd548b69ec49fca26565c8f6f0d344` / `52a8416729366487cdd3b6012071f5f8370e769f`: complete parse, 0 findings. Run reports were written under `%TEMP%\t3-curl`, not over the committed evidence.
- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: **5/5 passed**. This independently exercised the hash-bound recursive callback-cycle positive, detached-callback fixed control, unrelated recursive-cleanup control, existing lifetime controls, partial input and budget behavior.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py'`: **148/148 passed**.
- **D3 curl: PASS for the static source-level differential only.** Complete parsing and vulnerable/fixed results reproduce. This is not product-build, call-path, attacker reachability, or impact confirmation.
- **libpng CVE-2026-46675: PARTIAL.** Frozen D3 evidence leaves the selected vulnerable/fix-parent/fixed/OH targets partial; the cited archive/fix identity does not establish a complete parser target here.
- **libpng CVE-2026-33416: PARTIAL.** The selected source units remain parser partial and have no rule candidate; no safe conclusion follows.
- **cJSON CVE-2026-67215: PARTIAL/BLOCK.** Exact OH commit/tree is recorded, but the two-file run has a partial `cJSON.c`, zero findings and no trusted fixed source. The JSON Patch amplification then recursive-delete root cause is distinct from the D3 callback-cycle rule.
- **cJSON CVE-2026-67216: PARTIAL/BLOCK.** Exact OH commit/tree is recorded, but `cJSON.c` parses partial, there is no trusted fixed source, and exponential compare cost is outside this rule's root cause.

### T2 inventory integrity and scope

Independently ran `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: exit 0 and `overall_ok=true`. All 97 source-manifest files (4,364,747 bytes) were present and matched; all 345 IDs/source keys reconcile; JSON and CSV each contain 345 unique rows; original statuses remain 9 `not_reproduced` and 336 `not_testable`; queue counts are 9 `queued_not_reproduced`, 5 `queued_first_batch`, and 331 `paused_pending_evidence`; no missing next-action/ranking fields; all 14 verifier assertions passed. A separate check confirmed the 7 files named in `artifact_hashes.json` have matching sizes and SHA-256 values. The verifier's generated outputs were byte-for-byte unchanged after rerun.

**T2 disposition: PASS for reproducible queue and source-package reconciliation.** This verifies preservation and sorting of A0 evidence, not the truth of 345 candidate conclusions or current availability of every upstream source object.

`python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` and `git diff --check` both pass with no violations. The T1 matrix, D1 replay record, D2 replay record and this report's first-wave section are unchanged from first-wave acceptance commit `333ba323dccb9d9c507b39227a37ec6f86b5731`.

## Consolidated first + second wave decision

**PARTIAL overall.** First-wave current dispositions: D1 Contacts PARTIAL (exact A0 source and complete parser coverage confirmed; detector finding identity remains partial, and fixed source/Catalog/production CLI integration remain); D2 CVE-2025-0587 and CVE-2025-23420 PASS for static regression acceptance after the bound synthetic controls below; libtiff PARTIAL; web_webview BLOCK; and T1's 13-row matrix remains a PASS as a status/evidence inventory with its unchanged *before* statuses (3 BLOCK, 8 PARTIAL, 2 N/A). Second wave adds a passing static curl differential and a passing T2 queue-integrity audit. The remaining libpng and cJSON cases stay PARTIAL/BLOCK. All source-only results remain candidate evidence, not product vulnerability or safety determinations.

## Minimum remaining work

1. Contacts: review the `DeleteFile(filePath)` bucket inputs and obtain a trusted fixed source or retain BLOCK; owner review/Catalog admission and production CLI replay remain separate.
2. D2 historical cases: keep the synthetic controls labeled as synthetic and avoid project safety or precision/recall claims.
3. libtiff/web_webview: address the required parse/context blockers; recover the vulnerable full web_webview source before any differential judgment.
4. libpng 46675/33416: establish adequate parser coverage and source-to-product provenance before claiming more than PARTIAL.
5. cJSON 67215/67216: model their distinct root causes with separate rule identities and positive plus safe/unrelated controls; do not use the callback-cycle rule as coverage.
6. Keep dsoftbus exact-object absence, N/A exclusions, and all 345 A0 queue entries in the task tree with their current status semantics.

## Contacts exact-source identity follow-up

Root supplied the read-only project-object archive `D:\openHarmonyScanner\openharmony\.repo\project-objects\applications_contacts_data.git` for a follow-up to D1. From that archive, T3 independently verified:

- Commit `b02aadfc2d801ee30573fcb2d13490298e146fea` tree is `ef183625ccbc842f47b076eb75e68b665d7c21c6`.
- `dataBusiness/contacts/src/contacts_data_ability.cpp` at that commit is blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`.
- Independently extracted the blob byte-for-byte to a temporary file. The earlier replay used `--parse-status partial` and returned blocked; the follow-up independently parsed the same bytes as complete and reran `direct_replay.py <temp-file> --parse-status complete`. Detector `ohscanner.cpp.path_traversal` 0.1.0 returned `completed`/`complete` and three candidates at lines 789, 790 and 794 under rule `ohcpp-path-traversal-source-to-file-sink-candidate-001`; all diagnostics carry the exact source hash above and `identity_quality=partial`.
- The older cited commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` resolves to tree `2054824c04bb403eeea128a9262edfb3001efa4f` and this path resolves to blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`, which is different from A0's specified blob. Thus the exact A0 source identity is now **confirmed against b02aadf**, and the earlier `341cc3` identity should not be used as that A0 binding.

**Updated D1 disposition: PARTIAL, not identity-blocked.** Exact vulnerable source binding and candidate reproduction pass. On that exact 80,944-byte blob, an independent `src.parser.ast.parse_source(text, language='cpp')` run returned parse status `complete`, 0 parse issues, 57 functions, and 525 calls. The direct harness was then run with `--parse-status complete`; it returned `completed`/`complete`, three findings at lines 789, 790 and 794, and no parser limitation. These findings still carry `identity_quality=partial`, so complete syntax/parser coverage does not upgrade finding identity or establish the source-to-sink security conclusion. This is a direct detector harness, **not production `ohscan-run`**, because Catalog registration is absent. No independently verified fixed Contacts source is available; the fixed comparison and production integration remain BLOCK. The T1 13-row artifact remains an unchanged *before* baseline at PR #30 base: its original Contacts row saying that the baseline had no registered detector and could not run the intended production path remains historically accurate.

## D2 synthetic negative-control follow-up

T3 independently audited D2 commits `67cdad2ad709a1d9c24245ef029e4034a0764c55` (fixture content) and `9030cb911ce462341f32582ce6402c93a974c236` (replay evidence). Manifest commit tree `a2e4a35365d76220cae71064d293fd3807d35521` matched. For each control, T3 independently resolved the commit:path Git blob and SHA-256, checked the recorded snapshot SHA-256, and ran the pinned-source production CLI from this independent checkout with the listed detector and one-file scope:

| Historical root cause | Synthetic control | Blob | Source SHA-256 | Snapshot SHA-256 | Independent result |
|---|---|---|---|---|---|
| CVE-2025-0587 integer narrowing | safe | `edb2bb38680af1d389eba1999537b1ed787d6f25` | `dbda3ff4a7d1a8e4d9ff6e32c81bbb9bb75dbf45a6b98f4476908cb42290b59d` | `5f838e03861046e1703aca83f3b7d30783ffae6053bd96ccc20cae2a8134a5a2` | complete, 0 diagnostics |
| CVE-2025-0587 integer narrowing | unrelated | `f39c1f1c32d875dda79b0d5213ce8a730c8ab8de` | `ce93aab4c98d07d52bf4ea47389485dd435d2e1b7f77c0099d916fe3fe330731` | `8d598a5ffd8b4e2570dcb783a1fab0eb62eea62934e25bf0f98478c37c0e8c81` | complete, 0 diagnostics |
| CVE-2025-23420 mutable-array bounds | safe | `638f884acc3902d9ae37ba6d1db8fe4bb833302e` | `6c5b5bc9f67a5a438b8b6d3f8e6fe7f2899891db5b76235bba46f100f68d196c` | `dd28133bcb96af46d692a6e60796f0b7ad635f39186ac5efc83cdbae6dcc27b0` | complete, 0 diagnostics |
| CVE-2025-23420 mutable-array bounds | unrelated | `3c7520b897b0362f09f90c675f5e6b38d9f7cc47` | `8f44957d94da37d5e48515b2523d2fe08d29e0f914640663be1ba9d9b16d3050` | `da9f468d3e3225c695102c5fb66916d3c810e6d4372b6efa46f8967f1416ff78` | complete, 0 diagnostics |

All four controls are self-authored synthetic code; they are not additional real-project source identities and provide no Precision/Recall estimate. In combination with the already independently repeated exact real vulnerable/fixed pairs (CVE-2025-0587: complete 1/0; CVE-2025-23420: complete 5/0), they close the planned static detector regression matrix for those two root-cause shapes. **Updated T3 dispositions: PASS for static regression acceptance, not product security validation.** The T1 PR #30 before-matrix rows remain PARTIAL as historical baseline results and were not rewritten.

## T1 CVE-2025-26690 independent replay audit

T3 cherry-picked T1 frozen commit `a447b556c2c3da2cbcf2e856bd2c0798b32c48fb` into the independent validation checkout without conflict (local cherry-pick `442077b`). The original `matrix.json` was not edited. Source identities, synthetic snapshot identities, and detector analysis coverage were checked separately.

### Upstream source/blob identity

Using the connected GitHub source for `openharmony/communication_dsoftbus`, T3 independently fetched the file at each exact upstream ref with the GitHub file connector and fetched both commit metadata records:

- Vulnerable ref [`258662cd9840b55a31546a72d91027f6368cea84`](https://github.com/openharmony/communication_dsoftbus/blob/258662cd9840b55a31546a72d91027f6368cea84/core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp): official file connector returned blob `a82b71fb5520b02278a4af695bbe918d14c1048e`. The byte-for-byte local synthetic package copy is 8,502 bytes, has the same Git blob SHA-1, and raw SHA-256 `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6`.
- Fixed ref [`192f3e11d74beeaa3d879333471deb8a24a7e1c5`](https://github.com/openharmony/communication_dsoftbus/blob/192f3e11d74beeaa3d879333471deb8a24a7e1c5/core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp): official file connector returned blob `13ddbe93a7f617784dec0f3761e09f66b5c3217c`. The byte-for-byte local synthetic package copy is 9,387 bytes, has the same Git blob SHA-1, and raw SHA-256 `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81`.
- GitHub commit metadata independently returned the requested commit SHAs. The fixed commit diff includes the target file and null checks; the vulnerable commit's changed-file list does not include this path, as expected for a vulnerable snapshot commit. Neither metadata response exposed the upstream tree ID; these checks do not establish tree-level ancestry or prove the local snapshots contain other upstream files.

**Identity disposition: PASS for the exact upstream commit refs and file blobs/SHA-256; PARTIAL for full upstream commit/tree binding.** The A0 before matrix remains unchanged and historically records `BLOCK` before these source bytes were available locally.

### Independent synthetic-package CLI replay

The two local scan repositories contain only the exact fetched source file. Their commit/tree and M2 snapshot hashes are *synthetic packaging identities*, not upstream commit/tree IDs:

| Variant | Upstream commit / blob | Synthetic scan commit / tree | Snapshot SHA-256 | Parser | Detector / finding |
|---|---|---|---|---|---|
| Vulnerable | `258662cd9840b55a31546a72d91027f6368cea84` / `a82b71fb5520b02278a4af695bbe918d14c1048e` | `4388f103aba08b6a2fc3f232fc02d7c71b330b05` / `eb1090510490b14714786bddaf42095d3e4dc2af` | `25102a7c1fde5d072f082828ed60bbc586309724014d42d6df042845a977b8db` | complete (1 file) | detector coverage partial, blocked; 5 null-deref candidates at 71, 82, 97, 108, 123 |
| Fixed | `192f3e11d74beeaa3d879333471deb8a24a7e1c5` / `13ddbe93a7f617784dec0f3761e09f66b5c3217c` | `67deaf12a16bb5ddf74919554afaf9603dfe7aa7` / `563ed0715afbb5880673d11a0ca1bdf07fda1742` | `c8867f500a082ea923b8aede2735e12d409149f8071900098ee3f96f55e8bf11` | complete (1 file) | detector coverage partial, blocked; 0 findings |

T3 independently re-ran both pinned-source production CLI commands from the T3 checkout (outputs only under `%TEMP%\t3-26690`):

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\a-line-cve-2025-26690-official-fetch-20261019\synthetic-vulnerable --repository openharmony/communication_dsoftbus --commit 4388f103aba08b6a2fc3f232fc02d7c71b330b05 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out $env:TEMP\t3-26690\vulnerable.json --md-out $env:TEMP\t3-26690\vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\a-line-cve-2025-26690-official-fetch-20261019\synthetic-fixed --repository openharmony/communication_dsoftbus --commit 67deaf12a16bb5ddf74919554afaf9603dfe7aa7 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out $env:TEMP\t3-26690\fixed.json --md-out $env:TEMP\t3-26690\fixed.md
```

Both independent outputs matched the recorded synthetic commit/tree, snapshot SHA, raw source hash, parse status, and diagnostic count/lines. The detector coverage object explicitly reports `status=partial`, no `analyzed_files`, and an `unexamined` row whose `parse_status=complete` and `reason=detector_model_incomplete`; each run is `blocked`. Thus syntax parsing is complete while the detector's semantic model is not. The fixed 0 finding is not a safety result.

**Replay disposition: PASS for reproducibility of the static candidate differential; case disposition remains PARTIAL.** Five candidates align with the target entry points, and the fixed source yields zero same-rule findings, but upstream tree IDs are missing, no exact safe/unrelated controls are bound, and the detector itself reports incomplete semantic coverage. Do not promote to PASS for vulnerability detection or safe fixed behavior. Minimal next steps remain: bind the upstream tree objects/IDs, source-bound safe/unrelated controls, and improve/independently assess null-dereference detector coverage on this file.

## D3 second-wave independent acceptance

T3 cherry-picked D3 frozen commit `940409d3670dafd036b0e8afcbdbe479d815230c` into the independent validation branch without conflict; the local validation HEAD is `1b2766830b0437d4cb03e0a33188574bbfc9aa29`. The D3 source commit and the T3 local cherry-pick are preserved separately. No detector, fixture, or D3 evidence files were changed during this audit.

### cJSON rule identity, controls, and exact-source replay

`python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v` passed all 8 tests. The cJSON shapes use distinct rule IDs: `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` for recursive comparison cost and `ohcpp-resource-exhaustion-tree-amplification-candidate-004` for JSON Patch tree amplification followed by recursive cleanup. The tests include compare-cost positive and quiet safe-shaped control, tree-amplification positives for recursive release and patch flows, and a quiet unrelated recursive tree cleanup. These are synthetic regression controls; they do not bind fixed cJSON source.

T3 independently checked all 15 entries in `tests/detectors/fixtures/cpp_resource_lifetime/manifest.json`; every fixture's recorded byte length and SHA-256 matched the local bytes. This includes the compare-cost positive (`c2713c9eae8f450fb9f9885b1381fef585f0e45babd39f015d8666114f911011`) and safe-shaped control (`7f7c503d12a204caffa6e76a5d44745e2cdfcb94b917d632f4d59250d7fbdfcf`), tree amplification positives (`963e43af30e6c363788f69ec2ff16339568a6daa0cc3946c8e42f9f806404d51`, `0f303e3378ca7d311fc27af0f84cba6e211f8823a5896a6578c0749a421e4039`), and unrelated control (`0af7cbf64412eed50eda11a03aa2bac9f74deaf53f3d99be4d2258489f3efe6b`). The manifest labels the compare-cost quiet control `unrelated`; the tree rule has no explicit fixed or guarded safe fixture.

The production CLI was independently run on the exact cJSON source commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`, with scope `third_party/cjson/cJSON.c` and `third_party/cjson/cJSON_Utils.c`. It reproduced both distinct candidates: `cJSON.c:3161` for compare cost (source SHA-256 `427c72055ae68467b451599d36da074351a5ca53f6e103cd30064e32cf0fffbb`) and `cJSON_Utils.c:861` for tree amplification (source SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`). The snapshot SHA-256 was `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`; detector version was `0.3.0`.

The CLI result was `completed_with_limitations`, the detector run was `blocked`, and detector coverage was `partial` with 0 completely analyzed files and both files only partially inspected. Source parsing was 1 complete / 1 partial; even the syntactically complete `cJSON_Utils.c` remained detector-model partial. Both emitted candidates retain partial identity/unknown obligations. No trusted fixed cJSON source is bound. **Disposition: PASS for rule-specific synthetic focused regression and exact-source candidate reproduction only; PARTIAL/BLOCK for CVE-2026-67215 and CVE-2026-67216 detection acceptance and all fixed/safety claims.** The minimal remaining evidence is a trusted fixed source for each root cause, complete detector analysis of the targeted code, and independently bound safe controls where applicable.

### curl same-version vulnerable/fixed replay

The D3 evidence's fixed curl run used detector version `0.2.0`, whereas its vulnerable run used `0.3.0`. T3 independently reran both exact pinned source objects with the production CLI and the same `ohscanner.cpp.resource_lifetime` version `0.3.0`, profile `light-ast`, and one-file scope `lib/mime.c`:

| Variant | Commit / tree | File SHA-256 | Parse and detector coverage | Result |
|---|---|---|---|---|
| Vulnerable | `01346829096c61b372692f6dc43ffa778c6caccd` / `6ae23d9333713707a02588b44ed238a50e8b3bde` | `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` | complete / complete | 1 recursive-cleanup candidate at `lib/mime.c:1118` |
| Fixed | `d7546809d5bd548b69ec49fca26565c8f6f0d344` / `52a8416729366487cdd3b6012071f5f8370e769f` | `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` | complete / complete | 0 same-rule candidates |

Both independent CLI reports identify detector version `0.3.0`; the vulnerable snapshot SHA-256 is `c0ca047682dce16d7aec8a1607b06f7a0420602a6a0ae13b8195f6629a1ac730`, and the fixed snapshot SHA-256 is `cbc4bf484c7dacefd8869f7917b00983569e8d012470e88f278fc6104744c2f6`. The D3 version mismatch is therefore resolved for this static source differential. **Disposition: PASS for same-version static curl focused regression; no product build, product call path, runtime impact, or security confirmation is implied.**

### Consolidated D3 dispositions and follow-up

| Item | T3 disposition | Evidence boundary / minimum remaining work |
|---|---|---|
| D3 distinct cJSON rule IDs and synthetic positive/safe-shaped/unrelated controls | PASS (focused regression only) | All 8 focused tests passed; all 15 manifest hashes verified. The tree rule lacks explicit fixed/safe guarded fixture. |
| cJSON CVE-2026-67215 tree-amplification source replay | PARTIAL/BLOCK | Exact source emits candidate, but detector analysis is partial; no trusted fixed source or product validation. Add fixed source and complete independent target analysis. |
| cJSON CVE-2026-67216 compare-cost source replay | PARTIAL/BLOCK | Exact source emits candidate, but `cJSON.c` parse and detector analysis are partial; no trusted fixed source. Add fixed source and complete target analysis. |
| curl recursive cleanup vulnerable/fixed differential | PASS (static focused regression only) | Same detector `0.3.0`, both complete, 1/0 candidate differential; product impact remains unvalidated. |

The first-wave T1 matrix and D1/D2 dispositions are unchanged by this addendum. Outstanding T3 task: keep the D3 cases in the partial/block queue until fixed cJSON source identities and complete detector coverage are independently available; preserve product-validation limitations for curl and cJSON.

## D4 independent acceptance: libpng parser blockers

T3 cherry-picked D4 frozen commit `f880613d44707a91ffbf2104b0a14292b553acbb` into the independent validation branch without conflict (local cherry-pick `c46a379`). D4 declares D3 baseline `940409d3670dafd036b0e8afcbdbe479d815230c` and detector `ohscanner.cpp.resource_lifetime` `0.3.0`, consistent with the preceding T3 audit. D4 added evidence only; no detector changes were included.

### CVE-2026-33416 source identity and replay

The three D4 raw reports bind the upstream vulnerable source to commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`, and the fixed source to commit `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`, tree `a28bb962645843af84063c77f574f6d88da79f76`. Their explicit four-file scope is `pngset.c`, `png.c`, `pngread.c`, and `pngrtran.c`. The vulnerable per-file SHA-256 values in D4 JSON match T1's recorded source hashes. T3 independently checked the same vulnerable byte set against a local M2 source snapshot and matched all four hashes; it also checked all four fixed byte hashes from the corresponding local M2 snapshot. That local mirror provides equivalent byte content but has synthetic commits `afad740f043acd9bee412677d0a5ff1e046aaa24` / `dcd78000a2e39558bd0b9340633d7acff796d37` and trees `5d18312a3b10c4aa1a488b91ac41d010606640ef` / `444dba821b3f8b58326ce85d0daf056f64029ec7`. These synthetic identities are not substituted for the upstream identities in D4.

T3 reran the production CLI on those exact-byte local snapshots with detector version `0.3.0`, `light-ast`, and the same four-file scope. The vulnerable M2 replay had snapshot SHA-256 `f80ae78bc09612fd5b8c5a925f858b41e15711319d0a794cafeb4764f7ec73d9`; fixed had `21cfd3bac010b1ba63611630ac8381487a9455c24591618cb16bb52e0a600eae`. Both results matched D4: parsing partial on all four files, detector run blocked, coverage partial, and 0 findings. D4's OpenHarmony source snapshot also has the same vulnerable bytes and all-partial/zero result.

**Disposition: PARTIAL/BLOCK.** D4 replay is same-version and consistent with the 940409d baseline; it is not a static differential pass because the targeted source remains parser-partial. No safe inference follows from 0 findings. Exact upstream commit/tree IDs are preserved from D4/T1 records; independent T3 execution was byte-equivalent via local synthetic M2 snapshots because those upstream commits were not available in the T3 local source object store. Product linkage and call sequence remain unverified.

### CVE-2026-46675 source identity and replay

D4 binds the vulnerable and fixed `pngrutil.c` variants as separate byte-bound snapshots under synthetic commit `e283ed5d3a74c0112f092ddb1003c97e0e9a4717` and tree `c78da20c3ffe37b09653eaa3b49c5213745ac4bd`. The vulnerable source SHA-256 independently recomputed from bytes is `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e`; its Git blob SHA-1 is `a4eda54c8cb3d36cf1651dba159067b65030e3aa`, matching T1's upstream v1.6.55 blob. The fixed source SHA-256 is `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`; its blob SHA-1 is `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a`, matching the recorded upstream fix commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`. D4 notes that complete upstream trees are unavailable for this case.

The production CLI was independently rerun against both byte-bound files with detector `0.3.0`, scope `vulnerable-1.6.55/pngrutil.c` or `fixed/pngrutil.c`, and the same synthetic commit/tree. Both runs matched D4 snapshot hashes (`192e4c1ac567f539395a92a383b0f55e22baa49467de510efda1198962064098` vulnerable; `0e27e208e7bb29cbb2a95d76ed7e1ee53959fac13eb529fe6ee6bced724179c1` fixed), parser partial, detector blocked, coverage partial, and 0 findings.

There is one transcription error in `d4_libpng_20261019/README.md`: its vulnerable SHA-256 string has an extra `d` and is 65 characters. The D4 raw JSON, T3 recomputation from file bytes, and independent replay agree on the 64-character hash above. The fixed SHA-256 and both Git blob SHA-1 values match. This is documentation-only and does not change D4 run status.

**Disposition: PARTIAL/BLOCK.** Source-byte identities and same-version replay are consistent, but both target files parse partial; zero findings cannot pass detection or establish the fixed source as safe. Minimum follow-up is a parser-visible target context/complete analysis and reproducible source-bound sequence for the stale zstream transition, plus upstream tree binding if full source-tree identity is needed. Product call-path evidence remains outstanding.

### Consolidated D4 decisions

| Case | T3 disposition | Evidence boundary / minimum remaining work |
|---|---|---|
| CVE-2026-33416 | PARTIAL/BLOCK | Exact vulnerable/fixed byte hashes and 0.3.0 replays agree; all four scoped files are partial and both runs blocked. Obtain usable parser/type context for cross-file owner/release/use sequence and safe/unrelated controls. |
| CVE-2026-46675 | PARTIAL/BLOCK | Vulnerable/fixed SHA-256 and recorded Git blob IDs match; both 0.3.0 runs are partial/blocked. Correct the D4 README SHA typo; obtain complete parser-visible zstream state and caller sequence. |

The existing first-wave matrix, D3 acceptance, and 940409d baseline are unchanged. These replays support the D4 conclusion that no detector change is justified by the current partial parse evidence; they do not establish either source as fixed/safe or validate product exposure.
