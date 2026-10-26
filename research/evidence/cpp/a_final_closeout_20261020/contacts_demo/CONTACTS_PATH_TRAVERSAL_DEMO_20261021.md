# Contacts path traversal candidate: reproducible review package

Date: 2026-10-21 (Asia/Shanghai)

## Candidate selection and upstream state

Selected `openharmony/contacts_data` because the existing A-line `ohscanner.cpp.path_traversal` detector produces exact source-bound locations and the isolated harness demonstrates a deterministic file deletion followed by a PoC-only fixed comparison. This is a source/component demonstration, **not a confirmed product vulnerability**. Existing CVE cases such as Ark Runtime CVE-2025-0587/23420 and curl CVE-2026-92391 have useful source-level vulnerable/fixed differentials, but their current artifacts do not provide a stronger target-component runtime demonstration than this Contacts candidate.

- Latest fetched project `origin/main`: `c380a474718e8ec4497aff55b18a1dd38bafa13f` (2026-10-20). GitHub PR #36 is merged at `2a807d58007c48b9fc87795cf961ba4057f89240` and carries the Contacts detector as an explicit opt-in candidate.
- GitHub PR #35, `codex/a-line-static-evidence-followup-20261020`, remains open at `f193636e7b1384f0ca2e360b4ec3b0b0348d9340`; it records the same three Contacts positions and the remaining absence of a trusted upstream fix/product impact. PR #33/#34 are earlier detector/admission branches; PR #36 is the mainline integration.
- `origin/main` fetch succeeded. A later `git ls-remote` request could not reach `github.com`; GitHub connector PR/branch data was used to verify the referenced A-line branches and PR states. This does not claim a refreshed enumeration of every remote A branch.

## Source and detector binding

| Field | Bound value |
|---|---|
| Component | `openharmony/contacts_data`, OpenHarmony-6.1-LTS source line |
| Source commit / tree | `b02aadfc2d801ee30573fcb2d13490298e146fea` / `ef183625ccbc842f47b076eb75e68b665d7c21c6` |
| File / blob | `dataBusiness/contacts/src/contacts_data_ability.cpp` / `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6` |
| File SHA-256 | `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383` |
| Snapshot SHA-256 | `05e048668b58a1778da649164cf2fffaff84677eafeee7d4c87fbf967c3588a2` |
| Detector / rule | `ohscanner.cpp.path_traversal` **0.3.0** / `ohcpp-path-traversal-source-to-file-sink-candidate-001` **0.3.0** |
| Detector implementation SHA-256 | `9ef8642cb2a107028cc7db7dce6ade168f19f7864b79e656afaE6d8b625b9639` |
| Scan disposition | completed; 1 selected file parsed complete; 3 unverified candidates; `validated_vulnerability=0` |

The production CLI replay (`scan.json` / `scan.md`) binds all three observations to that source blob/hash:

| Candidate ID | Location | Observed operation |
|---|---|---|
| `ohscanner.cpp.path_traversal:04e3ef65d0e6ed6b` | `contacts_data_ability.cpp:789` | `DeleteFile(srcFilePath)` on save failure |
| `ohscanner.cpp.path_traversal:42213d591d92fb56` | `contacts_data_ability.cpp:790` | `DeleteFile(filePath)` on save failure |
| `ohscanner.cpp.path_traversal:b48a64b2266545fb` | `contacts_data_ability.cpp:794` | `DeleteFile(srcFilePath)` after success |

The rule labels the candidate `CWE-22`. No CVE is associated with this source evidence. Severity remains **unassessed**: the harness demonstrates file deletion only in its isolated filesystem, while caller control, permission boundary, target builds, and shipped-product impact are unknown.

## Trigger and impact demonstrated

In the `attack` PoC mode, the `PortraitFileName` bucket value is `../../../base/files/victim.txt`, while the harness places the target under a dedicated temporary `/tmp/ohscanner_contacts_demo_20261021/data/storage` tree. If portrait saving fails, the vulnerable source function calls `DeleteFile(srcFilePath)`; the harness observes that `victim.txt` disappears. The safe basename control deletes only its in-tree input and leaves the outside victim intact.

The harness compiles the exact pinned `HandleContactPortrait` function body (source lines 767–797, function SHA-256 `a988128ed2b52c3aed3d6805dbfbd3f3cdf355e1eeb4c03776a85fcac54a9888`) with lightweight local dependency stubs. It does **not** build OpenHarmony or exercise a real DataShare IPC caller. The stub permits `WRITE_CONTACTS`; whether an untrusted caller can supply these fields through a shipped product/API remains unknown. The `fixed` binary adds a PoC-only validation guard; no trusted upstream fixed Contacts commit was found, so this is not upstream patch revalidation.

## Revalidation result

`run_poc.sh` compiles both variants with GCC 16.2.0, C++17 + UBSan and repeats four modes three times each. Compiler identity is recorded in `poc/results/compiler.txt`. All 12 executions exited 0:

- Vulnerable traversal attack: 3/3 pass; victim exists before and is absent afterward.
- Vulnerable safe basename: 3/3 pass; victim remains and only the in-tree portrait source is removed.
- PoC-only fixed traversal: 3/3 pass; victim remains.
- PoC-only fixed safe basename: 3/3 pass; normal in-tree behavior remains.

Representative logs are `poc/results/attack_r1.log`, `safe_r1.log`, `fixed_r1.log`, and `fixed-safe_r1.log`; full repetition summary and executable/source hashes are in `poc/results/run_summary.tsv` and `poc/results/artifact_hashes.txt`. Binary hashes: vulnerable `target_ubsan` = `fc99ecc0677b90eae9ceb282c9f0d12c86c8d12f8a41010a0e091ca2407e63a8`; PoC-fixed `patched_ubsan` = `8d3a125858e810ed5e20d0995454dc1d0ffe0527eeb7d144d182ed70d701258c`.

## Remediation

Validate each filename/identifier as a single path component before constructing a path. Prefer directory-relative file operations anchored to the expected Contacts directory, reject separators and `.`/`..`, and verify canonical containment including symlink behavior. Cleanup on failure should remove only files created by the operation and should recheck that each path remains under the owned directory. The PoC-only guard is a test comparison, not an upstream patch proposal ready for deployment.

## Risk-detail page review

The candidate drawer already showed the rule, candidate CWE, explanation, pinned source excerpt, and evidence obligations. It omitted severity/association state and the source/detector binding on the same screen. `web/src/pages/JobDetail.tsx` now shows severity (`unassessed`), unassociated CVE status, confidence, repository/commit, source SHA-256, Git blob, detector/rule versions, and snapshot SHA-256 next to the source excerpt and obligations. Missing fields display as unavailable/unknown; no CVE or severity is inferred. The backend supplies these values from the fixed report and source re-read.

Updated risk-detail component SHA-256: `5985720b6329798e94477e4713a69528772a8931ecbbf9e28d8140fe36b17999`.

## Reproduction commands

From the OHScanner checkout, acquire the pinned public source object and run the exact-source production CLI replay:

```powershell
git clone --filter=blob:none --no-checkout https://gitcode.com/openharmony/applications_contacts_data.git "$env:TEMP\ohscanner-contacts-source-a0"
git -C "$env:TEMP\ohscanner-contacts-source-a0" fetch --depth=1 origin b02aadfc2d801ee30573fcb2d13490298e146fea
python -m src.cli ohscan-run --repo-dir "$env:TEMP\ohscanner-contacts-source-a0" --repository openharmony/contacts_data --commit b02aadfc2d801ee30573fcb2d13490298e146fea --include dataBusiness/contacts/src/contacts_data_ability.cpp --detector ohscanner.cpp.path_traversal --json-out research/evidence/cpp/a_final_closeout_20261020/contacts_demo/scan.json --md-out research/evidence/cpp/a_final_closeout_20261020/contacts_demo/scan.md
python research/evidence/cpp/a_final_closeout_20261020/contacts_demo/prepare_poc.py --git-repo "$env:TEMP\ohscanner-contacts-source-a0"
wsl --exec bash -lc 'cd /mnt/d/openHarmonyScanner/worktrees/a-line-final-closeout-20261020/research/evidence/cpp/a_final_closeout_20261020/contacts_demo && bash run_poc.sh'
```

Use the scan result's candidate IDs to open the task's **候选证据与人工复核** drawer. The local report and repeatable PoC are the review artifacts; product applicability remains unknown.

## Verification and limits

- C++ path detector unit tests: 12 passed.
- Web tests: 68 passed; TypeScript check and production bundle build passed.
- The Catalog test module was not executable in this turn's installed environments (Windows lacked `fcntl`; WSL lacked the `tree_sitter` package). Prior PR #34 records the WSL detector/Catalog 14/14 integration run; PR #36 records the merged-main full suite. No test waiver is counted as a pass.
- Product build, real Provider/IPC route, caller permission enforcement, exact upstream fixed commit, release-version range, and CVE mapping: unknown/not available.

Regression commands and environment import failures are recorded in `verification.log`.

Hashes of the generated CLI reports: `scan.json` `2cbada60a68308df4f6cab0d73adccff32bb56e646ed8a8749fdd15233de45e3`; `scan.md` `8453f811f5976a66d0a901bcf1d28474729f2c04afd08ece360f7419722fb973`.
