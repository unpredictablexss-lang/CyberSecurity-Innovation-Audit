# T25 DataShare CR-0013–CR-0015 independent source audit

## Disposition

The three original A0 rows bind to one exact `datashare_stub_impl.h` blob at DataShare commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`, tree `f731230c116c94d7619f5514c828b33ffac69924`. The frozen queue is 345 rows; these three remain `not_testable / paused_pending_evidence`.

The independently replayed CLI produced two candidate diagnostics, both on constructor writes to `uvQueue_` (header lines 35 and 42). It produced no diagnostic for CR-0014's `extension_` constructor initialization at line 40. The two `uvQueue_` writes are in alternative constructors; ordinary construction executes one of them, before the constructed object is returned. In the selected implementation, all observed request-path `uvQueue_` reads are under `mutex_`; no post-construction field write was found. This source evidence does not establish a same-object unordered cross-thread access pair. It also does not establish destruction quiescence, unusual publication behavior, or the shipped runtime thread model. The cases therefore remain **PARTIAL/BLOCK**, not safe and not confirmed races.

## Source identity and row mapping

The pinned object database was read offline using Git object commands. The exact tree and bytes were independently checked for the header and three implementation/queue files used by the CLI. Full blob IDs, raw SHA-256 values and sizes are in the adjacent JSON. The queue file SHA-256 is `a174c0a74986e8410c53f173b84bb446c59000c3867add612a14e8aab4396d27`.

| A0 row | Frozen location | Source operation | Independent disposition |
|---|---|---|---|
| CR-0013 | `datashare_stub_impl.h:35` | `uvQueue_` assignment in the `JsDataShareExtAbility` constructor | CLI candidate; initialization-only write; no same-object concurrent conflict evidenced; PARTIAL/BLOCK |
| CR-0014 | `datashare_stub_impl.h:40` | `extension_` initializer in the `StsDataShareExtAbility` constructor | No CLI finding; `GetOwner` reads the member and no later assignment was found; lifetime/runtime context incomplete; PARTIAL/BLOCK |
| CR-0015 | `datashare_stub_impl.h:42` | `uvQueue_` assignment in the `StsDataShareExtAbility` constructor | CLI candidate; alternative constructor initialization; no same-object concurrent conflict evidenced; PARTIAL/BLOCK |

The pinned `interfaces/inner_api/BUILD.gn` names `datashare_stub_impl.cpp` and `datashare_uv_queue.cpp` in `ohos_shared_library("datashare_provider")`. This establishes source inclusion in that declared target only. No product manifest, exact shipped profile, runtime, reachability/trigger, concrete impact, build, or TSan execution was verified. The queue `.cpp` is `partial` under the current parser and is not analyzed by this detector run, so queue semantics remain a material coverage limitation.

## Frozen current CLI baseline

Command executed from the scanner checkout:

```powershell
git clone --shared --no-checkout `
  D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_data_share.git `
  research/evidence/cpp/.t25_datashare_source_repo
python -m src.cli.main ohscan-run `
  --repo-dir research/evidence/cpp/.t25_datashare_source_repo `
  --repository openharmony/distributeddatamgr_data_share `
  --commit 560c5cdadf08b4beeb691e93d70ff32cc2dca8bd `
  --include frameworks/native/provider/include/datashare_stub_impl.h `
  --include frameworks/native/provider/src/datashare_stub_impl.cpp `
  --include frameworks/native/provider/include/datashare_uv_queue.h `
  --include frameworks/native/provider/src/datashare_uv_queue.cpp `
  --detector ohscanner.cpp.shared_ptr_race `
  --json-out research/evidence/cpp/a_t25_datashare_cr0013_0015_cli_20261020.json `
  --md-out research/evidence/cpp/a_t25_datashare_cr0013_0015_cli_20261020.md
```

- Detector: `ohscanner.cpp.shared_ptr_race` 0.5.1; rule `ohcpp-shared-ptr-race-candidate-001`.
- Four selected files, 43,135 bytes; parse status 3 complete / 1 partial. Detector coverage is partial because `datashare_uv_queue.cpp` has an incomplete AST and was not analyzed.
- Two diagnostics at header lines 35 and 42, both `uvQueue_`; none at line 40 (`extension_`). Raw CLI JSON and Markdown are retained next to this report.
- Product build/runtime verification: none. Syntax candidates are not race proof; the absence of a diagnostic at line 40 is not a safety verdict.

The temporary local clone used for the offline pinned-object replay was removed after capture. Recreate it with the first command before replaying; the A0 queue, original source checkout, and project object database were read-only.

## Post-freeze development source-binding cross-check

After T25's own source IDs, queue rows, and CLI JSON were frozen, I compared only the source-binding fields in D25 commit `930cd889219cf769d6386ae26176332e37472002`. Its three queue rows, commit/tree, four supporting-file blob/SHA identities, selected source set, and CLI replay provenance match T25. I materialized D25's verifier and its two raw replay JSON files into a temporary evidence subdirectory and independently ran it against the local project-object database and frozen `queue.json`; all three verifier checks passed. The temporary verifier files were removed. D25 finding labels were not used to determine T25's row dispositions.

## Verification and next evidence

Run the read-only source/CLI/queue-row verifier against the full frozen queue and local project object database:

```powershell
python research/evidence/cpp/verify_a_t25_datashare_race_source_audit.py `
  --queue research/deliveries/cpp/a0_triage_20261019/queue.csv `
  --git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/distributeddatamgr_data_share.git
```

Run the full A0 package reconciliation independently with `python -m research.deliveries.cpp.a0_triage_20261019.verify_triage`; expected result is `overall_ok=true`, 345 unique IDs, and unchanged aggregate original/queue statuses. Next evidence needed: complete parsing or a bounded source-level queue model; product profile and API entrypoint reachability; constructor/publication and destructor/call ordering; exact object scheduling/thread-affinity contract; and, only if a plausible same-object unordered conflict is established, a pinned product TSan target. Preserve all three original statuses until those obligations are addressed.
