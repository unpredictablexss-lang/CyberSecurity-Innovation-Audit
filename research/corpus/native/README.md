# Teammate A native historical corpus

Status: research corpus and evidence bindings only. This directory does not
implement an OHScanner detector and does not assign confirmed vulnerability
verdicts.

## Priority root-cause families

The four historical samples were reviewed on 2026-10-09. The two teammate-A
priority families are `lifetime_uaf` and `oob_write`.

| Family | sample_id | Label basis | Pair analysis unit |
|---|---|---|---|
| `lifetime_uaf` | `c_utils-singleton-uaf-2026-01` | patch and issue | `base/include/singleton.h`, `DelayedSingleton<T>::GetInstance` / `DestroyInstance` |
| `oob_write` | `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | patch and advisory | `ecmascript/js_array.cpp`, `JSArray::SortElementsByObject` |

The other two historical samples remain baseline-only references:
`kernel_liteos_a-getgroups-oob-2025-03` (`concurrency_race`) and
`communication_dsoftbus_null_deref_001` (`null_deref`). They are not promoted
into teammate-A family development in this round.

## Vulnerable/fixed/safe checklist

### `lifetime_uaf`

| Role | Exact commit | Source artifact | SHA-256 | Git blob SHA-1 | Scope |
|---|---|---|---|---|---|
| vulnerable | `bdfafdaafddb01ab7ae13354ce2ada9555d7935c` | `base/include/singleton.h` | `ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4` | `0e0c91010e39558202ab1c7f628c618fd7a09d23` | DelayedSingleton pair, lines 124-151 |
| fixed | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `base/include/singleton.h` | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` | `fb65b4d89ff9c60c54bc6a8e106b06935f23f633` | DelayedSingleton pair, lines 124-146 |
| safe | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `base/include/singleton.h` | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` | `fb65b4d89ff9c60c54bc6a8e106b06935f23f633` | Separate `Singleton<T>::GetInstance`, lines 197-206 |

The safe control is shape-scoped: an eager accessor returning a reference to a
static instance. It shares the fixed file and commit but has a different
analysis unit and is never merged with the fixed-pair result.

### `oob_write`

| Role | Exact commit | Source artifact | SHA-256 | Git blob SHA-1 | Scope |
|---|---|---|---|---|---|
| vulnerable | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `ecmascript/js_array.cpp` | `b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b` | `2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471` | `SortElementsByObject`, lines 638-673 |
| fixed | `1b23531531e768398682582969c2a9f17e72cafe` | `ecmascript/js_array.cpp` | `f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6` | `58266855967e3dc4af97721d3a2fc5417cb887b6` | `SortElementsByObject`, lines 638-671 |
| safe | `1b23531531e768398682582969c2a9f17e72cafe` | `ecmascript/js_array.cpp` | `f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6` | `58266855967e3dc4af97721d3a2fc5417cb887b6` | Separate `CheckStableArrayAndGet` / `CheckStableArrayAndSet`, lines 673-693 |

The safe control is a guard-shape control. Its stable-array and
index-less-than-elements-length checks are separate from the pair and do not
prove guard dominance or universal bounds safety.

## 2026-10-10 native self-built replay

`research/corpus/native/lifetime_uaf_native_run_2026-10-10.json` binds three
independent executions of `ohscanner.cpp.lifetime` on the pinned
`c_utils-singleton-uaf-2026-01` vulnerable, fixed and safe analysis units. The
raw source, native stdout/stderr and normalized outputs are generated only
under ignored `outputs/logs/native_lifetime_replay_2026_10_10/`.

All three benchmark cells are `not_applicable`, not `miss`: the historical root
cause is concurrent `std::shared_ptr` publication/destruction (and the control
uses a static reference), while detector `0.2.0-proposed` covers only a
same-function `std::unique_ptr` owner -> `owner.get()` raw alias ->
`owner.reset()` -> later dereference shape. The vulnerable execution is
`blocked` because the unmodeled `shared_ptr.reset()` leaves rule symbols
incomplete; fixed/safe execution completion is scoped execution only and is not
a safe verdict.

The SHA-256-bound raw bytes match the corpus source artifacts. Their observed
`splitlines`/newline counts are 211 and 213 while the preserved corpus metadata
records 212 and 214; this discrepancy is retained as
`metadata_mismatch_preserved`, not silently corrected or renamed raw-backed.
Full template instantiation, product macros, build dependencies, runtime race
triggering and security impact remain `unknown/not_run`.

## Isolation rules

- A record binds one `sample_id`, one exact commit, one revision, one
  `control_role`, one analysis unit/scope, one source artifact/hash, one
  tool/version/configuration, and one `run_id`.
- Vulnerable and fixed evidence are never joined into one run, result, count or
  report row.
- Safe controls are separate `safe` analysis units. Their future runs cannot
  replace the fixed-pair result.
- A different scope, commit, revision or run requires a new evidence unit and
  `binding_sha256`.
- `possible_hit` means only candidate/rule/region overlap. `miss` means the
  pinned analysis unit completed with adequate parsing but produced no match.
  Failed, partial or missing analysis is `unknown`; an unexecuted tool is
  `not_run`, never `miss`.
- `not_applicable` requires an explicit incompatible-analysis-unit reason.

## Evidence identity binding

Each generated evidence unit binds `sample_id`, `revision`, `control_role`,
repository, full exact commit, pair or safe-control scope, source artifact,
source/tree/blob hashes, tool/version/configuration and `run_id`. Its
`scan_context_identity` is a PR #5 field-name projection:

- request: `request_id`, `repository`, `commit`, `snapshot_sha256`,
  `target_id`, `profile_id`, `provenance`;
- source unit: `path`, `language`, `sha256`, `parse_status`, `parse_issues`;
- shared facts: sample/revision/role/analysis-unit scope and source artifact.

Real Git requests use `target_id="current-component:<repository>"`,
`profile_id="light-ast"` and `provenance="git_object"`. This is not a second
manifest schema. `SourceUnit.text` is omitted because target source is not
committed. The deterministic package is generated under the ignored
`outputs/reports/static_baselines/` directory and is reproducible from the
checked-in corpus metadata.

## Known gaps and exclusions

| Item | State | Reason |
|---|---|---|
| Runtime trigger / TSan / exploitability | `not_run` | Out of scope for this corpus/baseline round |
| Product build, macros, template instantiation | `unknown` | Affected-file snapshots do not recover complete build context |
| Historical multi-tool raw output hashes | unknown | Existing checked-in summaries did not retain those raw hashes; only stable logical references and source/config hashes are bound |
| 2026-10-10 self-built native replay | recorded, method `not_applicable` | Vulnerable/fixed/safe ran separately with source/stdout/stderr/normalized hashes; this unique_ptr/get/reset detector is incompatible with the shared_ptr/static-reference root cause |
| Independent holdout | `not_run` | Current four samples and both safe controls are development/evaluation inputs, not an independent holdout |
| Report-loader `target_id` bridge | `contract-change proposal` | Loader requires `target_id == sample_id`; PR #5 uses `current-component:<repository>` |
| Confirmed vulnerability verdict | excluded | Static matches and patch overlap do not prove concurrency, attacker control, guard dominance or impact |

## License and provenance

Both target repositories are Apache-2.0 at repository level. When source bytes
are retrieved, upstream headers and notices must be retained. This change
commits metadata and hashes only, not target source files.

Evidence provenance is recorded per family in `lifetime_uaf.json` and
`oob_write.json`, including official patch/advisory/issue references and
attribution. No third-party detector code or rule text is copied into these
records. The existing Semgrep vendor profile remains an unmodified MIT mirror
at upstream commit `dae50da6e6e629750f1daec73a01ef9206a372ab`; this corpus
work does not modify it.

## Independent holdout plan

The current four historical samples are a design/benchmark set. The two
safe-shape controls are not holdout samples. No independent holdout result is
claimed.

Before detector tuning starts, the project owner should:

1. Deduplicate candidates by `root_cause_instance_id`, keeping backports and
   duplicate advisories from crossing the split.
2. Select at least one unseen vulnerable/fixed pair per priority family from a
   different repository or independent root-cause instance, plus unrelated
   safe controls.
3. Pre-register repository, exact vulnerable/fixed commits, source paths,
   hashes, analysis-unit compatibility criteria, exclusion rules and raw-cell
   reporting. Commit only the metadata/hash manifest.
4. Freeze the detector method card and configuration, then give the owner a
   sealed holdout manifest hash. The owner retains holdout artifacts outside
   the development checkout.
5. Run the frozen detector once on the holdout and report every cell as
   `possible_hit`, `miss`, `unknown` or `not_applicable`, including parsing and
   execution state. Do not compute Precision/Recall from the small corpus.
6. Mark a sample contaminated and exclude it from independent evaluation if
   its patch, backport or source shape informed detector design.
