# IB8BCA registered replay addendum

This addendum corrects the scope of the earlier `not_run` statement in `ib8bca_dataview_independent_baseline_20261020.md`. That statement described rule availability only on the older independent test worktree at HEAD `420a71eefab561c9e67cbe07249cecc63deb4cd4`, whose Ark Runtime model did not contain the IB8BCA bindings. It did not establish availability on the planning branch.

## Planning-branch replay

I independently ran the planning worktree at its actual HEAD `85eb0948515e777d53996caf8f7ecb4b87897c90` (which supersedes the previously cited `8193d40e` state). The worktree already contained unrelated modified/untracked files before this replay; I left them untouched. The model on this HEAD includes exact `index_bounds_bindings` for both target commits and paths.

For each source I read the exact file from `D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git`, checked the Git tree/blob identity, computed SHA-256, parsed with `src.parser.ast.parse_source(..., 'cpp')`, then constructed a single-unit `ScanContext` with the bound repository, exact commit, `provenance='git_object'`, `profile_id='light-ast'`, `source_blob_oid`, and AST parse facts. I registered the actual `ArkRuntimeTypeSafetyDetector(model=RuntimeTypeModel())` and called `run_all_with_coverage(context, registry)`.

| Case | Commit / tree | Blob / SHA-256 | Parse | Diagnostic result | Detector and coverage status |
|---|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` / `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `aedb6d26681535371d1e9ed90b697b923b8100e6` / `bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548` | `complete`, 0 parser issues | 1 `ark.runtime.dataview-index-width-bounds` candidate at line 75 | report `blocked`; detector coverage `partial`; unexamined reason `detector_model_incomplete` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` / `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `dce9388e8b7e33c87aec33ac4d067fe40370561b` / `89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386` | `complete`, 0 parser issues | 0 diagnostics | report `blocked`; detector coverage `partial`; unexamined reason `detector_model_incomplete` |

The parent candidate message was: “Candidate only: 32-bit DataView/Atomics index arithmetic reaches a local bounds check,” with `Int32Add(index, elementSize)` in its trace. The fixed result had the limitation `index_width_bounds_arithmetic_not_fully_proven:BuiltinsDataViewStubBuilder::SetTypedValue`. In both cases, coverage reported `applicable_files=1`, `analyzed_files=[]`, `partially_inspected_files` containing the target, `coverage_counts.partial=1`, and aggregate `status=partial`. The detector report itself was `blocked` and included `INCOMPLETE COVERAGE` / `Coverage incomplete or unsupported; do not infer safety` limitations.

Reproduction command used a Python invocation equivalent to:

```python
raw = subprocess.check_output(["git", "--git-dir", source_store, "show", f"{commit}:{path}"])
text = raw.decode("utf-8")
index = parse_source(text, "cpp")
unit = SourceUnit(path, "cpp", text, sha256(raw).hexdigest(),
                  index.parse_status, tuple(json.dumps(x, sort_keys=True) for x in index.parse_issues))
request = ScanRequest(request_id="ib8bca-parent-or-fixed-replay",
                      repository="openharmony/arkcompiler_ets_runtime", commit=commit,
                      snapshot_sha256=snapshot_digest((unit,)),
                      target_id="current-component:openharmony/arkcompiler_ets_runtime",
                      profile_id="light-ast", provenance="git_object")
context = ScanContext(request, (unit,),
                      {"ast": {path: index.to_dict()}, "source_blob_oid": {path: blob_oid}})
registry = DetectorRegistry()
registry.register(ArkRuntimeTypeSafetyDetector(model=RuntimeTypeModel()))
reports, coverage = run_all_with_coverage(context, registry)
```

## Interpretation

This confirms that the planning branch can produce the parent candidate and zero fixed diagnostics under the exact registered rule and source bindings, while the detector model remains incomplete on both inputs. The fixed zero-diagnostic result is not a safe verdict, and the parent candidate is not a vulnerability or runtime bypass finding. The earlier `not_run` result remains accurate only for the older test-worktree base; it must not be generalized to the planning branch.
