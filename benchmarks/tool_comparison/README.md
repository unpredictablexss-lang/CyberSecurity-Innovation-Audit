# Multi-tool benchmark result protocol
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

This directory defines the comparison protocol, not a vulnerability verdict
engine. Tools are compared under pinned target, commit, scope, machine, and
measurement rules before deciding which capabilities belong in the final
pipeline.

## Current tool roles

| Tool / engine | Current evidence role | PR #4 status |
|---|---|---|
| Semgrep CE | fast pattern candidate generation | adapter done; community + OH rules evaluated |
| Opengrep | Semgrep-compatible engine candidate | same rule set produced matching results in local bake-off |
| Cppcheck | lightweight C/C++ baseline | adapter done; local sample results evaluated |
| CodeQL | data-flow / taint / cross-function evidence | adapter done; single-file no-build sample unit is `not_applicable` |
| Clang Static Analyzer | path-sensitive / symbolic evidence | adapter done for existing baseline JSON |
| Joern c2cpg | single-file CPG / AST-level query candidate | adapter implemented; current nothrow query is syntax evidence |

The normalized contract is `ToolRunResult / ToolDiagnostic`. The merge point is
Candidate / Evidence, not a scanner vote.

## Required comparison fields

Each run records at minimum:

- tool and version;
- target ID and pinned commit;
- files and LOC in scope;
- run status;
- elapsed time;
- optional peak memory;
- normalized diagnostics;
- limitations.

Each diagnostic records:

- provider;
- evidence type;
- file / line / column when available;
- rule/checker ID;
- severity;
- message;
- provisional CWE when available;
- confidence (default unassessed).

## Evidence roles

Normalized `evidence_type` values include:

```text
pattern, syntax, dataflow, control_flow, symbolic, historical, runtime,
permission, web_dynamic, human_review, unknown
```

These labels describe what kind of evidence a tool contributes. They are not
weights and they are not votes.

## Metrics and fairness

For historical ground-truth samples, report raw hit / miss / unknown /
not_applicable first. Compute aggregate Precision / Recall only when the labeled
sample set is large and balanced enough to support those metrics.

For current OpenHarmony source, true negatives and false negatives are
incomplete. Prefer:

- candidate counts;
- top-k manual-review yield;
- unique root causes after deduplication;
- review cost / time;
- runtime and peak memory;
- coverage and failed-analysis counts.

Do not report full-project Recall on an unlabeled current tree.

## Interpretation boundary

A warning from any scanner is a Candidate / Evidence record, not a vulnerability.
Multiple tools reporting the same location do not automatically make it a
vulnerability. Zero diagnostics from one tool do not prove safety.

Root-cause overlap is descriptive: it means a tool touched a known affected
file / symbol region. It is not a TP, not proof of exploitability, and not a
reportable vulnerability.

## Adapter implementation

The current branch provides five format-only adapters:

- `src/providers/semgrep.py`: Semgrep JSON -> ToolRunResult
- `src/providers/codeql.py`: CodeQL SARIF -> ToolRunResult
- `src/providers/clang_sa.py`: existing Clang baseline JSON -> ToolRunResult
- `src/providers/cppcheck.py`: Cppcheck XML -> ToolRunResult
- `src/providers/joern.py`: saved project query JSON -> ToolRunResult
- `src/providers/registry.py`: one `normalize_tool_output(...)` entry point

All adapters receive an `AdapterContext` containing the pinned target, commit,
scope, time, and memory metadata.

Adapters do not execute scanners and do not perform runtime validation. Their
only responsibility is to preserve native diagnostics while translating them
into the common schema.

## Commands

Normalize a native tool report:

```bash
python -m src.cli normalize-tool-output \
  --provider semgrep \
  --input outputs/native/semgrep.json \
  --target-id <target-id> \
  --commit <pinned-commit> \
  --scope-files <n> \
  --scope-loc <n> \
  --elapsed-seconds <seconds> \
  --json-out outputs/reports/semgrep.normalized.json \
  --md-out outputs/reports/semgrep.normalized.md
```

Compare two or more normalized `ToolRunResult` JSON files:

```bash
python -m src.cli compare-tools \
  --report outputs/reports/semgrep.normalized.json \
  --report outputs/reports/cppcheck.normalized.json \
  --json-out outputs/reports/tool_comparison.json \
  --md-out outputs/reports/tool_comparison.md
```

Generate the historical benchmark summary:

```bash
python -m src.cli benchmark-report \
  --samples-dir benchmarks/historical/ \
  --results outputs/reports/summary_inputs.json \
  --json-out outputs/reports/historical_benchmark_summary.json \
  --md-out outputs/reports/historical_benchmark_summary.md
```

`--results` reads saved evidence; it does not run scanners. Without it, every
sample/revision/tool is `unknown`, including the own scanners. The matrix has
separate `vulnerable` and `fixed` rows and includes Joern and OH-specific rules.
Never populate missing runs with empty candidate lists to manufacture a `miss`.

Create a local input manifest (paths relative to the manifest):

```json
{
  "schema_version": 1,
  "runs": [
    {
      "sample_id": "communication_dsoftbus_null_deref_001",
      "revision": "vulnerable",
      "report": "dsoftbus.joern.vulnerable.normalized.json",
      "analyzed_files": ["core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp"]
    },
    {
      "sample_id": "communication_dsoftbus_null_deref_001",
      "revision": "fixed",
      "report": "dsoftbus.clang.fixed.normalized.json",
      "not_applicable_reason": "Missing headers prevented forming a translation unit."
    }
  ]
}
```

Normalized reports must be real `ToolRunResult` artifacts with `target_id` equal
to `sample_id` and `commit` exactly matching the selected sample revision.
Completed runs declare all `analyzed_files` (repository-relative paths); their
count must match `scope_files`. Scope that omits an affected file is `unknown`.
Diagnostics should carry a `symbol` when the provider can establish it (Joern
now preserves query symbols). An affected-file diagnostic without a resolved
symbol is `unknown`; it is never guessed into a hit or silently counted as a
miss. Normalize absolute tool paths to repository-relative paths upstream.

`not_applicable_reason` is allowed only for a saved failed/blocked run; the
artifact is retained as evidence of the incompatibility. A general failure uses
`reason` and stays `unknown`. A successful empty report is `miss` only for its
own sample/revision. Duplicate runs for the same sample/revision/tool are
rejected; choose a run explicitly rather than mixing experiments. Different
rule sets should use different tool identities (e.g. `semgrep_oh`).

To import the existing own-text historical replay, reference its saved report
with `"format": "historical"`. One entry selects one revision; add a second
entry for the fixed revision. The embedded sample/commits and saved candidate
count are checked. AST counters do not count as an AST scanner run.

Output records artifact path, SHA-256, run ID, commit, version, scope, execution
status and tool limitations. An optional `sha256` in an input entry pins the
expected artifact bytes. The summary remains static region coverage, not a
vulnerability report or a claim that the fixed revision is safe.

### Pinned AST symbol mapping and parsing coverage

An input entry may add `"source_repo": "/path/to/component-checkout"` (or a
manifest-relative path). The loader checks the origin owner/repository and
exact pinned commit, then reads `git show <commit>:<file>` for declared files.
It does not checkout a revision or read dirty working files. Missing symbols
are filled only when a complete syntax tree identifies exactly one enclosing
function at the diagnostic line. Missing lines, ambiguous ranges and unknown
function names remain unresolved. Source bytes and parse status/issues are
recorded under `source_snapshots`, with their SHA-256 hashes.

Partial/failed snapshot parsing makes the run's coverage `unknown`, including
when the tool produced no diagnostics. This is conservative syntax coverage,
not a proof of C++ semantic validity, reachability or safety.

`scan --engine ast` now emits per-file `parsing` statuses (`complete`, `partial`,
`failed`) and ERROR/missing-node ranges in JSON and Markdown. Normalized reports
can retain this `parsing` list using repository-relative file paths. Completed
`own_ast` runs require complete saved parsing coverage for all `analyzed_files`;
old reports without coverage remain `unknown`. Other tools with recorded
partial/failed parsing likewise stay unknown. Normalization should preserve
actual run coverage, never replace it with a clean reparse from a different run.

`compare-tools` rejects reports whose target ID, commit, file count, or LOC scope
do not match. It reports per-tool diagnostic/evidence counts and exact file/line
overlap only.

## Team / technical integration

The consolidated implementation plan is documented in:

- `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/143fa63fa479be79fa80ca5f8322c74afecc273c/docs/strategy/team_parallel_multi_scanner_plan.md`

It combines the vertical real-case workflow with the horizontal multi-scanner
benchmark line and fixes the merge point at the normalized Candidate / Evidence
protocol rather than direct code concatenation.
