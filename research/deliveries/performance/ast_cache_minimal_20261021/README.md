# AST cache cold/hot smoke comparison — 2026-10-21

## Scope and result

This is a reproducible **minimal local Git fixture**, not the 11-component OpenHarmony corpus and not an ABCD vulnerability-scan benchmark. The fixed fixture commit is `48ff11b0cf9c2490c9e8b9686267a91216cff263` (tree `242954da691567b6cfe412412c88eff61f030a07`), with three C++ files (97 bytes): two complete parses and one partial parse. The demonstration-only `ohscanner.example.cpp.copy-calls` detector emitted one unverified syntax candidate; one partial file remained unexamined. Both runs reported `completed_with_limitations`.

| Measure | Cold | Hot |
|---|---:|---:|
| Outer wall time | 1.9241 s | 1.6654 s |
| Process CPU time | 0.257626 s | 0.238899 s |
| Peak RSS | 29,440 KB | 28,160 KB |
| C/C++ AST files actually parsed | 3 | 0 |
| AST cache misses / hits | 3 / 0 | 0 / 3 |
| AST parse stage | 0.011299 s | 0 s |
| Source read stage (including pinned-source recheck) | 0.373112 s | 0.342155 s |
| Detector execution stage | 0.000051 s | 0.000081 s |
| Complete / partial parses | 2 / 1 | 2 / 1 |
| Candidate count / unexamined files | 1 / 1 | 1 / 1 |

The normalized result signatures match (`92af33a836bfba61a62130d9dc9651b22cf9bdf8da3e8e45370dacbd4e499183`), and `hot.json` records `comparison.identical=true`. This single tiny run pair verifies cache hits and result/coverage equivalence. The wall-time observation is not sufficient to claim a general acceleration; much of this sample's time is process startup and Git source reading.

## Environment and reproduction

- Host: WSL Linux; Python 3.12.15; Git 2.53.0.
- Parser packages: tree-sitter 0.26.0, tree-sitter-c 0.24.2, tree-sitter-cpp 0.23.4. JavaScript/TypeScript packages were installed but are not used by this C++ fixture.
- Source tree, manifest, raw cold/hot JSON, Markdown summaries, per-run scanner JSON, and CLI logs are included in this directory. The bundled Git repository preserves the exact commit and tree.
- The fixed 11-component corpus was not present at `$HOME/openharmony-audit/perf-corpus/`, so the requested 11-component cold/hot comparison was not run. The archival 2026-10-14 results are not substituted for current-main measurements.

Reproduce from the project root in an environment with the project dependencies:

```bash
fixture_root="$(mktemp -d)"
mkdir -p "$fixture_root/perf-corpus"
git clone research/deliveries/performance/ast_cache_minimal_20261021/fixture_repo.bundle \
  "$fixture_root/perf-corpus/component"
git -C "$fixture_root/perf-corpus/component" rev-parse HEAD

python scripts/perf_scale_scan.py \
  --manifest research/deliveries/performance/ast_cache_minimal_20261021/manifest.json \
  --targets-root "$fixture_root" \
  --ast-cache-dir "$fixture_root/ast-cache" \
  --json-out "$fixture_root/cold.json" --md-out "$fixture_root/cold.md"
python scripts/perf_scale_scan.py \
  --manifest research/deliveries/performance/ast_cache_minimal_20261021/manifest.json \
  --targets-root "$fixture_root" \
  --ast-cache-dir "$fixture_root/ast-cache" \
  --json-out "$fixture_root/hot.json" --md-out "$fixture_root/hot.md" \
  --compare-json "$fixture_root/cold.json"
```

The comparison signature covers pinned commit/tree/snapshot identity, scope inventory, parse coverage, detector coverage, detector status, diagnostics (including source locations and source hashes), and limitations. Timing and cache counters are excluded from the signature by design.

## Limits

- Cache reuse covers only the versioned C/C++ `light-ast` shared outline for verified Git Blob inputs. It does not cache detector-specific parsing, cross-file facts, headers as semantic dependencies, macros, build configuration, or detector results.
- RSS/CPU are measured by the external process wrapper when supported; in-tool stage timings are emitted in each scanner report. Report writing is included in outer wall time, while the in-tool report-render timer covers Markdown preparation.
- This fixture verifies a partial parse remains partial and its file remains unexamined on cache hit. It says nothing about vulnerability precision/recall, full-corpus performance, or production impact.
