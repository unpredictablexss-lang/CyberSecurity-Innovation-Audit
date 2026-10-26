# OHScanner AST cache hot run

This is a reproducible minimal local Git fixture, not the 11-component OpenHarmony corpus and not an ABCD vulnerability-scan benchmark. Fixture commit: `48ff11b0cf9c2490c9e8b9686267a91216cff263`; tree: `242954da691567b6cfe412412c88eff61f030a07`. It has three C++ files (97 bytes): two complete parses and one partial parse. The demonstration detector is `ohscanner.example.cpp.copy-calls`; its one candidate is not a verified vulnerability. Overall status: `completed_with_limitations`.

| Metric | Value |
|---|---:|
| Outer wall time | 1.6654 s |
| Process CPU time | 0.238899 s |
| Peak RSS | 28160 KB |
| Source read stage | 0.342154946 s |
| AST parse stage | 0 s |
| Detector execution | 0.000081459 s |
| Files actually parsed | 0 |
| AST cache hits | 3 |
| Complete / partial parses | 2 / 1 |
| Candidate / unexamined files | 1 / 1 |
| Result signature | `92af33a836bfba61a62130d9dc9651b22cf9bdf8da3e8e45370dacbd4e499183` |

Run details and scanner output are in this directory. `cold.json` and `hot.json` preserve the machine-readable rows; per-run JSON, Markdown and logs are under `cold_components/` and `hot_components/`. The `fixture_repo.bundle` and `manifest.json` supply the exact source revision and inputs. The hot run was compared against the cold run; normalized results and coverage match.

Reproduce from the project root in an environment with project dependencies:

```bash
fixture_root="$(mktemp -d)"
mkdir -p "$fixture_root/perf-corpus"
git clone research/deliveries/performance/ast_cache_minimal_20261021/fixture_repo.bundle \
  "$fixture_root/perf-corpus/component"
python scripts/perf_scale_scan.py \
  --manifest research/deliveries/performance/ast_cache_minimal_20261021/manifest.json \
  --targets-root "$fixture_root" --ast-cache-dir "$fixture_root/ast-cache" \
  --json-out "$fixture_root/cold.json" --md-out "$fixture_root/cold.md"
python scripts/perf_scale_scan.py \
  --manifest research/deliveries/performance/ast_cache_minimal_20261021/manifest.json \
  --targets-root "$fixture_root" --ast-cache-dir "$fixture_root/ast-cache" \
  --json-out "$fixture_root/hot.json" --md-out "$fixture_root/hot.md" \
  --compare-json "$fixture_root/cold.json"
```

The fixed 11-component corpus was not present locally, so it was not run. This tiny one-pair measurement verifies cache behavior and result equivalence; startup and source verification dominate, so it does not establish a general speedup. Partial parse coverage and the unexamined file remain unchanged. Cache reuse only covers the versioned C/C++ single-file `light-ast` summary for verified Git Blob inputs, not detector-specific parsing, cross-file facts, headers as semantic dependencies, macros, build configuration, or detector results.
