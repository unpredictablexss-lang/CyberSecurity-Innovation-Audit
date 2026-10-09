# OpenHarmony self-built C/C++ detector prototype

> Detector Contract v1 remains unfrozen. The M0 `ScanRequest/SourceUnit/
> ScanContext/DetectorFinding/DetectorRun/Detector` interfaces and the Runner
> to `ToolRunResult(schema_version=1)` bridge are implemented on this branch,
> but this detector is still versioned `0.1.0-proposed`.

## Selected detector

- ID: `ohscanner.cpp.lifetime`
- Version: `0.1.0-proposed`
- Shape: explicit `std::unique_ptr` owner -> raw `owner.get()` alias ->
  `owner.reset()` -> stale alias dereference before alias rebinding.
- Sync constraint: classify whether reset/use share one scoped mutex lock. The
  lock is never treated as lifetime proof.
- Required shared facts: none. Request provenance and source path/text/SHA-256/
  parse status are mandatory `ScanRequest`/`SourceUnit` fields.
- Production dependency: Python standard library plus the existing OHScanner
  contracts/Runner. No Semgrep, Cppcheck, Clang SA, CodeQL, Joern, network,
  source mutation, or exploit/PoC.

## Current implementation

- `lifetime_detector.py`: M0-compatible deterministic narrow detector.
- Existing `src/ohscanner/runner.py`: per-detector exception isolation and
  read-only mapping to `ToolRunResult(schema_version=1)`.
- `research/experiments/cpp/lifetime_sync_slice.py`: lifetime/sync slice and
  ablation.
- `research/experiments/cpp/bounds_length_parcel_slice.py`: independent
  bounds/length/Parcel research slice only, not a production detector.

The detector sorts and collapses finding identities before returning. The
shared Runner remains the source of `ToolDiagnostic.diagnostic_id` and forces
severity/confidence to `unassessed`.

## Reproduce

From the repository root using Python 3.10+:

~~~text
python3 -m unittest discover -s tests -v
python3 -m research.experiments.cpp.lifetime_sync_slice
python3 -m research.experiments.cpp.bounds_length_parcel_slice
~~~

Experiment modules print JSON to stdout and intentionally do not commit
generated outputs.

## Result interpretation

- `completed/failed/blocked` are execution states only; `completed` is not safe.
- `complete/partial/failed/not_run` are parsing coverage states. Incomplete
  coverage remains unknown and is never a benchmark `miss`.
- `possible_hit/miss/unknown/not_applicable` belong only to an independent
  benchmark evaluator and are never emitted here.
- Empty findings are not proof of safety.
- A finding is `candidate` syntax evidence. Review and runtime validation remain
  downstream and unassessed/not run.
- The cooperative timeout hook only demonstrates detector-local failure
  isolation. The shared Runner still has no hard timeout, process isolation, or
  memory sandbox.

## Fixtures and methods

- Lifetime fixtures and exact hashes:
  `tests/detectors/fixtures/cpp_lifetime/manifest.json`
- Bounds/Parcel research fixtures and exact hashes:
  `tests/detectors/fixtures/cpp_bounds_length_parcel/manifest.json`
- Method card:
  `research/methods/cpp/cpp_lifetime_sync_method_card.md`
- ToolRunResult v1 mapping design:
  `research/experiments/cpp/toolrunresult_v1_mapping_design.md`
- Holdout design:
  `research/methods/cpp/cpp_lifetime_holdout_plan.md`

All fixtures are self-authored synthetic development inputs, not real
OpenHarmony vulnerability samples.
