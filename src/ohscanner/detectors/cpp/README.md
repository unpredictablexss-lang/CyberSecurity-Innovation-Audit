# C/C++ detector-local prototype

> Detector Contract v1 is still proposed. Everything below is a detector-local
> pre-freeze implementation and fixture workflow, not an implemented shared
> `ScanRequest/SourceUnit/ScanContext/Detector/DetectorRun` API.

## Selected detector

- ID: `ohscanner.cpp.lifetime`
- Version: `0.1.0-proposed`
- Shape: explicit `std::unique_ptr` owner -> raw `owner.get()` alias ->
  `owner.reset()` -> stale alias dereference before alias rebinding.
- Sync constraint: classify whether reset/use share one scoped mutex lock. The
  lock is never treated as lifetime proof.
- Production execution dependency: Python standard library only. No Semgrep,
  Cppcheck, Clang SA, CodeQL, Joern, network, source mutation, or exploit/PoC.

## Proposed local pieces

- `proposed_contract.py`: detector-local fixture data classes only.
- `lifetime_detector.py`: deterministic narrow detector.
- `proposed_runner.py`: per-job timeout/crash isolation experiment.
- `proposed_toolrun_bridge.py`: read-only mapping to existing
  `ToolRunResult(schema_version=1)` / `ToolDiagnostic`.

The bridge adds no public fields. Explanation, constraints, missing obligations,
source hash, and failure kind remain sidecar concepts.

## Reproduce

From the repository root using Python 3.10+:

~~~text
python3 -m unittest discover -s tests -v
python3 -m research.experiments.cpp.lifetime_sync_slice
python3 -m research.experiments.cpp.bounds_length_parcel_slice
~~~

The first command runs the complete repository suite. The experiment modules
print JSON to stdout and intentionally do not commit generated outputs.

## Result interpretation

- `completed` means execution completed, not safe.
- `partial/failed/not_run/not_applicable` are parsing/coverage states.
- `possible_hit/miss/unknown/not_applicable` belong to benchmark matching and
  are never emitted by this detector.
- Empty diagnostics are not proof of safety.
- Candidate severity/confidence are `unassessed`; review/runtime validation
  remain `not_run`.

## Fixtures and docs

- Lifetime fixtures and exact hashes:
  `tests/detectors/fixtures/cpp_lifetime/manifest.json`
- Bounds/Parcel research fixtures and exact hashes:
  `tests/detectors/fixtures/cpp_bounds_length_parcel/manifest.json`
- Method card:
  `research/methods/cpp/cpp_lifetime_sync_method_card.md`
- ToolRunResult v1 mapping:
  `research/experiments/cpp/toolrunresult_v1_mapping_design.md`
- Holdout design:
  `research/methods/cpp/cpp_lifetime_holdout_plan.md`
