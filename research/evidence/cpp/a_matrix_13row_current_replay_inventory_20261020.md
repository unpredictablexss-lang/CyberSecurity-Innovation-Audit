

## Focused integer/bounds detector controls (2026-10-20)

Command:

```powershell
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v
```

Result: 20 tests passed. Coverage includes integer/bounds positive shapes, checked/fixed and safe shapes, unrelated accessors/operators, deterministic output, partial-parse and budget fail-closed behavior, and hash-bound fixture control classes. This validates the detector control suite on the integrated checkout; it does not replace the source-bound safe/unrelated controls or product reachability evidence missing from CVE-2025-0587 and CVE-2025-23420. Those rows remain PARTIAL.
