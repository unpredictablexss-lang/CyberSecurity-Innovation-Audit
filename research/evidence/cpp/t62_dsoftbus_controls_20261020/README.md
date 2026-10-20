# T62 dSoftBus source-control review

Date: 2026-10-20  
Scanner baseline: PR #35 head `81dd4aea9bb51522ac912b33504ef0d2ddb79089`  
Disposition: **BLOCK / PARTIAL**. This adds source-bound control observations and a fresh whole-file replay; it does not close the detector's partial semantic coverage.

## Exact source and replay

The controls and vulnerable candidates are in the same production source blob:

- Repository declaration: `openharmony/communication_dsoftbus`
- Path: `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp`
- Vulnerable commit: `258662cd9840b55a31546a72d91027f6368cea84`
- Tree: `366a4ced9400653c9628c0b677e4ae657c0e7bd8`
- Blob: `a82b71fb5520b02278a4af695bbe918d14c1048e`
- Source SHA-256: `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6`
- Fixed commit: `192f3e11d74beeaa3d879333471deb8a24a7e1c5`; tree `1d58ba0ef706a6f69dd372bd496c8058810882aa`; blob `13ddbe93a7f617784dec0f3761e09f66b5c3217c`; source SHA-256 `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81`.

Both commits were found in `D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-object-store`. The verifier checks commit/tree/path blob identity and raw source hashes against the source record. Provenance is still limited to the recorded Gitcode fetch URL; no signed publisher attestation is claimed.

The current PR #35 scanner checkout reran the complete target file for each immutable source object:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-vulnerable --repository openharmony/communication_dsoftbus --commit 258662cd9840b55a31546a72d91027f6368cea84 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out research/evidence/cpp/t62_dsoftbus_controls_20261020/vulnerable.json --md-out research/evidence/cpp/t62_dsoftbus_controls_20261020/vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-fixed --repository openharmony/communication_dsoftbus --commit 192f3e11d74beeaa3d879333471deb8a24a7e1c5 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out research/evidence/cpp/t62_dsoftbus_controls_20261020/fixed.json --md-out research/evidence/cpp/t62_dsoftbus_controls_20261020/fixed.md
```

The rerun produced five vulnerable candidates at lines 71, 82, 97, 108, and 123, and zero fixed-source candidates. Syntax parsing is complete for both files. The detector reports `partial` semantic coverage (0/1 complete) and `blocked` execution for both; zero findings are not evidence that the remaining source is safe.

## Reviewed production controls

These controls are direct excerpts from the exact vulnerable production blob, not generated fixtures:

| Function | Source lines | Nullability behavior | Control boundary |
|---|---:|---|---|
| `ClientOnJoinLNNResult` | 35–47 | Rejects null `info`; then rejects null `clientProxy` before `OnJoinLNNResult`. | Both early-return branches locally precede the protected field access or member call. This is a same-type proxy safe control plus an unrelated input-pointer control. |
| `ClientOnLeaveLNNResult` | 51–62 | Rejects null `pkgName`; then rejects null `clientProxy` before `OnLeaveLNNResult`. | Both checks return before subsequent use. Same-type proxy safe control plus unrelated input-pointer control. |
| `ClientNotifyHichainProofException` | 128–145 | Allocates the same `BusCenterClientProxy` with `std::nothrow`; rejects null before `OnHichainProofException`. | Strong same-allocation-pattern safe control. The guard's error return exits the function before the call. |
| `ClientOnDataLevelChanged` | 211–225 | Rejects null `pkgName`, `networkId`, and `dataLevelInfo`; separately rejects null `clientProxy` before `OnDataLevelChanged`. | Unrelated argument-null control and same-type proxy safe control. |

Manual control-flow review confirms each listed guard returns from the function before its corresponding dereference/call. The fresh whole-file CLI output contains no diagnostics at these function sites; however, because the same run is `partial/blocked`, that observation is **inconclusive scanner coverage**, not a scanner-validated safe result. The unrelated input controls show expected early returns in source, but they are not claimed as independently evaluated by the detector.

## Status

The source controls improve the independent evidence package, while the core scanner limitation remains: its semantic model does not complete guard/dominance analysis for this file (0/1). Preserve the existing 5/0 differential and `PARTIAL/BLOCK` disposition. Do not promote CVE-2025-26690 to PASS until semantic coverage resolves these controls and product/runtime/reachability evidence is available.

Verifier:

```powershell
python research/evidence/cpp/verify_t62_dsoftbus_controls_20261020.py --source-git-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-object-store
```
