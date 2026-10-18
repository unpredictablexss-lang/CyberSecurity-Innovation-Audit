# D32: multi-repository known-CVE Workbench replay

Date: 2026-10-19  
Detector: `ohscanner.known_disclosed_cves` 0.9.0  
Purpose: verify the explicit opt-in detector path through the real Workbench API, Worker, report serializer, and hash-checked source viewer on fixed G-mirror Git objects.

## Method

The replay uses isolated temporary Workbench data and does not touch the user's live service on port 8765. Each repository is scanned twice with its pinned commit, narrow include paths, and explicit detector ID. Candidate source hashes are checked against the source-viewer response. The local G-mirror working trees are not used as source; Git commit objects are.

## Results

| Repository | Pinned commit | Stable candidate identities | Detector status |
|---|---|---|---|
| `third_party_libpng` | `e57b1079564a02a50321ec528aa6e41884979d32` | CVE-2026-33636 at `palette_neon_intrinsics.c:63,108`; CVE-2026-46675 at `png.h:277` | blocked |
| `third_party_libtiff` | `d4a0516c477dfbaf1153ae295893ab75aadd63d4` | CVE-2025-9900 at `tif_getimage.c:621` | blocked |
| `third_party_curl` | `1386bb128bb060b284309397b97adcaaec21c003` | CVE-2026-92391 at `mime.c:1146` | completed |
| `third_party_cJSON` | `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748` | CVE-2026-67215 at `cJSON_Utils.c:808`; CVE-2026-67216 at `cJSON.c:3067` | blocked |
| `miscservices_pasteboard` | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | CVE-2025-25212 at `pasteboard_service.cpp:222`; CVE-2025-27247 at `pasteboard_service_stub.cpp:41` | blocked |

Ten API/Worker scans across five components retained nine diagnostics covering eight distinct CVE identifiers. All ten source-viewer hashes matched the corresponding candidate source hashes; candidate signatures and source identities were stable across the repeated runs. The machine-readable records, including report hashes and source bindings, are in `D32_KNOWN_CVE_PANEL_REPLAY.json`.

The two CVE-2026-33636 locations are distinct functions in one archive member, not duplicate identities. The G-mirror libpng build metadata lists a patch for that CVE, while the archived upstream tarball still contains the vulnerable shape. This run scans the archive source and cannot establish whether the product build applies that patch.

## Evidence boundary

Every result remains `candidate`; `validated_vulnerability=0`. The blocked statuses are preserved, so stable findings do not imply complete parsing. Component source snapshots do not establish product inclusion, caller reachability, attacker control, affected product releases, or impact. This replay validates API/Worker/report/source-viewer behavior in an isolated TestClient; it is not a live-panel browser test or an independent recall holdout.

Reproduce with:

```bash
.venv-web/bin/python research/data_sensitive/d32_known_cve_panel_replay.py \
  --output research/data_sensitive/D32_KNOWN_CVE_PANEL_REPLAY.json
```
