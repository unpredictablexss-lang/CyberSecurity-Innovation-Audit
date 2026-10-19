# CVE-2025-26690 current CLI replay (2026-10-19)

## Result

The current production M2 CLI and registered `ohscanner.cpp.null_dereference` v0.2.0 scanned the exact pinned `bus_center_client_proxy.cpp` on both sides of the historical fix. The vulnerable revision produced five CWE-476 candidates at lines 71, 82, 97, 108 and 123; the fixed revision produced zero. Both selected translation units parsed completely. `validated_vulnerability` remains 0: these are static source candidates, not product vulnerability confirmation.

| Side | Commit | Tree | File blob | File SHA-256 | Bytes | Parse | Candidates |
|---|---|---|---|---|---:|---|---:|
| Vulnerable | `258662cd9840b55a31546a72d91027f6368cea84` | `366a4ced9400653c9628c0b677e4ae657c0e7bd8` | `a82b71fb5520b02278a4af695bbe918d14c1048e` | `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6` | 8502 | complete | 5 |
| Fixed | `192f3e11d74beeaa3d879333471deb8a24a7e1c5` | `1d58ba0ef706a6f69dd372bd496c8058810882aa` | `13ddbe93a7f617784dec0f3761e09f66b5c3217c` | `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81` | 9387 | complete | 0 |

The upstream patch adds a null guard after each `new (std::nothrow) BusCenterClientProxy(...)` allocation and before dereference. The five findings are at those allocation/dereference pairs. They establish a useful historical regression target; allocation failure reachability and product impact remain outside this static scan.

## Reproduction

From the scanner repository root, with a local Git repository containing these exact source objects:

```powershell
$repo = 'D:\path\to\communication_dsoftbus'
$target = 'core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp'
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/communication_dsoftbus --commit 258662cd9840b55a31546a72d91027f6368cea84 --include $target --detector ohscanner.cpp.null_dereference --json-out research/evidence/cpp/dsoftbus_cve_2025_26690_replay_20261019/vulnerable.json --md-out research/evidence/cpp/dsoftbus_cve_2025_26690_replay_20261019/vulnerable.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/communication_dsoftbus --commit 192f3e11d74beeaa3d879333471deb8a24a7e1c5 --include $target --detector ohscanner.cpp.null_dereference --json-out research/evidence/cpp/dsoftbus_cve_2025_26690_replay_20261019/fixed.json --md-out research/evidence/cpp/dsoftbus_cve_2025_26690_replay_20261019/fixed.md
```

The isolated replay repository was fetched from `https://gitcode.com/openharmony/communication_dsoftbus`; both commit trees and file blob IDs match the historical benchmark binding. Full normalized CLI JSON and Markdown outputs are stored beside this README. The detector remains opt-in; this replay does not add it to ordinary default profiles because unrelated control noise still needs independent review.
