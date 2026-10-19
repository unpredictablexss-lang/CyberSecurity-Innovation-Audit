# D40: high-recall sensitive logging on an unreviewed Wi-Fi component

## Result

On the pinned `openharmony/communication_wifi` commit `e336c82b3b107d87f68c5e0448cc246b50b53b38` (tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`), D's 0.17.0 detector now retains the public-log call at `wifi/services/wifi_standard/wifi_framework/wifi_toolkit/utils/softap_parser.cpp:93` as a CWE-532 candidate. The path reads `GetPreSharedKey()`, passes it through `PassWordAnonymize`, then emits it through `WIFI_LOGI` with `%{public}s`. The logger macro resolves in the pinned component header to HiLog Info.

`PassWordAnonymize` masks interior characters but leaves the first and last two characters visible when the passphrase meets the minimum length. That is enough to justify review of residual disclosure, not enough to claim a product vulnerability. This replay is static source evidence only: no product build, runtime log capture, unauthorized reader, or impact has been verified. Finding status remains `candidate`; the aggregate run is `blocked` with partial coverage; `validated_vulnerability=0`.

## Detector changes

D 0.17.0 and sink model 0.7.0 make four conservative changes:

- Normalize the OpenHarmony spelling `PassWord` and recognize `PreSharedKey`/`PSK` as possible key material.
- Exclude clear metadata names such as `passwordId`, lengths, counts, tags and type/allow-list constants from heuristic source seeding.
- Model the reviewed `WIFI_LOGF/E/W/I/D` macro family as format-index-zero logging sinks.
- Inspect nested calls under unsupported statements such as `switch` on a cloned state and merge may-flow effects. The file remains partial/blocked and branch feasibility is not claimed.

The regression suite adds controls for these metadata names, a same-file PassWord helper, a direct WIFI_LOGI sink and a switch-contained logging call. Unsupported control flow remains an explicit limitation.

## Fixed-source evaluation

The offline replay read only the pinned Git tree and used the same 761-file C/C++ scope twice. The prior D19 0.15.0 baseline produced 66 candidates in 48.9814 seconds with 148,692 KiB peak RSS. D 0.17.0 produced 125 candidates in 18.3473 seconds with 149,740 KiB peak RSS; the repeated candidate signatures and coverage were identical. Compared with the baseline, 80 candidate identities were added and 21 removed. These are candidate-set changes, not TP/FP counts. The current run marks 596 files partial and 165 not analyzed; no file was complete. The larger result set shows that source-name fallback improves coverage but still needs candidate triage and semantic refinement. This is not an independent holdout and does not support a precision/recall claim.

Inputs and commands:

```bash
PYTHONPATH=. .venv-web/bin/python research/data_sensitive/d19_unreviewed_replay.py \
  --repo-dir /path/to/communication_wifi \
  --repository openharmony/communication_wifi \
  --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 \
  --output-dir /tmp/d40-wifi-replay
```

Raw per-run reports were kept in `/tmp` during the audit. The fixed source identity is the repository commit/tree, file Git blob and source SHA emitted by the replay tool.

## Workbench path

`D40_WIFI_PRESHAREDKEY_PANEL_REPLAY.py` selects the opt-in Catalog entry and runs the pinned source through scan API, Worker, report persistence and hash-checked source viewer twice. Both runs retain the same candidate identity at line 93, and the viewer SHA-256 matches the source binding. The DetectorRun remains `blocked`, and the report keeps `validated_vulnerability=0`. This verifies the API pipeline for this finding; it is not browser automation or product validation. Raw results: `D40_WIFI_PRESHAREDKEY_PANEL_REPLAY.json`.

## Review and remediation boundary

Do not claim that Wi-Fi product logs expose a recoverable credential to an unauthorized reader. Confirm the exact product build, runtime logging level/privacy policy, the helper's behavior for deployed passphrase lengths, log collection permissions and the effect of the exposed prefix/suffix. If review determines the disclosure is unacceptable, remove the passphrase from the log entirely; log only non-secret state or a bounded status code. Do not rely on partial masking as a security boundary. No patch was applied in this study, and no product PoC was run.