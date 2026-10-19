# D41 preregistered cross-component source-only holdout

**State before scan:** preregistered, not run. Freeze date: 2026-10-19. Do not tune the detector against these snapshots; any implementation or model change voids this run as a holdout and requires a new frozen source set.

## Frozen detector and run protocol

The baseline is main commit `efb79ee2397396f38bb0df5d4703f55d7977f138`. Detector `ohscanner.data.sensitive_exposure` is version 0.17.0, source model 0.4.0, source-profile catalog 0.1.0, and sink model 0.7.0. The frozen engine bundle SHA-256 is `9d0f2763a97f3fcaaa1841355a89cf8fdd93a422042db2f9dc5a0664dfb0ea9e`; per-file hashes and exact source identities are in [D41 manifest](D41_HOLDOUT_MANIFEST.json).

The six repositories below were selected before executing D on them. They exclude the DSoftBus, AccessToken, IoT Connect, Wi-Fi development profiles and all existing D1–D40 replay fixtures. Each run uses all eligible C/C++ paths from its pinned Git tree under the existing D19 path policy; each component is analyzed twice with no code or model edits between runs. Candidate identity, coverage, source binding, run status, runtime, and peak RSS will be compared. This measures repeatability and cross-component behavior; it does not by itself provide TP/FP/FN or accuracy.

| Component snapshot | Commit | Tree | Eligible C/C++ files |
|---|---|---|---:|
| `openharmony/security_huks` | `4ae4e0db461f137672719d43ffc6c5b1b6c05be8` | `9c922a60d815a34eb96c060274ed863fd3a6fea8` | 537 |
| `openharmony/security_certificate_manager` | `5fcc0b6379567a70176307c281360be2ba281d6b` | `f3e078b356ac0724d8ab267d73ab85e69b9b44ad` | 304 |
| `openharmony/inputmethod_imf` | `7777cba9eb19085af8e7b90088531028d2937460` | `3edaf7b3825158e13177a8ed61fa1689905229ba` | 402 |
| `openharmony/window_window_manager` | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` | `24e60146ba2fe4af3aaef20b306a1e306df44617` | 1,079 |
| `openharmony/telephony_call_manager` | `6638d1b37f278d7ed380d907674820e7467cedf8` | `3eb7742bdcd1507ad75cfe9c580ff7fefe4f9d41` | 393 |
| `openharmony/multimedia_camera_framework` | `085a5d0e2dc1c90a4b676bad55675a1cf12a6380` | `daef3c4c6bc50ead50610846a958c29ae669f0f3` | 1,105 |

Total frozen scope: 3,820 source files. All six local Git checkouts were clean at freeze. Git commit/tree/blob identities are authoritative for the scan input; origin URL is recorded as declared metadata and is not treated as cryptographic proof of publisher identity.

## Labels and review boundary

No independent labels exist yet. A reviewer who did not tune D must assess the frozen source excerpts without being shown the scanner’s risk claim first, then assign `supported_risk`, `protected_safe`, `unrelated`, or `unknown` with line-bound supporting and contradicting evidence. Ambiguous or unreviewed cases remain `unknown`. Machine candidate counts and duplicate-run stability are not TP/FP/FN, and nothing in this study can promote a finding to confirmed.

This is a static component-source study. It does not verify product inclusion, runtime logging configuration, access control, unauthorized readership, attacker reachability, product impact, or a product-fixed-build retest. It cannot satisfy Gate M3.

## Reproduction

After the preregistration commit is recorded, run the frozen replay separately for each component using the repository path and commit from the manifest:

```bash
PYTHONPATH=. .venv-web/bin/python research/data_sensitive/d19_unreviewed_replay.py \
  --repo-dir /path/to/frozen/component \
  --repository openharmony/component_name \
  --commit <manifest-commit> \
  --output-dir research/data_sensitive/D41_HOLDOUT/<component>
```

The replay script executes two same-scope rounds and writes raw reports plus a summary. No network access, ref movement, or source worktree modification is needed. Do not alter the rule, model, path filter, or frozen commits after the manifest is committed.