# D18 G-drive repository experiments

Date: 2026-10-18

These experiments used the G-drive OpenHarmony mirror as authorized by the project owner. The missing repositories were cloned into `G:\OpenHarmony-GitCode-Mirror\experiments-20261018-sensitive-exposure\windows-git`; neither existing mirror repositories nor A/B worktrees were modified.

## DSoftBus default-dispatch replay

- Repository: `openharmony/communication_dsoftbus`
- Commit: `0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`
- Tree: `bd915661eedd139df17f249191e2a691e76f7565`
- Scope: the same 9 files bound by the existing source manifest
- Command: `PYTHONPATH=src python -m research.data_sensitive.replay --repo-dir <pinned-repo> --output-dir research/data_sensitive/D18_G_REPO_DSOFTBUS_REPLAY`
- Output: `D18_G_REPO_DSOFTBUS_REPLAY/first.json`, `replay.json`, `summary.json`

Detector 0.13.0 produced one candidate at `core/authentication/src/auth_hichain.c:136`; two same-scope executions had identical candidate identities and coverage. Status is `completed_with_limitations`: 3 files are partial, 6 are not analyzed, and no file is complete. The candidate remains an unresolved cross-file call. This repetition is not an independent holdout, full-component result, or vulnerability confirmation; `validated_vulnerability=0`.

## HiLog sink model review

- Repository: `openharmony/hiviewdfx_hilog`
- Clone ref: `master`; pinned commit: `393d7e9a690edb76ed27e710b472623daf650dc8`
- Tree: `c2d29126676b26aa0ad8c6e2797b3acae1106e54`
- `interfaces/native/kits/include/hilog/log.h`: blob `7db4a31047c91b42e87db4c492d238b13645abad`, SHA-256 `366c1719a81325f6126a002147f0ab48cd178a7a550f83f8e682e4b095bc4cd`
- `interfaces/native/innerkits/include/hilog/log_c.h`: blob `db7eef60ccfcd2db46f5b68fd951455f4bf4cb69`, SHA-256 `fbc7ac09c51afda1536f3b83a6e8fad30fa31918386df6d628e83e618f9333e2`
- `interfaces/native/innerkits/include/hilog_base/log_base.h`: blob `63cc6cf17a3acabccf3a7ee10ce1b62328139834`, SHA-256 `d7cd3611b7f29ff889ba0d42cd908def2346c4cbd0a01bb3dafda7519f7e38ee`

The public header defines `OH_LOG_DEBUG/INFO/WARN/ERROR/FATAL` at lines 267, 284, 301, 318, and 335. Each forwards `type` plus variadic arguments to `OH_LOG_Print`, so the format argument starts at macro argument index 1. The same header declares `OH_LOG_PrintMsg` at line 194 and `OH_LOG_PrintMsgByLen` at line 214; their message arguments are at indexes 4 and 5. The model now records these seven entry points. Regression tests verify that a synthetic modeled sensitive field reaching each entry remains a candidate.

This is sink-signature validation against pinned headers plus a synthetic regression. The default scanner has no HiLog component source profile, so no repository-wide HiLog scan was attempted. The regression does not establish that HiLog itself leaks a secret, and it does not confirm any product vulnerability.

## Default profile check

The AccessToken exact-revision replay was repeated through the default detector dispatch at `D18_ACCESS_TOKEN_DEFAULT_REPLAY.json`. It preserves all 8 candidates and the original `blocked`/partial state. Candidate identities remain authorization-principal flows, not confirmed bearer-secret exposures. Product impact remains unknown; `validated_vulnerability=0`.
