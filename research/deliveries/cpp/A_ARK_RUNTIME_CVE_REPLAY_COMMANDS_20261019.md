# Ark runtime CVE replay commands (2026-10-19)

Run from `D:\openHarmonyScanner\worktrees\a-path-traversal-detector-20261019`, baseline `db77164fdc2af0da02e4d3efc056d84694fd68e8`.

## Source object verification

```powershell
$repo = 'D:\openHarmonyScanner\arkruntime-holdout-history'
git -C $repo show -s --format='commit=%H%nparents=%P%ntree=%T%nsubject=%s' cae11f121c030a90ba41d8e4d866f91292f25892
git -C $repo show -s --format='commit=%H%nparents=%P%ntree=%T%nsubject=%s' 5aa9c035e98911ec7ed28065a2138c2709792a42
git -C $repo show -s --format='commit=%H%nparents=%P%ntree=%T%nsubject=%s' aeee3fd12c03193545edea4b8e0fdfa3d9a03d11
git -C $repo show -s --format='commit=%H%nparents=%P%ntree=%T%nsubject=%s' 1b23531531e768398682582969c2a9f17e72cafe
git -C $repo ls-tree cae11f121c030a90ba41d8e4d866f91292f25892 ecmascript/base/atomic_helper.cpp
git -C $repo ls-tree 5aa9c035e98911ec7ed28065a2138c2709792a42 ecmascript/base/atomic_helper.cpp
git -C $repo ls-tree aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 ecmascript/js_array.cpp
git -C $repo ls-tree 1b23531531e768398682582969c2a9f17e72cafe ecmascript/js_array.cpp
```

File SHA-256 and patch SHA-256 were independently calculated from raw Git object bytes; exact values are in [`A_ARK_RUNTIME_CVE_REPLAY_STATUS_20261019.md`](A_ARK_RUNTIME_CVE_REPLAY_STATUS_20261019.md).

## Upstream vulnerable/fixed replay

```powershell
python -m src.cli.main ohscan-run --repo-dir 'D:\openHarmonyScanner\arkruntime-holdout-history' --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_vulnerable.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_vulnerable.md
python -m src.cli.main ohscan-run --repo-dir 'D:\openHarmonyScanner\arkruntime-holdout-history' --repository openharmony/arkcompiler_ets_runtime --commit 5aa9c035e98911ec7ed28065a2138c2709792a42 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_fixed.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_fixed.md
python -m src.cli.main ohscan-run --repo-dir 'D:\openHarmonyScanner\arkruntime-holdout-history' --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_vulnerable.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_vulnerable.md
python -m src.cli.main ohscan-run --repo-dir 'D:\openHarmonyScanner\arkruntime-holdout-history' --repository openharmony/arkcompiler_ets_runtime --commit 1b23531531e768398682582969c2a9f17e72cafe --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_fixed.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_fixed.md
```

## Synthetic safe / unrelated / partial controls

The control repository was created outside the project tree at:

`C:\Users\DEEPSL~1\AppData\Local\Temp\ohscanner-ark-controls-raw-20261019-35peojm5`

It is synthetic local Git commit `949874ac2a6d598a3642542da98ddc7f6c613ad7` (tree `c2b46a96694f2e6880820656fae5456ece4ac92f`). Each file derives from a commit:path listed in the status report. Safe controls use the fixed source blob; unrelated controls use the other CVE's vulnerable file; partial controls contain only a source prefix (300 bytes for CVE-0587; first 18,000 bytes for CVE-23420). Run commands:

```powershell
$repo = 'C:\Users\DEEPSL~1\AppData\Local\Temp\ohscanner-ark-controls-raw-20261019-35peojm5'
python -m src.cli.main ohscan-run --repo-dir $repo --repository synthetic/ark-runtime-controls --commit 949874ac2a6d598a3642542da98ddc7f6c613ad7 --include controls/cve0587_safe.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_safe_control.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_safe_control.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository synthetic/ark-runtime-controls --commit 949874ac2a6d598a3642542da98ddc7f6c613ad7 --include controls/cve0587_unrelated.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_unrelated_control.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_unrelated_control.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository synthetic/ark-runtime-controls --commit 949874ac2a6d598a3642542da98ddc7f6c613ad7 --include controls/cve0587_partial.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_partial_control.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_0587_partial_control.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository synthetic/ark-runtime-controls --commit 949874ac2a6d598a3642542da98ddc7f6c613ad7 --include controls/cve23420_safe.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_safe_control.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_safe_control.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository synthetic/ark-runtime-controls --commit 949874ac2a6d598a3642542da98ddc7f6c613ad7 --include controls/cve23420_unrelated.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_unrelated_control.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_unrelated_control.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository synthetic/ark-runtime-controls --commit 949874ac2a6d598a3642542da98ddc7f6c613ad7 --include controls/cve23420_partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_partial_control.json --md-out research/evidence/cpp/ark_runtime_replay_20261019/cve_2025_23420_partial_control.md
```

## Focused verification

```powershell
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v
python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane cpp
```

Results: focused detector suite 17/17 passed; current cpp scope check returned zero violations. The scope check enumerates all current changes in the shared worktree, including simultaneous A-line work, and reported the full checked path set to stdout.
