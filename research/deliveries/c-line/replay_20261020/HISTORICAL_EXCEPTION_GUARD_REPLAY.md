# Exact-bound historical exception-guard replay

The C-line research profile now includes two separately pinned historical
exception-guard samples in addition to its existing C1 target. Detector
version is `0.6.3`; `c_line_static_model()` is model `0.8.14` with profile
revision `c-line-static-contract-v15`.

The added exception-guard bindings are limited to:

| Role | Commit | Source blob | Source SHA-256 |
|---|---|---|---|
| Parent | `c758818dbfd0b146a908d43d21f6ca1706c33783` | `857ad416bc102fcd5d462e9702d2ba7c51f29b6d` | `984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9` |
| Fixed | `81ca57487d04ea30cd11c271e86494a4e130f43e` | `3b9de9d915d767d7a67316145451da2446162884` | `4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0` |

The registered CLI was run against the local immutable Git store
`D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`:

```powershell
python -m src.cli.main ohscan-run --repo-dir 'D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git' --repository openharmony/arkcompiler_ets_runtime --commit c758818dbfd0b146a908d43d21f6ca1706c33783 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out research/deliveries/c-line/replay_20261020/parent.json --md-out research/deliveries/c-line/replay_20261020/parent.md
python -m src.cli.main ohscan-run --repo-dir 'D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git' --repository openharmony/arkcompiler_ets_runtime --commit 81ca57487d04ea30cd11c271e86494a4e130f43e --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out research/deliveries/c-line/replay_20261020/fixed.json --md-out research/deliveries/c-line/replay_20261020/fixed.md
```

| Sample | CLI detector status | Parser | Exception-guard candidates |
|---|---|---|---:|
| Parent | `blocked` | `partial` | 2 (`Filter`, `Map`) |
| Fixed | `blocked` | `partial` | 0 |

The parent diagnostics are source candidates only. The fixed sample's empty
candidate list is not a safety verdict. Both CLI runs report incomplete
coverage and remain blocked because the C++ parser omits portions of these
files; neither is represented as complete analysis. The JSON and Markdown CLI
outputs are saved alongside this report.

Validation: the registered-profile historical adapter and catalog tests pass
with this Git store supplied (`13 passed`); the complete Ark runtime suite
passes without an external store (`152 passed, 3 skipped`). The explicit-store
suite mode also enables a separate parser-owner test that expects a checked-out
working tree at `OHSCANNER_ARK_REPO`; the supplied path is a bare Git store, so
that unrelated checkout-only test is not run in the full-suite invocation.

Only the exact two commits above were added. The existing exact C1 exception
guard binding remains. Other commits, matching file paths, and matching API
spellings do not become applicable through this profile. The historical pair
is a bounded research comparison and does not establish product build
configuration, runtime impact, or a vulnerability verdict.
