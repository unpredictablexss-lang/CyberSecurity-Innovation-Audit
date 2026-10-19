# D54 — libpng lifetime detector replay

Date: 2026-10-30 (Asia/Shanghai)
Baseline: `dac497e85b55baf9279368469047fc142b325ea6`
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`
Disposition: **no rule change; both cases remain PARTIAL/BLOCK**.

## Replay results

| Case | Variant | Commit / tree | Exact target scope | Parse / rule coverage | Findings |
|---|---|---|---|---|---:|
| CVE-2026-33416 | vulnerable | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | `pngset.c`, `png.c`, `pngread.c`, `pngrtran.c` | 4/4 partial; 0 complete | 0 |
| CVE-2026-33416 | fixed v1.6.56 | `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` / `a28bb962645843af84063c77f574f6d88da79f76` | same four files | 4/4 partial; 0 complete | 0 |
| CVE-2026-46675 | vulnerable | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | `pngrutil.c` | 1/1 partial; 0 complete | 0 |
| CVE-2026-46675 | fixed | `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` / `4c64b5f18cef7d129adee3b403fc4be93f82e30d` | `pngrutil.c` | 1/1 partial; 0 complete | 0 |

Each full-source run used the current production `ohscan-run` CLI, `light-ast`, and the same detector selection. Raw outputs are the four `d54_libpng*_cli_20261030.json` files beside this report. The exact target file SHA-256 values and run snapshot identities are recorded in the JSON evidence; `verify_d54_libpng_lifetime_20261030.py` checks them against the pinned Git objects.

## Root/model assessment

For **33416**, the exact vulnerable/fixed source pair is trusted and hash-bound. Source review links `png_set_PLTE`'s shared allocation at `pngset.c:791–792`, `png_free_data` at `png.c:654–658`, and later palette/transparency use in `png_do_expand_palette` (`pngrtran.c:4328–4497`). Current parser output does not preserve the needed typed member identity and cross-file call/state relation; all four source units are partial on both sides. The zero/zero CLI result therefore does not prove detector silence on a comparable complete representation or validate the fix.

For **46675**, the exact vulnerable and upstream fixed `pngrutil.c` sources are hash-bound. D34's pinned fragment replay has six complete function fragments and one partial (`png_handle_iCCP`) on each side, with zero candidates. Those isolated slices omit the zstream declaration and the full call/state order. The reported stale `zstream.next_in/avail_in` relation across chunk decompression and later IDAT inflate is not representable as a verified same-object lifecycle in the present parser model.

The exact fix identities are credible upstream source controls, but neither current fixed-side run is a detector fixed pass because its target remains partial. No rule change is supported without guessing from repository/function/field names or stitching fragments. Keep both as **PARTIAL/BLOCK**, not safe and not fixed-pass.

## Minimum missing input

- For 33416: parser-visible declarations/types and direct-call/cross-file field-state context for the four-file scope, plus source-bound safe/unrelated lifecycle controls under that context.
- For 46675: a parser-visible bounded path joining `png_struct` zstream field declaration, chunk decompression, release/detach and later IDAT consumption, plus independently sourced safe/unrelated lifecycle controls.
- Do not make parser-partial files appear complete by synthetic fragment stitching. Product build and application reachability remain separate unknowns.

## Verification

```powershell
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v
python research/evidence/cpp/verify_d54_libpng_lifetime_20261030.py --libpng-git-dir D:\openHarmonyScanner\tmp\libpng-gitlab-mirror-pins-20261019.git --46675-git-dir D:\openHarmonyScanner\tmp\t34-libpng46675-source-20261023.git
python research/evidence/cpp/verify_d34_libpng46675_model_assessment.py --source-git-dir D:\openHarmonyScanner\tmp\t34-libpng46675-source-20261023.git
python scripts/check_change_scope.py --base dac497e85b55baf9279368469047fc142b325ea6 --lane cpp
```

The focused detector suite passed (8 tests). A0 was not modified; the 345-row queue remains unchanged. These are static candidate replays, not product vulnerability validation.
