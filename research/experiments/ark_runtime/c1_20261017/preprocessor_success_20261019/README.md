# C1 ARM preprocessing success — 2026-10-19

## Result

For the selected `hihope/rk3568` GN output (`out-gn-20261019-retry3`), both ARM actions for `builtins_typedarray_stub_builder.cpp` completed all three compiler operations successfully:

| Action | Preprocess `-E` | Dependency scan `-M` | Macro dump `-dM -E` |
|---|---:|---:|---:|
| `libark_jsoptimizer_set` | 0 | 0 | 0 |
| `libark_jsoptimizer_set_with_maple` | 0 | 0 | 0 |

The captured `.ii`, `.d`, macro dumps, stderr, and machine-readable observation are in `results/`. Both dependency files include the generated runtime headers listed under `generated/` and the generated Musl `features.h` from the GN output. Their hashes and the two output hashes are included in `results/preprocessor_observation.json`.

## Generated inputs

All copied generated headers came from declared GN/Ninja targets in the exact retry3 output. The preserved Ninja logs show those target invocations, their exit codes, and the graph's duplicate-output warnings. `features.h` was produced by the GN-declared Musl header action as recorded in the preceding C1 handoff; it is not manually synthesized. The headers copied here are audit copies; the preprocessing itself ran against the generated files in the isolated output tree.

## Limits and status

- This establishes the effective include resolution and preprocessor macro state for the two selected ARM compile actions.
- Ninja was invoked with `-w dupbuild=warn`; the graph still reports duplicate-output warnings. The two declared ARM object targets later succeeded under a read-only-root namespace after building their prerequisite closure in an isolated source-COW view; this does not establish a clean full graph or product image.
- A supplemental direct Clang invocation and a subsequent exact-profile Ninja build both compiled the two ARM targets. Direct-compile outputs are retained as separate supplemental evidence; Ninja-built outputs and the read-only-root replay are captured in `../ninja_cow_target_build_20261019/`. Neither establishes a full product image.
- The top-level manifest export still has 19 nested gitlink commit trees outside the manifest archive and the missing `vendor/ohemu/common/qemu-run` linkfile source. The complete snapshot and full product build therefore remain partial/blocked.
- C2's 18 dependency semantics remain `unknown` until its per-dependency evidence review consumes this profile.

## Reproduction environment

The observations used the preserved two ARM compile commands from `product_profile_20261019.v1.json`, the pinned OHOS Clang++ 15.0.4 tool package, a no-network container, read-only source/toolchain mounts, and writable output/results mounts. The exact output is under `/home/deepsleep/c-line-c1-profile-20261018/out-gn-20261019-retry3/rk3568` in the WSL Ubuntu scratch area. The source snapshot and profile digest are described in the parent C1 evidence.

The later supplemental object compile ran outside that container boundary. Its results are kept separately and must not be presented as an isolated product build.

## First isolated Ninja object-target attempt (2026-10-19)

The exact profile Ninja binary (SHA-256 `2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b`, version 1.13.2) and Python 3.12.10 (SHA-256 `02e619087c33f723f4bd8e7f7443f35d87d4383d9592de04b66a3c05a5d4f316`) were available in the C1 scratch toolchain. I ran target 1 under separate user, mount, and network namespaces, with the exact source, prebuilts, source-view, and compiler-toolchain mounts read-only and the GN output/evidence mounts writable. The WSL root filesystem itself remained writable; this does not claim the original Docker root-read-only boundary. Boundary details, exact runner, output logs, and hashes are in `../ninja_isolated_build_20261019/`.

Ninja parsed the full product graph with 630 duplicate-output warnings and scheduled 2,870 prerequisite actions. The object target has an order-only `libark_jsoptimizer_set.inputdeps.stamp`; its transitive chain scheduled Musl notice generation before the requested compiler action. That notice generator attempted to write `third_party/musl/COPYRIGHT` into the read-only source mount and failed with `EROFS` (target return code 1). The target object compilation was not reached, and the second ARM target was not attempted. I preserved the read-only source constraint and did not edit Ninja rules or redirect the notice side effect. The product-build gate remains blocked; the earlier two direct Clang objects and preprocessing outputs remain supplemental/profile evidence, not Ninja target-build evidence.


## Exact-profile Ninja target build with read-only root (2026-10-19)

Attempt 6 completed its remaining 136 actions for target 1 and 6 for target 2 in an isolated user/mount/network namespace using the exact `hihope/rk3568` GN output root and a source OverlayFS view whose lower layer was the hash-pinned, read-only manifest snapshot. The overlay upper captured only notice-file copy-ups and Python bytecode cache writes; every upper file that had a lower counterpart was byte-identical, and the source lower remained unchanged. The GN output root and evidence directory were separate writable mounts.

With the full GN output tree mounted at `/src/out` (including `out/preloader/rk3568/compile_standard_whitelist.json`), the two exact Ninja object targets succeeded. A second invocation remounted the namespace root read-only, rejected a root write probe, removed only the two generated object files, and rebuilt each target as `[1/1] CXX`, both rc 0. `ninja -t commands` argv for both targets matches the exact C1 profile action argv; the object hashes, logs, runner, Ruby runtime packages, and source-overlay inventory are in `../ninja_cow_target_build_20261019/`; the complete attempt 6 logs and upper-layer inventory precede the attempt 7 read-only-root replay. Ruby 3.2.3 was staged from Ubuntu Noble packages whose SHA-256 values matched the apt package index and was mounted read-only; networking stayed disabled during each build.

This closes successful exact-profile Ninja builds for the two selected ARM object targets under a read-only-root namespace. It does not build a full product image or resolve the 19 missing gitlinks and the absent `vendor/ohemu/common/qemu-run` linkfile source. The profile's prerequisite output tree was reused incrementally; the read-only-root replay forced both exact target object actions to execute. Duplicate-output warnings remain, so the complete product-build gate stays blocked.
