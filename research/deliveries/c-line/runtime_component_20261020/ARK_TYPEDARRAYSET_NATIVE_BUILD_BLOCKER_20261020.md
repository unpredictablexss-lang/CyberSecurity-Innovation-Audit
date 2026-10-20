# Ark `typedarrayset` Linux-native component run: blocker record

Date: 2026-10-20  
Task: `C-CLOSEOUT-RUNTIME-DEV-20261020`  
Worktree: `codex/c-runtime-dev-closeout-20261020`, base `61434e9b7e867d165f6031b986b23ff83a2f8a46`.

## Result

**Runtime validation was not completed.** No Ark VM binary was built, no official test was run, and no boundary-trigger JavaScript was executed. This record is an environment/build-input blocker, not a runtime result and not evidence that the source candidate is exploitable or safe.

The exact Ark Runtime source was made available on the Linux-native WSL filesystem at `/tmp/ohscanner-ark-a65` by streaming `git archive` from the existing local object store. Its source identity is repository `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. The target files were read from that archive and match these Git blobs and SHA-256 values:

| File | Blob | SHA-256 |
|---|---|---|
| `test/moduletest/typedarrayset/BUILD.gn` | `05cafccad3022f21b4f2164c10450526038a94b7` | `246725e9b9f2e3a1b7557ecde21a529326231246a7cbe17220c13504bf9d149b` |
| `test/moduletest/typedarrayset/typedarrayset.js` | `8ecfb752bf705bc73a8fc4968b0f44997ef62bea` | `e665af2413099b5bc143f67a30f8d97abe5215efc1c57b8dc529cddfff0de492` |
| `test/moduletest/typedarrayset/expect_output.txt` | `208b31b6bb00c73dd508a5fbb75580577ff500dd` | `eae881fa3768a24c3e72edd5b6e345822a1bde63a869cf5935327005a661b039` |

The task tree's independent tester verified that this official case covers ordinary `set` behavior for nine constructors, typed-array and Array sources, holes/undefined, and offset `2`. It does **not** exercise the candidate's large-offset/range-sum wrap path. Also, `test/moduletest/BUILD.gn` does not include `typedarrayset` in `module_test_list`; a module aggregate run would not count as this test. If a runtime becomes buildable, the direct label must be run:

```sh
hb build --product-name rk3568 \
  -T arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset \
  --disable-package-image --disable-post-build
```

Even a pass on that label is only a VM/module smoke. Candidate validation needs a separate bounded JS boundary case and a meaningful source-fixed comparison. The source-derived candidate trigger is more specific than merely passing an offset over `UINT32_MAX`: use a 6145-byte buffer, a `Uint8Array` target view at byte offset 4096 with length 2049, an ordinary non-stable array-like source with `length: 2049`, and offset `18446744073709549568` (`2^64 - 2048`). Source arithmetic predicts the 64-bit range sum wraps to 1 and the narrowed byte write begins at 2048. A controlled test can initialise an alias view spanning bytes 2048–4095 with a sentinel, then assert whether `set` throws and whether that alias changed. A source-path check supports this numeric input: it is exactly representable as binary64 (`0x1.fffffffffffffp+63`, 2048 below `2^64`); `JSTaggedValue::ToInteger` calls `ToNumber` then `NumberHelper::TruncateDouble` in `ecmascript/js_tagged_value.cpp`, and the Set call site converts the result to `uint64_t` without a `SAFE_NUMBER` cap. That establishes conversion plausibility from source, not executed JavaScript reachability, dispatch, exception behavior, or writes. A smaller offset above `UINT32_MAX` alone is expected to hit the range check before the candidate path.

The independent source review found no exact fixed source commit: GitCode master `25863269ac05c2f4d6ab84631f2de58b9aa9cf18` is a descendant of `a65`, but the relevant implementation/helper blobs are unchanged. No temporary source patch or fixture was used as a substitute.

## Environment and isolated preparation

- Host: WSL2 Linux x86_64, kernel `6.6.87.2-microsoft-standard-WSL2`.
- Linux-native `/` filesystem: about 1 TB total, 930 GB available at the end of preparation. `/home` was not writable for the current user, so staging used `/tmp`.
- Python 3.12.15 environment from the earlier setup was available at `/tmp/ohscanner-ohos-build-venv`; HB invoked with that interpreter. System Python 3.14.7 also exists.
- GN was copied as a single file from the existing OpenHarmony checkout to `/tmp/ohscanner-tools/usr/bin/gn`; version `2026 (47b40ef4)`, SHA-256 `aa76f11ec5ab820695fdd0973d644d205305b1a23fabcc43e230871f502230a7`.
- Ninja 1.13.2 was fetched as a Debian package and unpacked without system installation into `/tmp/ohscanner-tools/usr/bin/ninja`; SHA-256 `5b4ca0a4aa1a83db4dccdf3e375c0b4b44cd907cd17546d51fda59ecffec3e16`.
- The matching OpenHarmony `build` repository was archived to `/tmp/ohscanner-oh-src/build` from commit `6b6d6533967db07e8e7d40d140fc63d0faabacbd`, tree `d58b57c4bc6273a51e182a1014eea26ae60df028`.
- The local manifest file was inspected only for identity: `.repo/manifest.xml` SHA-256 `33d794c99c197c2eb0726ff2cc8c4bcd532e0f3fcd75eaea3fbd10bd53675d25`.
- The Ark tree and build repository were extracted to Linux-native `/tmp`; the user checkout and shared `openharmony/out` were not used as build output. The exact source tree is unmodified. The isolated `/tmp/ohscanner-oh-src/.gn` was briefly changed to disable `ohos_components_support` for a diagnostic-only GN probe, then restored from the checkout. This artificial configuration is not treated as a product build.
- No build process remains running. No Ark source or files outside the assigned worktree were edited.

## Attempts and observed stopping points

1. Ordinary direct GN generation against the native staged root:

   ```sh
   /tmp/ohscanner-tools/usr/bin/gn gen /tmp/ohscanner-oh-src/out/host --root=/tmp/ohscanner-oh-src
   ```

   After restoring the checkout's `.gn`, GN stopped because `parts_info/components.json` is absent. The staged source is not a complete OpenHarmony checkout/product tree.

2. Diagnostic-only probe: in the isolated copy of `.gn`, set `ohos_components_support = false`, then rerun the same GN command. GN advanced to `build/config/BUILDCONFIG.gn` and stopped because the product preloader output `out/preloader/${product_name}/build_config.json` is absent. Turning the component switch off is not an acceptable production configuration and this probe does not establish build success.

3. Actual HB invocation in the native staged source root:

   ```sh
   cd /tmp/ohscanner-oh-src
   timeout 90 /tmp/ohscanner-ohos-build-venv/bin/python build/hb/main.py build \
     --product-name rk3568 \
     -T arkcompiler/ets_runtime/test/moduletest/typedarrayset:typedarrayset \
     --disable-package-image --disable-post-build
   ```

   HB exited `255` before preloading or GN generation: `Invalid built-in product path: /tmp/ohscanner-oh-src/productdefine/common/products`. The native staging copy contains Ark Runtime and the `build` repository, not the complete product/source manifest workspace. Full stdout/stderr is in `logs/hb-native-target.log`; GN probe output is in `logs/gn-default.log` and `logs/gn-diagnostic.log`.

The prior WSL/NTFS attempt against `/mnt/d` is not reused as this run's evidence. Linux-native archiving avoided that full-tree read bottleneck for the exact Ark and `build` Git repositories. Building still requires product and platform repositories and generated metadata that are not present in the native staging root. Recreating those through HB would require the complete OpenHarmony manifest checkout and preloader inputs; selectively fabricating product metadata would make the run nonrepresentative.

## Minimum continuation condition

Provide or materialize a complete checkout of the manifest-pinned OpenHarmony product/build inputs on a Linux-native filesystem, including the product definition for `rk3568`, `parts_info/components.json`, matching `device`/`vendor`/Ark dependencies, host toolchain inputs, and per-product preloader outputs generated in that same native tree. Then run the direct target above with an independent output directory and bounded time/memory. If the VM builds, run the official target as smoke and separately add the smallest reproducible array-like boundary case; do not claim a fix comparison unless an exact fixed source commit and matching binary are available.

