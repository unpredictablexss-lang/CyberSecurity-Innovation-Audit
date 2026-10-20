# T9 exact-source build-context audit

Date: 2026-10-20 (Asia/Shanghai)  
Scanner worktree: `efa09aaaac01f81084034ea0994c310007ba1dbf`; `src/` is byte-identical to scanner baseline `81dd4aea9bb51522ac912b33504ef0d2ddb79089`.  
Disposition: **PARTIAL/BLOCK** for libpng 33416, libpng 46675, and libtiff 9900. No scanner, test, fixture, or A0 files changed.

## Independent source identity

Fresh local checkouts from the pinned Git object stores were made with `core.autocrlf=false`. Their target-file SHA-256 values match the independent T61/T6 bindings:

| Case | Vulnerable / fixed commits | Target-file SHA-256 (vulnerable / fixed) |
|---|---|---|
| libpng 33416 | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` | `pngset.c`: `9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0` / `d3a203e40b6a6000a7cb78a61e0fd9664b0c39a65d82260efedb0f0184a8bc19` |
| libpng 46675 | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` | `pngrutil.c`: `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e` / `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e` |
| libtiff 9900 | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` / `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `tif_getimage.c`: `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` / `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |

The T61 source-object verifier and T6 source-bound replay verifier pass. The T23 acceptance verifier also passes and retains the 345-row A0 invariant. These checks validate identity and prior status evidence; they do not turn the three cases into passes.

## Compile context and source-map experiment

For both exact libpng revisions in each pair, upstream `configure` was rerun in isolated checkouts under WSL after normalizing CRLF only in the shell helper copies required by WSL. Invocation: `./configure --disable-shared --enable-static --disable-tests --disable-tools`. Generated Makefiles report `CC=gcc`, `DEFS=-DHAVE_CONFIG_H`, `CPPFLAGS` empty, `CFLAGS=-g -O2`, and `DEFAULT_INCLUDES=-I.`. The upstream `make pnglibconf.h` target generated the required configuration header. The `.i` files were produced with `gcc -DHAVE_CONFIG_H -I. -g -O2 -E <target.c>`; GCC line markers are retained as the original-file source map.

The CMake build directories for libtiff contain generated `flags.make` and `build.make` files. The exact target compile/preprocess context is `-DTIFF_DO_NOT_USE_NON_EXT_ALLOC_FUNCTIONS -D_FILE_OFFSET_BITS=64`, include directories for that exact source's `libtiff/` and `out/libtiff/`, `-Wall -Winline -Wformat-security -Wpointer-arith -Wdisabled-optimization -Wno-unknown-pragmas -fstrict-aliasing -std=gnu99`, and `-E`. Their source files' target SHA-256 matches the pinned T6 identities. `.i` outputs retain GCC `#line` markers.

The `.i` artifacts are temporary under `D:\openHarmonyScanner\tmp\t9-preprocessed`; their hashes and sizes are in the machine record. Scanner CLI replays used the exact `.i` bytes at the original source path in disposable derived commits (the generated commit IDs are recorded separately and are not represented as upstream revisions). Results:

| Case / side | Preprocessed CLI parse | Detector | Findings | Interpretation |
|---|---|---|---:|---|
| 33416 vulnerable / fixed (`pngset.c` probe) | partial / partial | `resource_lifetime@0.4.2` blocked / blocked | 0 / 0 | Header/macro expansion did not make the scanner's target file complete; this single-file probe cannot establish the cross-file case. |
| 46675 vulnerable / fixed (`pngrutil.c`) | partial / partial | `resource_lifetime@0.4.2` blocked / blocked | 0 / 0 | Expanded translation unit remains partial; line markers do not currently restore original-line locations in the scanner report. |
| 9900 vulnerable / fixed (`tif_getimage.c`) | exact `.i` generated; scanner CLI not completed | existing whole-file result remains partial / blocked, 0 / 0 | — | A disposable full Git checkout could not be made from the available promisor mirror because required ancestor object `c6b523b5911c298a3e099c380a79446ad207b21e` is absent. Existing exact-source CMake build trees did generate the `.i`, and T6 already verifies the pinned whole-file CLI replay. |

The `.i` experiment is evidence that obtaining real macros, defines, includes, and line markers alone does not close the current scanner parser gap for the two libpng cases. For libtiff, the translation unit was preprocessed using the exact CMake-generated recipe but a source-bound CLI scan of that derived `.i` remains unverified because the disposable repository cannot be reconstructed from available Git objects. No zero-finding result is treated as a safety conclusion or fixed differential. All three rows stay **PARTIAL/BLOCK**.

## Reproduction and verification

```powershell
python research/evidence/cpp/verify_t9_source_context_audit_20261020.py
python research/evidence/cpp/verify_t61_libpng_acceptance_20261020.py
python research/evidence/cpp/verify_t6_remaining_matrix_replay_20261020.py --scanner-repo .
python research/evidence/cpp/verify_t23_supervisor_race_acceptance.py
```

T9 did not alter A0 data. The T23 verifier reports the existing 345 unique IDs/status invariant unchanged.
