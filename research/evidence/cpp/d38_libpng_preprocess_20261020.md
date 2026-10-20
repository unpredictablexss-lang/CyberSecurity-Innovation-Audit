# D38 libpng build-context preprocessing probe

Date: 2026-10-20  
Scanner baseline: `efa09aaaac01f81084034ea0994c310007ba1dbf`  
Cases: CVE-2026-33416 and CVE-2026-46675  
Disposition: **No scanner change; preprocessing did not establish root-cause candidates or complete parsing.**

## Result

The exact vulnerable and fixed commits were available in the existing local bare source mirrors. I created fresh snapshots under `D:\openHarmonyScanner\tmp\d38-libpng-preprocess-20261020`, ran Autotools `configure` on each snapshot with the recorded build flags, generated `pnglibconf.h`/`pngprefix.h`, and preprocessed the relevant translation units with WSL Ubuntu GCC 13.3.

The probe produced 10 `.i` files: four target translation units on each side of 33416, plus `pngrutil.c` on each side of 46675. Every preprocessed input remained `partial`; parse issues ranged from 174 to 401. `resource_lifetime@0.4.2` returned `blocked` and zero findings on all 10 inputs. Preprocessing therefore does not close either case and supplies no basis for a detector change.

I also ran each preprocessed variant through the production `ohscan-run` CLI in a separate temporary Git repository, with generated files renamed to `.c` so the normal source frontend selected them. The scanner bound each synthetic commit/tree, scanned the expected file count (4/4 for 33416, 1/1 for 46675), reported all selected files partial, and returned `resource_lifetime=blocked` with zero diagnostics. These synthetic commits are only scanner-input containers; the generator binds each `.i` back to its upstream source via the upstream blob/hash and the preprocessed-output hash. Per-run synthetic tree/commit and CLI artifact hashes are recorded in the machine evidence.

GCC line markers preserve enough information for this external probe to map selected function starts back to the exact original files and lines. Examples include vulnerable 33416 `png_set_PLTE` → `pngset.c:740`, fixed `png_set_PLTE` → `pngset.c:741`, vulnerable 46675 `png_decompress_chunk` → `pngrutil.c:680`, and fixed `png_decompress_chunk` → `pngrutil.c:686`. The AST itself reports generated `.i` line numbers, not these mapped original lines. The current scanner does not consume the marker map, so scanning `.i` as if it were original source would misstate finding locations and cannot be used to downgrade `partial` to `complete`.

This is a concrete negative feasibility result for the proposed shortcut, not evidence that no future generic preprocessor integration can work. A valid integration would have to bind the compiler configuration to the pinned tree, retain and apply line-marker maps, account for generated headers and include files, and keep parser incompleteness fail-closed. The present probe provides no root-cause candidate on either side.

## Pinned inputs and commands

Source commits, trees, blobs, and source SHA-256 values were checked against the independent T61 source manifest; the generator recomputes both Git blob IDs and SHA-256 before analyzing each preprocessed file. Machine details and per-file outcomes are in [the JSON evidence](d38_libpng_preprocess_20261020.json).

The generated Makefiles recorded `CC=gcc`, `CPP=gcc -E`, `DEFS=-DHAVE_CONFIG_H`, `DEFAULT_INCLUDES=-I.`, and `CFLAGS=-g -O1 -fsanitize=address -fno-omit-frame-pointer`. The effective preprocessing invocation was:

```sh
gcc -DHAVE_CONFIG_H -I<snapshot-root> -g -O1 -fsanitize=address \
  -fno-omit-frame-pointer -E <snapshot-root>/<file>.c -o <probe-root>/preprocessed/<variant>-<file>.i
```

The exact source archive bindings were:

```text
33416 vulnerable: libpng-gitlab-mirror-pins-20261019.git @ c3e304954a9cfd154bc0dfbfea2b01cd61d6546d
33416 fixed:      libpng-gitlab-mirror-pins-20261019.git @ d5515b5b8be3901aac04e5bd8bd5c89f287bcd33
46675 vulnerable: t34-libpng46675-source-20261023.git @ c3e304954a9cfd154bc0dfbfea2b01cd61d6546d
46675 fixed:      t34-libpng46675-source-20261023.git @ aa77ef38c17ab2fc1b41bec09fb973c6a386641d
```

To reproduce in this Windows workspace, extract each listed commit with `git --git-dir=<mirror> archive <commit>`, run `CC=gcc CFLAGS='-g -O1 -fsanitize=address -fno-omit-frame-pointer' ./configure`, then `make pnglibconf.h pngprefix.h`. Run the command above for `pngset.c`, `png.c`, `pngread.c`, and `pngrtran.c` on both 33416 snapshots, and for `pngrutil.c` on both 46675 snapshots. WSL Ubuntu must provide GCC 13.3. Finally run:

```powershell
$env:PYTHONPATH = '<this scanner worktree>'
python research/evidence/cpp/d38_libpng_preprocess_probe_20261020.py `
  --probe-root D:/openHarmonyScanner/tmp/d38-libpng-preprocess-20261020 `
  --output research/evidence/cpp/d38_libpng_preprocess_20261020.json
```

Before regenerating the evidence JSON, run production CLI on the preprocessed inputs in four isolated temporary Git repositories. For each variant, copy its `.i` files from `preprocessed/` into a new repository as the original `.c` basenames, `git init`, commit those files, and run:

```powershell
python -m src.cli ohscan-run --repo-dir <synthetic-repo> `
  --repository d38/<variant> --commit <synthetic-commit> `
  --detector ohscanner.cpp.resource_lifetime `
  --include <each-generated-c-basename> `
  --json-out <probe-root>/cli-output/<variant>.json `
  --md-out <probe-root>/cli-output/<variant>.md
```

The generator fails on any source blob/hash mismatch, missing one of the expected 10 source/preprocessor pairs, missing CLI artifact, or unexpected CLI result. It records target-function source-line mappings, parser status, detector status, finding count, preprocessed and CLI artifact hashes, and marker count.

## Scope and next action

No detector, parser, Catalog, API, or fixture was changed. The existing case dispositions remain **PARTIAL/BLOCK**. Further work should be a separate generic parser/preprocessor capability slice with explicit provenance and mapped source positions; this probe does not justify scanner-side use of untracked build outputs or weakening parse-status gates.
