# OHScanner M1 Fixed-Commit Source Index

> Source/AST inventory, NOT a vulnerability report.

- Repository (user declared): `c11/perf-read-only`
- Commit: `ab30df6a01797af455d2abbbc9533ab15964ee68`
- Git tree: `b4dc74e0cdf75d923f4c6bfc44be6a453ca86915`
- Source manifest SHA-256: `dec4682e6b6e3901e06ddefe4c322c2cc5c1bd0da443140adb6f7c9b1c3efc7c`
- Profile: `light-ast`
- Python: `3.12.14`
- Git: `git version 2.55.0.windows.5`
- Scanned source files: **16**
- Tracked Git entries: 1384
- Out of scope: 1280
- Unsupported/non-source entries: 88
- Git symlinks ignored: 0
- Submodules ignored: 0
- Oversize/non-UTF8 skipped: 0/0
- Languages: `{"cpp": 16}`
- Parse statuses: `{"complete": 15, "partial": 1}`

## Unsupported and unknown coverage

- C/C++ and JS/TS syntax are bounded; unsupported ArkTS remains partial/unknown, without type/manifest semantics.
- Source repository name is user-declared; local Git object identity is checked, not official remote ownership.
- Headers default to C++ grammar; no GN/product compile flags, macro instantiation or full device coverage.
- No vulnerability detector executed. candidate_count=0 is not a security finding.
- Non-UTF8 and oversized sources are skipped and counted; report scope reflects actual selected files.
- Tracked tar.gz/tgz archives are read-only and bounded; archive member paths are virtual and bind to archive Git blob plus archive/member SHA-256.

## Per-file index

| Path | Language | Parse | Functions | Calls |
|---|---|---|---:|---:|
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/harness.cpp` | cpp | complete | 2 | 19 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/observations.h` | cpp | complete | 1 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/poc_compat.h` | cpp | complete | 0 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/hilog/log.h` | cpp | complete | 5 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/ipc_object_stub.h` | cpp | complete | 3 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/ipc_types.h` | cpp | complete | 0 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/iremote_broker.h` | cpp | complete | 2 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/iremote_stub.h` | cpp | complete | 3 | 1 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/message_option.h` | cpp | complete | 6 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/message_parcel.h` | cpp | complete | 5 | 2 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/peer_holder.h` | cpp | complete | 0 | 0 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stub/securec.h` | cpp | partial | 2 | 3 |
| `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/stubs.cpp` | cpp | complete | 9 | 6 |
| `src/ohscanner/poc/harnesses/cpp_lifetime_unique_ptr_alias/harness.cpp` | cpp | complete | 3 | 13 |
| `src/ohscanner/poc/harnesses/cpp_shared_ptr_delayed_singleton/harness.cpp` | cpp | complete | 5 | 28 |
| `src/ohscanner/poc/harnesses/cpp_shared_ptr_delayed_singleton/nocopyable.h` | cpp | complete | 4 | 0 |
