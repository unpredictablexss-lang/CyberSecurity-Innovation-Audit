# T34: libpng CVE-2026-46675 independent audit

Date: 2026-10-23  
Baseline: `1cb2178c88715b6c8f908ac7826cb684a35730f7`  
Disposition: **PARTIAL/BLOCK**

## Scope and source identity

T34 independently bound the exact upstream vulnerable and fixed `pngrutil.c` sources. It cloned the local pinned-source mirror into a task-local bare Git repository and fetched the exact fixed commit from the official `pnggroup/libpng` Git remote. Commit, tree, file blob, SHA-256, and byte count all agree with the D14/T11 evidence.

The task-local source object database is `D:/openHarmonyScanner/tmp/t34-libpng46675-source-20261023.git`; it is kept outside the Git worktree so the change-scope gate only sees the committed evidence files.

| Variant | Commit | Tree | `pngrutil.c` blob | SHA-256 | Bytes |
|---|---|---|---|---|---:|
| Vulnerable | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` | `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | `a4eda54c8cb3d36cf1651dba159067b65030e3aa` | `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e` | 153112 |
| Fixed | `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` | `4c64b5f18cef7d129adee3b403fc4be93f82e30d` | `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a` | `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e` | 152477 |

The fixed commit parent is `4eeb825ab26605ed34cd74495d4cce920939fe9f`. T34 resolved the earlier missing fixed-tree link; tree identity is now verified from the fetched commit object and `pngrutil.c` tree entry.

## Current production CLI replay

The current CLI ran `ohscanner.cpp.resource_lifetime` **0.4.2** with `light-ast` profile and exactly one tracked source file in scope on each pinned commit.

| Variant | Parse | Parse issues | Detector run | Findings |
|---|---|---:|---|---:|
| Vulnerable | partial | 72 | blocked | 0 |
| Fixed | partial | 72 | blocked | 0 |

The CLI emitted no candidate positions on either side. Since both translation units are partial and both detector runs are blocked, the zero results do not prove a fixed differential or safe code. The raw CLI JSON/Markdown outputs are [vulnerable JSON](t34_libpng46675_vulnerable_cli_20261023.json), [vulnerable Markdown](t34_libpng46675_vulnerable_cli_20261023.md), [fixed JSON](t34_libpng46675_fixed_cli_20261023.json), and [fixed Markdown](t34_libpng46675_fixed_cli_20261023.md).

## Independent function-fragment replay

T34 reran the D12 seven-function fragment experiment over the pinned source bytes. Each variant had six complete isolated fragments and one partial `png_handle_iCCP` fragment. The parent translation unit remained partial for all functions. The resource-lifetime detector emitted zero findings on every fragment.

Complete fragment syntax is direct mechanism/control evidence only at the isolated syntax level. It does not establish cross-function ownership or stale `zstream` field transitions, caller order, trigger feasibility, product reachability, or impact. The partial iCCP fragment further prevents an end-to-end lifecycle conclusion.

## Result and unresolved work

The upstream advisory/fix and source diff identify a stale zstream ownership/lifecycle transition spanning inflate/decompression/read operations. Current CLI and fragment replays did not produce a root-cause candidate. No narrow, independently supported detector change is accepted by this audit. The case remains **PARTIAL/BLOCK**; the fixed comparison is also blocked as a safety conclusion because parser coverage is partial.

No product build, call-path, runtime trigger, or impact evidence was established. No A0 queue IDs or statuses were changed; the A0 verifier confirms 345 IDs and the original status counts are preserved.

Commands and machine-verifiable assertions are recorded in [JSON audit](t34_libpng46675_independent_audit_20261023.json) and [verifier](verify_t34_libpng46675_audit.py). The verifier checks both exact Git identities, source SHA/size, CLI binding and outcomes, fragment identities/coverage, and the PARTIAL/BLOCK disposition.
