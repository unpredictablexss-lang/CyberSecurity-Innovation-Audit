# C8 parser integration request: Ark Runtime TypedArray Map

Status: pending shared parser/runner integration; no shared code changed by C8.

## Observed production CLI boundary

The v0.8.9 `ohscan-run` command scanned the exact pinned `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` source from four commits using `light-ast`, one file per run. The detector found the Map type-origin candidate only on the vulnerable parent (line 2665) and not on the fixed merge. All four first-party runs report detector status `blocked` and translation-unit status `partial`; the relevant Map function region produced AST/model observations, but file completeness is not established.

Parser reports identify missing nodes at lines 3391 and 3703 (line offsets vary by revision). Source inspection associates these regions with macro DSL constructs (`BRANCH(...)` without an ordinary statement terminator in source form and token-pasting macro continuations such as `TYPE##_ARRAY_ROOT_HCLASS_ON_HEAP_INDEX`). `light-ast` does not report preprocessor-expanded syntax. These are evidence-based suspected causes, not a parser bug diagnosis.

## Requested integration

Please expose one supported production parsing mode that either:

1. uses the exact compile profile and preprocessor definitions for the pinned source, or
2. reports a sound bounded-function completeness result for the selected Map body, with dependency/macro uncertainty surfaced and no claim of whole-TU completeness.

The contract must preserve source-location mapping and must not silently turn unsupported macro regions into complete coverage. C-line can replay the four pinned cases after integration and compare detector output and status. Ownership for the shared parser/runner/API change must be assigned through the repository integration workflow; this file is the request, not authorization to edit shared code.

## Replay scope

Local source DB: `D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git` for CVE pair and `D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git` for !11684. Scans must use pinned local objects and must not fetch.

See `reports/v089-cve-map-parent.json`, `reports/v089-cve-map-fixed.json`, `reports/v089-holdout-safe-parent.json`, and `reports/v089-holdout-safe-fixed.json` for production CLI records.
