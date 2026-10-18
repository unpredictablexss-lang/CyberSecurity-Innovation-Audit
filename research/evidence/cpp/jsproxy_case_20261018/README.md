# A-JSPROXY-01 component case

This case binds the `JSProxy::instance_` candidate to a pinned
`openharmony/distributeddatamgr_kv_store` source and a TSan harness. It is
component-level evidence only: `candidate/unassessed`, `validated_vulnerability=0`,
and `product_gate=not_met`.

## Source binding

- Repository: `openharmony/distributeddatamgr_kv_store`
- Commit: `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- `frameworks/common/js_proxy.h`: blob `19b5dcc...`, source SHA-256
  `38d4f173...`
- `JsKVStoreResultSet` and `NapiQueue` files are bound in `case_manifest.json`.

The current detector (`ohscanner.cpp.shared_ptr_race` 0.5.1) reports two
`instance_` candidates in the pinned header: the `SetInstance` write at line 37
and the `GetInstance` read at line 42.

The same detector reports zero findings on the mutex-protected fixed header
(`harness/fixed/js_proxy.h`), so the fix control is quiet at the detector layer
as well as under TSan.

## Harness and result

- Vulnerable header: exact pinned header bytes; `results.json` records its SHA.
- Fixed header: same source with a `std::mutex` around `SetInstance`/`GetInstance`.
- Compiler: Ubuntu clang 14.0.0, `-fsanitize=thread`, `setarch x86_64 -R`.
- Repeat count: 3 per variant.
- Vulnerable: exit `66/66/66`, TSan data race reported in all three runs.
- Fixed: exit `0/0/0`, no TSan race in all three runs.

The vulnerable logs identify the conflicting accesses at `js_proxy.h:37`
(`SetInstance`) and `js_proxy.h:42` (`GetInstance`). See `results.json` and
`logs/vulnerable/`.

Run `python3 verify_case.py` to re-check source blob/source hashes, the three
vulnerable/fixed runs, the patch hash, and the patch's applicability to the
pinned Git index. It prints `case_ok` on success.

## Patch

`patch/js_proxy_mutex.patch` adds a `std::mutex` to the template and locks both
accessors. It is checked against the pinned Git index with
`git apply --cached --check`; the working-tree copy is CRLF while the Git blob
is LF.

## Limitations

The case does not prove a real product entry, permission boundary, attacker
control, CIA impact, or product build. It does not upgrade the candidate to
confirmed/reportable. A full product build and runtime trace remain required.
