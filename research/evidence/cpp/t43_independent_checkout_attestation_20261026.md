# T43 independent-checkout attestation

- Verification checkout: `D:\openHarmonyScanner\worktrees\t43_taihe_ffi_independent_verify_20261026`, branch `codex/t43-taihe-independent-verify-20261026`, based directly on parent `aacc11729e95d19171fdbf70c30859ce2a05e246`.
- Independently reran the exact two-file `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI scope against Taihe FFI commit `d91f43e80d892bca694c6b0fce8ea27cd644919f` / tree `8c5eecdad09e2fe960ce5f3728959a4726f0a91d`.
- Both files parsed completely. The run emitted 16 diagnostics, matching 16 of the 17 requested A0 positions. CR-0213 (`image_source_taihe.h:57`) remains unmapped; this is not a safe result.
- Independently recomputed each source blob and SHA-256 against the frozen A0 rows. Reviewed pinned root `BUILD.gn`: it does not reference the two audited files; the only nested test BUILD files are the unrelated integer test targets. The `ra_napi_image` header labels itself a test file. No product target is bound, so build inclusion remains BLOCK/unknown.
- Preserved all 17 A0 statuses (`not_testable / paused_pending_evidence`); no detector, tests, fixtures, or A0 content changed. Overall remains `PARTIAL/BLOCK` because same-object unsynchronized concurrent accesses, product reachability, impact, and trusted fixed/safe ground truth are not established.

Artifacts: [independent CLI JSON](t43_independent_cli_20261026.json), [independent CLI Markdown](t43_independent_cli_20261026.md), [machine attestation](t43_independent_checkout_attestation_20261026.json), and [attestation generator/verifier](t43_independent_checkout_attestation_20261026.py).
