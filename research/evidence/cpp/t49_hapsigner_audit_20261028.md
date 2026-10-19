# T49 — hapsigner shared_ptr_race CR-0300 independent audit

## Result

**PARTIAL/BLOCK.** CR-0300 is a `developtools_hapsigner` A0 row, not part of the camera family. Its exact source is `openharmony/developtools_hapsigner` commit `2697b2298b111e90c0999e79595645a68437f3d7`, tree `dbee4af9158f1d0663a0a776d2e7db5aa1f9201c`, file `binary_sign_tool/hap/sign/include/elf_sign_context.h:46`, blob `44e062bc5572c3a658cc9eaceb149f70e320f963`, SHA-256 `cde0bb719af2db91517921d44f31d439126658f36125bd9d703c249fd0869808`.

The exact-file replay with current `ohscanner.cpp.shared_ptr_race` 0.5.1 completed with full parsing and **0 diagnostics**. The historical A0 candidate therefore does not reproduce on the current detector. This is not proof of safety or proof of a detector defect: the A0 record has no separately recorded rule lineage, while the current rule is explicitly syntax-candidate-only.

## Source and build context

At the candidate line, `GetConvertor()` returns a const reference to the `std::shared_ptr<ELFIO::endianess_convertor>` member. In the exact source call chain, `SignElf::Sign` creates `ElfSignContext ctx` on the stack, calls `ctx.Load(...)`, and passes that same object by reference to section construction and writer routines synchronously. `Load` assigns `convertor` from that call's `ELFIO::elfio` reader. No cross-invocation shared `ElfSignContext` or same-instance concurrent access was found in the inspected call chain.

The exact GN declaration for `binary-sign-tool` adds `signature_tools_hap_src`; `hap/signature_tools_hap.gni` includes `sign_elf.cpp`, `elf_sign_context.cpp`, and `elf_sign_writer.cpp`. This establishes a declared executable target relationship only. It does not lock the shipped product profile or prove external consumers, concurrent runtime schedules, or impact. No trusted fixed source or target-derived concurrent harness was available.

No detector change was justified. Preserve CR-0300 as `not_testable / paused_pending_evidence`; maintain PARTIAL/BLOCK. Full bindings and verifiable assertions are in [the machine-readable audit](t49_hapsigner_audit_20261028.json), [raw CLI result](t49_hapsigner_cli_20261028.json), and [verifier](verify_t49_hapsigner_audit_20261028.py).

## Replay command

```powershell
python -m src.cli ohscan-run --repo-dir <exact-hapsigner-checkout> --repository openharmony/developtools_hapsigner --commit 2697b2298b111e90c0999e79595645a68437f3d7 --include binary_sign_tool/hap/sign/include/elf_sign_context.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/t49_hapsigner_cli_20261028.json --md-out research/evidence/cpp/t49_hapsigner_cli_20261028.md
```

