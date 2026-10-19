# D51 — HUKS CR-0341 `extension_` shared_ptr assessment

Date: 2026-10-29 (Asia/Shanghai)  
Disposition: **PARTIAL/BLOCK; no detector change**. The exact A0 header parses completely under the current production `shared_ptr_race` 0.5.1 adapter and has zero findings. Source review found `extension_` initialized in the constructor and read through `const` shared_ptr operations; no post-construction write or reset was found in the pinned HUKS component. This does not establish product-level safety, Binder dispatch/destruction guarantees, JS runtime thread behavior, or security impact.

## A0 identity and status preservation

- Queue row: `CR-0341`, queue ID `T2-0341`; candidate `ohscanner.cpp.shared_ptr_race:63b7b6b9dff04365`; line 33, symbol `extension_`.
- Repository and source commit: `openharmony/security_huks` at `4ae4e0db461f137672719d43ffc6c5b1b6c05be8`.
- Git tree: `9c922a60d815a34eb96c060274ed863fd3a6fea8`.
- Header blob: `2c12eef68c03b83e27c805b651bf99c981efac45`; blob bytes SHA-256 `f189d4fbcb83e989ed3367fa8cb656e39a62f9aeddeb22b39c8d82352b435f45`, matching the frozen row.
- A0 scanner snapshot SHA-256: `9fc6f1440f14899a71e9d4b99bd343782ad97eae5d1fa66b44c7fe23f4d3992c`.
- Original status remains `not_testable`; original triage remains `queued_first_batch`. No A0 records were edited.

## Current production CLI replay

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\worktrees\source-d29-huks-20261020 --repository openharmony/security_huks --commit 4ae4e0db461f137672719d43ffc6c5b1b6c05be8 --include services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d51_huks_cr0341_cli_20261029.json --md-out research/evidence/cpp/d51_huks_cr0341_cli_20261029.md
```

Result: run `completed`; current detector `ohscanner.cpp.shared_ptr_race` 0.5.1; 1 selected file, 141 LOC, complete parse, 0 diagnostics, approximately 0.0054 seconds. The scanner itself records that modeled member accesses were constructor-initialization only and cautions that stable ownership is not a concurrency proof. This is a source-scope result, not a safety verdict.

## Access, lifetime and synchronization review

| Access | Source | Assessment |
|---|---|---|
| Initialization | `inc/hks_crypto_ext_stub_impl.h:32-33` | Constructor copies the `const std::shared_ptr<HksCryptoExtAbility>&` parameter into the member. |
| Null check | `src/hks_crypto_ext_stub_impl.cpp:43-50` | `extension_ == nullptr` is a read. Each exported stub method first calls this helper and returns on failure. |
| Dispatch reads | `src/hks_crypto_ext_stub_impl.cpp:72,86,102,118,133,147,162,177,191,207,223,239,253,269,284,298` | Methods invoke the extension through `extension_->...`; no assignment, reset, swap, or mutable reference to the member was found in the component. |
| Destruction | header `:35` | Destructor body is empty; ordinary member destruction follows object lifetime. |
| Stub creation / strong owner | `src/js_hks_crypto_ext_ability.cpp:672-685` | `OnConnect` constructs the stub from `static_pointer_cast(...shared_from_this())` and returns its remote object. This shows the visible creation path, not framework dispatch/destruction guarantees. |
| Build target | `ability_native/BUILD.gn:16-76` | `crypto_extension_ability_native` shared library is included under `os_level == "standard"`; it compiles the stub implementation. `module_loader/BUILD.gn:14-43` declares a dependent shared library. Product profile selection is not bound here. |

Concurrent invocation may produce concurrent read-only operations on the same `shared_ptr` object, but the reported candidate does not show a racing write to that object. The calls may enter extension/JS code; their serialization and any independent object-state races are outside this detector question and remain unverified. No object-level lock is present around those calls in this adapter, but that alone is not evidence of a shared_ptr race.

## Remaining evidence and disposition

- No concrete detector gap was reproduced: current analysis sees the constructor-only member initialization; source inspection found no missing post-construction write path for this member.
- The A0 row's concurrency ownership, guard dominance, attacker-controlled trigger, entry privilege, sensitive operation and CIA impact remain unproven.
- `os_level == "standard"` is a GN condition, not evidence that a particular product image includes the target. Exact product build/profile and runtime threading/JS dispatch semantics remain unknown.
- No target-derived concurrent harness was run. Generic TSan controls in A0 are method controls only.
- Keep **PARTIAL/BLOCK** and the A0 status `not_testable / queued_first_batch`; do not interpret zero findings as safe or fixed.
- No detector, API, diagnostic schema, Catalog or A0 queue changes were made.

## Reproduction and verification

Raw CLI output: [JSON](d51_huks_cr0341_cli_20261029.json), [Markdown](d51_huks_cr0341_cli_20261029.md). Run the source/A0/CLI identity verifier with:

```powershell
python research/evidence/cpp/verify_d51_huks_cr0341.py --source-repo D:\openHarmonyScanner\worktrees\source-d29-huks-20261020 --a0-queue research/deliveries/cpp/a0_triage_20261019/queue.json --cli-json research/evidence/cpp/d51_huks_cr0341_cli_20261029.json
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 92badc906009f40b99dd4d603552acc05467398a --lane cpp
```
