# D29 — HUKS CR-0342 shared_ptr replay

Date: 2026-10-20 (Asia/Shanghai)  
Disposition: **PARTIAL / no detector change**. The current production M2 CLI parses the reported header completely and emits zero findings. Source review explains why the reported `cancelled_` access is not a same-`shared_ptr` concurrent access: the death-recipient and task own distinct `shared_ptr` instances to one `std::atomic<bool>`. The flag's cross-thread operations are atomic. This is not a claim that the product build or all callback teardown semantics have been validated.

## Pinned source and A0 provenance

The A0 JSON and CSV row is CR-0342, candidate `ohscanner.cpp.shared_ptr_race:234a77018701bb81`, symbol `cancelled_`, line 48, profile `light-ast`, status `not_testable`, queue status `queued_first_batch`. Both frozen status fields remain unchanged.

The recorded full commit is `4ae4e0db461f137672719d43ffc6c5b1b6c05be8`; its tree is `9c922a60d815a34eb96c060274ed863fd3a6fea8`. The referenced header blob is `3719b03ef01f215b3188a236503ff973a1cb6e5d`, and its SHA-256 is `6a656b45b3809a77b4fe124cff3c1b0b668ef754640667fcddedf576117a2974`. Commit/tree/blob/hash all match the A0 row. The frozen row is not rewritten.

Repository object source: `openharmony/security_huks`; local Git object store `D:\openHarmonyScanner\openharmony\.repo\project-objects\security_huks.git`. The scanner used a detached checkout at the resolved full commit.

## Production CLI replay

Command (from the scanner worktree):

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\worktrees\source-d29-huks-20261020 --repository openharmony/security_huks --commit 4ae4e0db461f137672719d43ffc6c5b1b6c05be8 --include services/huks_standard/huks_service/extension/ukey_client_service/inc/hks_ukey_async_task.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d29_huks_cr0342_cli_20261020.json --md-out research/evidence/cpp/d29_huks_cr0342_cli_20261020.md
```

Result: CLI execution completed; detector `ohscanner.cpp.shared_ptr_race` version `0.5.1`; one selected C++ file, 7,931 bytes / 174 LOC; parse `complete` with no issues; zero diagnostics. The scanner explicitly records that `HksUkeyDeathRecipient::cancelled_` was only observed during constructor initialization and that stable-owner shape is not a concurrency proof. This contradicts the original 0.2.0-proposed syntax candidate as an actionable unsynchronized `shared_ptr` race, but does not prove global safety.

## Cross-reference and synchronization review

| Object/access | Source location | Finding |
|---|---|---|
| `HksUkeyDeathRecipient::cancelled_` | `hks_ukey_async_task.h:47-58` | Constructor receives a `shared_ptr` by value and moves it into a recipient-owned member. `OnRemoteDied` performs atomic `store(true, relaxed)`; no write to this `shared_ptr` member. |
| `HksUkeyAsyncTask::cancelled_` | `hks_ukey_async_task.cpp:74-77`; header `:148-149` | Task constructs a `shared_ptr<atomic<bool>>`, then copies it into the death recipient. This initializes the task member before task submission. No later reassignment found. |
| Worker read | `hks_ukey_async_task.cpp:117-138` | `Run()` reads the pointee using `atomic<bool>::load(relaxed)`. |
| Reply read | `hks_ukey_async_task.cpp:200-205` | `OnDone()` reads the same atomic pointee using `load(relaxed)`. |
| Recipient callback | `hks_ukey_async_task.h:50-54` | Binder death notification writes the pointee with `atomic<bool>::store(relaxed)`. |
| Recipient registration/teardown | `hks_ukey_async_task.cpp:75-87` | Constructor registers; destructor removes recipient before member destruction. Framework guarantee for already in-flight callback draining is not independently proven here. |
| Task worker lifetime | `hks_task_executor.cpp:112-137,140-175`; `hks_task_executor.h:76` | Executor queues unique-owned tasks under a mutex and uses one worker. Worker calls `Run()` then `OnDone()` before task destruction. `Stop()` drains queued tasks and joins workers. Product runtime configuration/build is not bound by this replay. |

The relevant race hypothesis conflates (a) concurrent manipulation of one `shared_ptr` object and (b) accesses through distinct `shared_ptr` copies to a shared pointee. The source shows the latter; the pointee is atomic. `shared_ptr` control-block operations on separate instances are intended to be thread-safe. This evidence therefore does not establish a detector miss. The remaining uncertainty is callback teardown semantics and actual product compilation/runtime configuration, not a demonstrated non-atomic `shared_ptr` access gap.

## Status and next evidence

- Detector change: none. No positive/safe/unrelated fixture was added because no rule change was supported.
- A0 original state preserved: `not_testable / queued_first_batch`.
- Case disposition: **PARTIAL/BLOCK** for vulnerability confirmation; source-level mechanism review is complete, but the product build profile, full service reachability/privilege context, actual binder callback teardown contract, and target-derived runtime evidence remain unverified.
- Minimum next evidence: bind the product build/configuration and confirm its exact task-executor worker count; cite the platform `RemoveDeathRecipient` in-flight callback contract or exercise a target-derived teardown harness; then establish the caller entry and impact before deciding whether any race exists.
- Independent reproduction: run `python research/evidence/cpp/verify_d29_huks_cr0342.py --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\security_huks.git --queue-json research/deliveries/cpp/a0_triage_20261019/queue.json --queue-csv research/deliveries/cpp/a0_triage_20261019/queue.csv --cli-json research/evidence/cpp/d29_huks_cr0342_cli_20261020.json`.
