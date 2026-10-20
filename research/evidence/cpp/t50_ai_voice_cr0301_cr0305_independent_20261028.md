# T50 — ai_intelligent_voice_framework CR-0301–CR-0305 independent acceptance

This is a source-bound test-line replay against the exact component commit in A0. It does not change detector code, tests, fixtures, or queue state. It is not a proof of a race, authorization flaw, safe behavior, or product impact.

## Result

All five rows keep their original `not_testable / paused_pending_evidence` status and remain **PARTIAL/BLOCK**. The source tree is commit `19188608475123695def986a399641bfa64a49f7`, tree `0ec80bfd6532b91f450d2f84517c461a4f7a18ae`. Current production detector versions are `shared_ptr_race 0.5.1` and IPC `0.12.12 / oh-ipc-2026.10-v32`. All selected target translation units parsed completely.

| A0 row | Target and A0 line | Current replay | Independent source review |
|---|---|---|---|
| CR-0301 | `adapter_callback_service.h:28` | No finding at the A0 position | The candidate line initializes `listener_` in the constructor. The callback implementation reads it; constructors are used by enroll and wakeup engines. This single header run has no read/write pair. Callback overlap, object lifetime, product thread model and impact remain unknown. |
| CR-0302 | `engine_util.h:77` | `ohcpp-shared-ptr-race-candidate-001` reproduced | Assignment to `EngineUtil::adapter_` in `CreateAdapterInner`. |
| CR-0303 | `engine_util.h:78` | Same rule reproduced | Null check/read of `adapter_` immediately after the assignment. |
| CR-0304 | `engine_util.h:86` | Same rule reproduced | Reset of `adapter_` in `ReleaseAdapterInner`. |
| CR-0305 | `intell_voice_service_stub.cpp:70` | `ipc.capability.export` reproduced | The concrete pinned virtual factory checks `MANAGE_INTELLIGENT_VOICE`, and the Stub returns on a nonzero factory result before export. Caller grants/reachability and product policy remain unverified. |

CR-0302–0304 share one source blob and represent three operations on the same `adapter_` member, not three independent bugs. `EngineUtil` itself has no mutex protecting that member; derived callers vary. The component contains wrapper and listener locks and serialized/state-machine callers, but the exact lock dominance across every same-instance adapter read/write and callback schedule is not established. The GN target includes engine sources under `intelligent_voice_framework_engine_enable`; the GNI default enables it. This does not identify a resolved product profile or prove runtime concurrency.

For CR-0305, the D48 source-bound flow establishes the local interprocedural guard: `CreateIntellVoiceService` checks the IPC caller token through `VerifySystemPermission` before engine creation, and denial returns nonzero, preventing the remote object write. The product image, caller permissions, external reachability, exported engine operations/impact, and trusted fixed-source comparison are still missing. The candidate should not be suppressed based on this incomplete product evidence.

## Source identities

The five target blobs and SHA-256 values are bound to the original queue rows, and the verifier rechecks them directly from the component Git object database. The report’s machine-readable evidence also records exact blob/SHA identities for callback implementation and construction sites, `EngineUtil` implementation, component GN/GNI, and IPC service/proxy sources. Original A0 snapshot identity: `a2499e0c8f9ba4ec53e169f6c88d46cc10004f69d6b1b7339f80cf9b5891a4d5`.

## Verification

Run from the repository root with the component’s bare Git object directory:

```powershell
python research/evidence/cpp/t50_ai_voice_cr0301_cr0305_independent_20261028.py `
  --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\ai_intelligent_voice_framework.git `
  --output research/evidence/cpp/t50_ai_voice_cr0301_cr0305_independent_20261028.json
```

The replay re-parses each exact source, calls the current first-party detector, asserts the expected line-level finding behavior, verifies all five queue identities and unchanged statuses, and source-binds the callback/adapter use and build context. It confirms the A0 queue still contains 345 unique rows; the full A0 package reconciliation and change-scope checks are recorded with this delivery. See [machine-readable results](t50_ai_voice_cr0301_cr0305_independent_20261028.json) and [verifier](t50_ai_voice_cr0301_cr0305_independent_20261028.py).
