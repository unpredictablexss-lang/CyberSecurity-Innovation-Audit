# D48 — ai_intelligent_voice_framework IPC CR-0305 no-change assessment

> Current scanner candidate replay and source review only. This is not a product vulnerability confirmation or a safety verdict.

## Result

CR-0305 remains `not_testable / paused_pending_evidence` and **PARTIAL/BLOCK**. The current production IPC detector reproduces the `ipc.capability.export` candidate at the A0 sink (line 70) on the exact queue-bound source. No finding gap was reproduced, so no detector change is justified.

The one-file bounded model does not bind the virtual factory call to the service implementation. The exact pinned service implementation checks `MANAGE_INTELLIGENT_VOICE` against the IPC caller token before creating an engine, and the Stub returns on every nonzero result before it writes the engine remote object. Thus the observed source weakens the candidate's “unrecognized caller authorization” concern for this concrete implementation. It does not resolve product caller grants, actual product build/profile, external call reachability, capability use or impact. The candidate remains an unverified review lead; neither a vulnerability nor safety is established.

## Source binding

| Item | Pinned identity |
|---|---|
| A0 review | `CR-0305`, queue `T2-0305`, candidate `ohscanner.interface.ipc:e777b1353fbbe284`, original status `not_testable` |
| Repository and commit | `openharmony/ai_intelligent_voice_framework` @ `19188608475123695def986a399641bfa64a49f7` |
| Tree | `0ec80bfd6532b91f450d2f84517c461a4f7a18ae` |
| Original A0 snapshot SHA-256 | `a2499e0c8f9ba4ec53e169f6c88d46cc10004f69d6b1b7339f80cf9b5891a4d5` |
| Target file blob / SHA-256 | `79a9acae7a4bb5a6dab18b40159f2aab52fcb544` / `55dc2d68954cf94eb41014010fc6696236d9839fa8246aebd2faa8d033d30fc6` |

The target replay supplied only `services/intell_voice_service/server/sa/intell_voice_service_stub.cpp`; its detector-run snapshot is `59299dfe24510ec24a794a4db4a25c2b53b7f0e0f7dea307e23171acd4ef06aa`. This one-file replay snapshot is distinct from the full A0 snapshot above. The verifier also binds the Stub header, service implementation/header, permission helper, proxy, SA configuration, GN target and feature defaults by Git blob and SHA-256.

## Current production detector replay

| Detector | Version / model | Target parse | Run | Result |
|---|---|---|---|---|
| `ohscanner.interface.ipc` | `0.12.12` / `oh-ipc-2026.10-v32` | complete | completed, one target file | `ipc.capability.export` at `intell_voice_service_stub.cpp:70` |

The finding describes `WriteRemoteObject(engine->AsObject())`, with the branch trace `type == INTELL_VOICE_HEADSET_WAKEUP`, `ret != 0` false, and `engine != nullptr` true. It remains a static syntax candidate. Complete parsing of this translation unit does not mean the detector analyzed the cross-file virtual callee or established product-level caller policy.

## Source review

1. `IntellVoiceServiceStub` derives from `IRemoteStub<IIntellVoiceService>`. `OnRemoteRequest` checks the interface token and dispatches the registered transaction. Descriptor equality is not treated as caller authorization.
2. `CreateEngineInner` reads a callback remote object and calls `RegisterDeathRecipient`, maps the headset wakeup type, and invokes `CreateIntellVoiceEngine`. It writes the returned engine object only when `ret == 0` and `engine != nullptr`; `ret != 0` returns before the export sink.
3. The exact `IntellVoiceService` implements `IntellVoiceServiceStub`. Its `CreateIntellVoiceEngine` calls `VerifySystemPermission("ohos.permission.MANAGE_INTELLIGENT_VOICE")` before `HandleCreateEngine`; denial returns nonzero. The permission helper checks whether the caller is a system/native app and then calls `AccessTokenKit::VerifyAccessToken` using `IPCSkeleton::GetCallingTokenID()`.
4. `RegisterDeathRecipient`, which the Stub invokes before creation, performs the same permission check before registering the callback object. Its failure return is ignored by the Stub, but a later failed factory result still prevents the engine object export.
5. The pinned client proxy writes the service interface token, sends `HDI_INTELL_VOICE_SERVICE_CREATE_ENGINE`, and reads the returned remote object. This documents intended client flow, not reachability by an unauthorized principal.
6. The pinned GN server source set includes `intell_voice_service_stub.cpp`; the component GNI defaults engine support on. The service cfg lists the `intell_voice` process UID and its process permissions, while the SA profile names ability 312. These are component build/config facts, not proof of the reviewed product image or caller permission grants.

The reported object handoff is therefore guarded by a source-visible cross-file permission check in the pinned concrete Service implementation. The static detector still emits a candidate because its bounded target-only model does not resolve this virtual callee and its authorization summary. Silencing the candidate would require a trustworthy cross-file call/override/return-value model and evidence that the policy is effective in the intended product; neither is established in this task. No rule change, shared API/schema/catalog change, or A0 queue-state mutation was made.

## Remaining proof obligations

- Bind the exact product GN profile/variant and built image. The cfg's `permission` array applies to the service process and does not identify all callers granted `MANAGE_INTELLIGENT_VOICE`.
- Establish whether a non-system or otherwise unauthorized principal can obtain and call this SA in the affected product configuration.
- Determine the returned engine capability's sensitive operations and whether the permitted recipient boundary creates confidentiality, integrity or availability impact.
- Bind a trusted fixed-source/product regression comparison; none was supplied by this replay.

Do not mark the candidate fixed, not reproduced, false positive, exploitable or safe based on this source review. Keep the original A0 status and obligations unchanged.

## Reproduction and checks

From the repository root, with the exact local bare source object directory available:

```powershell
python research/evidence/cpp/d48_ai_voice_cr0305_no_change_20261028.py `
  --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\ai_intelligent_voice_framework.git `
  --output research/evidence/cpp/d48_ai_voice_cr0305_no_change_20261028.json
```

The verifier checks the pinned commit/tree/blob/source hashes, re-parses the exact file, invokes the current first-party IPC detector, and asserts the root candidate is present at line 70. It also checks the source snippets that support the bounded authorization-flow assessment. See the machine-readable result at [D48 JSON](d48_ai_voice_cr0305_no_change_20261028.json) and the replay verifier at [D48 verifier](d48_ai_voice_cr0305_no_change_20261028.py).
