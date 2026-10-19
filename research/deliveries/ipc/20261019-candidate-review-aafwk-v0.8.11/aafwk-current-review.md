# Component audit: openharmony/aafwk_standard

> Candidate evidence and coverage. Not a validated vulnerability list, and a
> zero-candidate audit is not a clean component.

- Pinned commit: `834a566b1372268c7bbb0c40362322f812ca6efc`
- Git tree: `c3744c8c230573a4bcdb76bf49493a1ea61c72d1`
- Source snapshot SHA-256: `69370701eb08d6c24a9b4176d4e8d9e0b692a5de6d6886fdd4c8da3b351d315e`
- Scope plan SHA-256: `408a909b236ed1d0316535576dd95c101e4d026b1c45d04294173ae9c45a3162`
- Passes: `complete-ast`, `all-files`
- Wall clock: 0.844s
- Peak RSS: 41.3 MB (process high-water mark; see limitations)
- Validated vulnerabilities: **0** (static candidates only)

## 1. Run state

| Shard | Pass | Detector status | Planned | Loaded | Applicable | Analyzed | Diagnostics | Scope files | Seconds |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | `complete-ast` | blocked | 5 | 5 | 5 | 0 | 0 | 0 | 0.255 |
| 0 | `all-files` | blocked | 5 | 5 | 5 | 0 | 16 | 0 | 0.465 |

## 2. Analysis coverage

### Scope actually derived from the pinned tree

| Measure | Count |
|---|---:|
| Tracked entries | 2330 |
| Out of the requested include prefixes | 2325 |
| Excluded as test/mock/sample/vendored | 0 |
| Non-source | 0 |
| Symlinks / submodules | 0 / 0 |
| Oversize (> 1 MiB blob) | 0 |
| Unreadable (blob not local) | 0 |
| **Audited source files** | **5** |
| **Audited source bytes** | **99109** |
| Shards | 1 |

### Parse depth of the audited scope

- Parse status: `{"partial": 5}`
- Files analyzed: 0 of 5
- In scope but in a language no selected detector declares: `{}`
- Not analyzed, by reason: `{"incomplete_ast:partial": 5}`
- Candidates: 16 in 5 files
- Candidates by the parse status of their file: `{"partial": 16}`
- Candidates with runner-recorded obligations: 16
- Candidates with driver-synthesized unknown obligations: 0

### File accounting (must close)

- 5 selected = 0 complete + 5 partial + 0 failed + 0 unclaimed-by-detector + 0 dropped-by-loader + 0 not-run
- Identity: `files_selected = parse_complete + parse_partial + parse_failed + unclaimed_by_detector + dropped_by_loader + not_run_files`
- Closed: **True**
- NOTE: A blocked run records scope_files and scope_loc as 0 even though it emitted candidates; its per-candidate evidence obligations are recorded as for any other run. Read the applicable/analyzed counts for those shards, not the zero.

## 3. Candidates for review

> A candidate seen by both passes is one interpretation applied twice to the same
> file — repetition, not independent corroboration, and not a promotion.

| # | File:line | Symbol | Rule | Mechanism CWE | Consequence | Parse | Obligations |
|---:|---|---|---|---|---|---|---|
| 1 | `frameworks/kits/ability/native/src/continuation/distributed/reverse_continuation_scheduler_primary_stub.cpp:63` | `ReverseContinuationSchedulerPrimaryStub::OnRemoteRequest` | `ipc.relay.descriptor-boundary` | CWE-441 | boundary_bypass | partial | 4 (shared_runner) |
| 2 | `frameworks/kits/ability/native/src/continuation/remote_register_service/connect_callback_stub.cpp:68` | `ConnectCallbackStub::OnRemoteRequest` | `ipc.relay.descriptor-boundary` | CWE-441 | boundary_bypass | partial | 4 (shared_runner) |
| 3 | `interfaces/innerkits/app_manager/src/appmgr/app_mgr_stub.cpp:168` | `AppMgrStub::HandleGetAmsMgr` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 5 (shared_runner) |
| 4 | `interfaces/innerkits/app_manager/src/appmgr/app_mgr_stub.cpp:359` | `AppMgrStub::HandleGetAbilityRecordsByProcessID` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 5 (shared_runner) |
| 5 | `services/abilitymgr/src/ability_manager_stub.cpp:294` | `AbilityManagerStub::AcquireDataAbilityInner` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 4 (shared_runner) |
| 6 | `services/abilitymgr/src/ability_manager_stub.cpp:354` | `AbilityManagerStub::StartAbilityInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 7 | `services/abilitymgr/src/ability_manager_stub.cpp:415` | `AbilityManagerStub::StartAbilityAddCallerInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 8 | `services/abilitymgr/src/ability_manager_stub.cpp:437` | `AbilityManagerStub::ConnectAbilityInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 9 | `services/abilitymgr/src/ability_manager_stub.cpp:523` | `AbilityManagerStub::StartAbilityForSettingsInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 10 | `services/abilitymgr/src/ability_manager_stub.cpp:549` | `AbilityManagerStub::StartAbilityForOptionsInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 11 | `services/abilitymgr/src/ability_manager_stub.cpp:583` | `AbilityManagerStub::GetWantSenderInner` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 4 (shared_runner) |
| 12 | `services/abilitymgr/src/ability_manager_stub.cpp:1008` | `AbilityManagerStub::StartAbilityByCallInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 13 | `services/abilitymgr/src/ability_manager_stub.cpp:1260` | `AbilityManagerStub::GetTopAbilityTokenInner` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 4 (shared_runner) |
| 14 | `services/abilitymgr/src/ability_scheduler_stub.cpp:208` | `AbilitySchedulerStub::OpenFileInner` | `ipc.auth.missing` | CWE-862 | unauthorized_effect | partial | 4 (shared_runner) |
| 15 | `services/abilitymgr/src/ability_scheduler_stub.cpp:213` | `AbilitySchedulerStub::OpenFileInner` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 4 (shared_runner) |
| 16 | `services/abilitymgr/src/ability_scheduler_stub.cpp:628` | `AbilitySchedulerStub::CallRequestInner` | `ipc.capability.export` | CWE-926 | capability_exposure CWE-668 | partial | 4 (shared_runner) |

### Candidate 1: `ipc.relay.descriptor-boundary` at `frameworks/kits/ability/native/src/continuation/distributed/reverse_continuation_scheduler_primary_stub.cpp:63`

- Symbol: `ReverseContinuationSchedulerPrimaryStub::OnRemoteRequest`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`185021995fa87a1b…`)
- Mechanism CWE: CWE-441; possible consequence: boundary_bypass\

  AUTH-01 candidate: Unresolved member-pointer IPC dispatch lacks interface-descriptor validation; callee remains unknown. Entry=ReverseContinuationSchedulerPrimaryStub::OnRemoteRequest; possible consequence (not established): a caller of one interface may reach behaviour reserved for another [boundary_bypass]; path=((54, 'descriptor != token => False'), (60, 'iter != requestFuncMap_.end() => True'), (62, 'func != nullptr => True'))

  Pinned source `2325ec4623fc…`, lines 59-67:

  ```c++
        59      auto iter = requestFuncMap_.find(code);
        60      if (iter != requestFuncMap_.end()) {
        61          auto func = iter->second;
        62          if (func != nullptr) {
  >     63              return (this->*func)(data, reply);
        64          } else {
        65              HILOG_WARN("ReverseContinuationSchedulerPrimaryStub::OnRemoteRequest failed, func is nullptr");
        66          }
        67      } else {
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 2: `ipc.relay.descriptor-boundary` at `frameworks/kits/ability/native/src/continuation/remote_register_service/connect_callback_stub.cpp:68`

- Symbol: `ConnectCallbackStub::OnRemoteRequest`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`9c3889484ad0ce85…`)
- Mechanism CWE: CWE-441; possible consequence: boundary_bypass\

  AUTH-01 candidate: Unresolved member-pointer IPC dispatch lacks interface-descriptor validation; callee remains unknown. Entry=ConnectCallbackStub::OnRemoteRequest; possible consequence (not established): a caller of one interface may reach behaviour reserved for another [boundary_bypass]; path=((60, 'token.compare(IConnectCallback::GetDescriptor()) != 0 => False'), (65, 'localFuncIt != memberFuncMap_.end() => True'), (67, 'memberFunc != nullptr => True'))

  Pinned source `d169d04056de…`, lines 64-72:

  ```c++
        64      auto localFuncIt = memberFuncMap_.find(code);
        65      if (localFuncIt != memberFuncMap_.end()) {
        66          auto memberFunc = localFuncIt->second;
        67          if (memberFunc != nullptr) {
  >     68              return (this->*memberFunc)(data, reply);
        69          }
        70      }
        71      HILOG_INFO("ConnectCallbackStub::OnRemoteRequest, default case, need check.");
        72      return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 3: `ipc.capability.export` at `interfaces/innerkits/app_manager/src/appmgr/app_mgr_stub.cpp:168`

- Symbol: `AppMgrStub::HandleGetAmsMgr`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`bd5cec80057f1df5…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteRemoteObject lacks a recognized caller authorization on this path. Entry=AppMgrStub::HandleGetAmsMgr [dispatch=map_member_ptr codes=static_cast<uint32_t>(IAppMgr::Message::APP_GET_MGR_INSTANCE)]; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=((164, 'amsMgr => True'),)

  Pinned source `62301fe0ec1b…`, lines 164-172:

  ```c++
       164      if (!amsMgr) {
       165          HILOG_ERROR("abilitymgr instance is nullptr");
       166          result = ERR_NO_INIT;
       167      } else {
  >    168          if (!reply.WriteRemoteObject(amsMgr->AsObject())) {
       169              HILOG_ERROR("failed to reply abilitymgr instance to client, for write parcel error");
       170              result = ERR_APPEXECFWK_PARCEL_ERROR;
       171          }
       172      }
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `dispatch_binding` [unknown] (origin `shared_runner`) — Handler was admitted as an entry from a source-derived dispatch binding. Verify dispatcher-level guards (e.g. IsCallerValid/IsPermissionGranted), their dominance over this transaction code, and the overload/receiver binding.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 4: `ipc.capability.export` at `interfaces/innerkits/app_manager/src/appmgr/app_mgr_stub.cpp:359`

- Symbol: `AppMgrStub::HandleGetAbilityRecordsByProcessID`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`bd5cec80057f1df5…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteRemoteObject lacks a recognized caller authorization on this path. Entry=AppMgrStub::HandleGetAbilityRecordsByProcessID [dispatch=map_member_ptr codes=static_cast<uint32_t>(IAppMgr::Message::APP_GET_ABILITY_RECORDS_BY_PROCESS_ID)]; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=()

  Pinned source `62301fe0ec1b…`, lines 355-363:

  ```c++
       355      std::vector<sptr<IRemoteObject>> tokens;
       356      auto result = GetAbilityRecordsByProcessID(pid, tokens);
       357      reply.WriteInt32(tokens.size());
       358      for (auto &it : tokens) {
  >    359          if (!reply.WriteRemoteObject(it)) {
       360              HILOG_ERROR("failed to write query result.");
       361              return ERR_FLATTEN_OBJECT;
       362          }
       363      }
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `dispatch_binding` [unknown] (origin `shared_runner`) — Handler was admitted as an entry from a source-derived dispatch binding. Verify dispatcher-level guards (e.g. IsCallerValid/IsPermissionGranted), their dominance over this transaction code, and the overload/receiver binding.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 5: `ipc.capability.export` at `services/abilitymgr/src/ability_manager_stub.cpp:294`

- Symbol: `AbilityManagerStub::AcquireDataAbilityInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteRemoteObject lacks a recognized caller authorization on this path. Entry=AbilityManagerStub::AcquireDataAbilityInner; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=((293, 'result => True'),)

  Pinned source `9d9d65813728…`, lines 290-298:

  ```c++
       290      sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
       291      sptr<IAbilityScheduler> result = AcquireDataAbility(*uri, tryBind, callerToken);
       292      HILOG_DEBUG("acquire data ability %{public}s", result ? "ok" : "failed");
       293      if (result) {
  >    294          reply.WriteRemoteObject(result->AsObject());
       295      } else {
       296          reply.WriteParcelable(nullptr);
       297      }
       298      return NO_ERROR;
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 6: `ipc.auth.missing` at `services/abilitymgr/src/ability_manager_stub.cpp:354`

- Symbol: `AbilityManagerStub::StartAbilityInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call StartAbility has a structured path without a recognized caller authorization. Entry=AbilityManagerStub::StartAbilityInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((348, 'want == nullptr => False'),)

  Pinned source `9d9d65813728…`, lines 350-358:

  ```c++
       350          return ERR_INVALID_VALUE;
       351      }
       352      int32_t userId = data.ReadInt32();
       353      int requestCode = data.ReadInt32();
  >    354      int32_t result = StartAbility(*want, userId, requestCode);
       355      reply.WriteInt32(result);
       356      delete want;
       357      return NO_ERROR;
       358  }
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 7: `ipc.auth.missing` at `services/abilitymgr/src/ability_manager_stub.cpp:415`

- Symbol: `AbilityManagerStub::StartAbilityAddCallerInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call StartAbility has a structured path without a recognized caller authorization. Entry=AbilityManagerStub::StartAbilityAddCallerInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((403, 'want == nullptr => False'), (409, 'data.ReadBool() => True'))

  Pinned source `9d9d65813728…`, lines 411-419:

  ```c++
       411      }
       412
       413      int32_t userId = data.ReadInt32();
       414      int requestCode = data.ReadInt32();
  >    415      int32_t result = StartAbility(*want, callerToken, userId, requestCode);
       416      reply.WriteInt32(result);
       417      delete want;
       418      return NO_ERROR;
       419  }
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 8: `ipc.auth.missing` at `services/abilitymgr/src/ability_manager_stub.cpp:437`

- Symbol: `AbilityManagerStub::ConnectAbilityInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call ConnectAbility has a structured path without a recognized caller authorization. Entry=AbilityManagerStub::ConnectAbilityInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((424, 'want == nullptr => False'), (430, 'data.ReadBool() => True'), (433, 'data.ReadBool() => True'))

  Pinned source `9d9d65813728…`, lines 433-441:

  ```c++
       433      if (data.ReadBool()) {
       434          token = data.ReadRemoteObject();
       435      }
       436      int32_t userId = data.ReadInt32();
  >    437      int32_t result = ConnectAbility(*want, callback, token, userId);
       438      reply.WriteInt32(result);
       439      delete want;
       440      return NO_ERROR;
       441  }
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 9: `ipc.auth.missing` at `services/abilitymgr/src/ability_manager_stub.cpp:523`

- Symbol: `AbilityManagerStub::StartAbilityForSettingsInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call StartAbility has a structured path without a recognized caller authorization. Entry=AbilityManagerStub::StartAbilityForSettingsInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((507, 'want == nullptr => False'), (512, 'abilityStartSetting == nullptr => False'), (518, 'data.ReadBool() => True'))

  Pinned source `9d9d65813728…`, lines 519-527:

  ```c++
       519          callerToken = data.ReadRemoteObject();
       520      }
       521      int32_t userId = data.ReadInt32();
       522      int requestCode = data.ReadInt32();
  >    523      int32_t result = StartAbility(*want, *abilityStartSetting, callerToken, userId, requestCode);
       524      reply.WriteInt32(result);
       525      delete want;
       526      delete abilityStartSetting;
       527      return NO_ERROR;
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 10: `ipc.auth.missing` at `services/abilitymgr/src/ability_manager_stub.cpp:549`

- Symbol: `AbilityManagerStub::StartAbilityForOptionsInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call StartAbility has a structured path without a recognized caller authorization. Entry=AbilityManagerStub::StartAbilityForOptionsInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((533, 'want == nullptr => False'), (538, 'startOptions == nullptr => False'), (544, 'data.ReadBool() => True'))

  Pinned source `9d9d65813728…`, lines 545-553:

  ```c++
       545          callerToken = data.ReadRemoteObject();
       546      }
       547      int32_t userId = data.ReadInt32();
       548      int requestCode = data.ReadInt32();
  >    549      int32_t result = StartAbility(*want, *startOptions, callerToken, userId, requestCode);
       550      reply.WriteInt32(result);
       551      delete want;
       552      delete startOptions;
       553      return NO_ERROR;
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 11: `ipc.capability.export` at `services/abilitymgr/src/ability_manager_stub.cpp:583`

- Symbol: `AbilityManagerStub::GetWantSenderInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteRemoteObject lacks a recognized caller authorization on this path. Entry=AbilityManagerStub::GetWantSenderInner; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=((574, 'wantSenderInfo == nullptr => False'), (579, 'data.ReadBool() => True'))

  Pinned source `9d9d65813728…`, lines 579-587:

  ```c++
       579      if (data.ReadBool()) {
       580          callerToken = data.ReadRemoteObject();
       581      }
       582      sptr<IWantSender> wantSender = GetWantSender(*wantSenderInfo, callerToken);
  >    583      if (!reply.WriteRemoteObject(((wantSender == nullptr) ? nullptr : wantSender->AsObject()))) {
       584          HILOG_ERROR("failed to reply wantSender instance to client, for write parcel error");
       585          return ERR_INVALID_VALUE;
       586      }
       587      return NO_ERROR;
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 12: `ipc.auth.missing` at `services/abilitymgr/src/ability_manager_stub.cpp:1008`

- Symbol: `AbilityManagerStub::StartAbilityByCallInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call StartAbilityByCall has a structured path without a recognized caller authorization. Entry=AbilityManagerStub::StartAbilityByCallInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((998, 'want == nullptr => False'), (1005, 'data.ReadBool() => True'))

  Pinned source `9d9d65813728…`, lines 1004-1012:

  ```c++
      1004      sptr<IRemoteObject> callerToken = nullptr;
      1005      if (data.ReadBool()) {
      1006          callerToken = data.ReadRemoteObject();
      1007      }
  >   1008      int32_t result = StartAbilityByCall(*want, callback, callerToken);
      1009
      1010      HILOG_DEBUG("resolve call ability ret = %d", result);
      1011
      1012      reply.WriteInt32(result);
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 13: `ipc.capability.export` at `services/abilitymgr/src/ability_manager_stub.cpp:1260`

- Symbol: `AbilityManagerStub::GetTopAbilityTokenInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`182fc1f0f1d52a3c…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteRemoteObject lacks a recognized caller authorization on this path. Entry=AbilityManagerStub::GetTopAbilityTokenInner; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=()

  Pinned source `9d9d65813728…`, lines 1256-1264:

  ```c++
      1256  int AbilityManagerStub::GetTopAbilityTokenInner(MessageParcel &data, MessageParcel &reply)
      1257  {
      1258      sptr<IRemoteObject> token;
      1259      auto result = GetTopAbility(token);
  >   1260      if (!reply.WriteRemoteObject(token)) {
      1261          HILOG_ERROR("data write failed.");
      1262          return ERR_INVALID_VALUE;
      1263      }
      1264      reply.WriteInt32(result);
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 14: `ipc.auth.missing` at `services/abilitymgr/src/ability_scheduler_stub.cpp:208`

- Symbol: `AbilitySchedulerStub::OpenFileInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`7d57447bdce60b32…`)
- Mechanism CWE: CWE-862; possible consequence: unauthorized_effect\

  AUTH-02 candidate: Sensitive modeled call OpenFile has a structured path without a recognized caller authorization. Entry=AbilitySchedulerStub::OpenFileInner; possible consequence (not established): an operation intended to require authorization may run without it [unauthorized_effect]; path=((199, 'uri == nullptr => False'), (204, 'mode.empty() => False'))

  Pinned source `9bf0339c2b17…`, lines 204-212:

  ```c++
       204      if (mode.empty()) {
       205          HILOG_ERROR("AbilitySchedulerStub mode is nullptr");
       206          return ERR_INVALID_VALUE;
       207      }
  >    208      int fd = OpenFile(*uri, mode);
       209      if (fd < 0) {
       210          HILOG_ERROR("OpenFile fail, fd is %{pubilc}d", fd);
       211          return ERR_INVALID_VALUE;
       212      }
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 15: `ipc.capability.export` at `services/abilitymgr/src/ability_scheduler_stub.cpp:213`

- Symbol: `AbilitySchedulerStub::OpenFileInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`7d57447bdce60b32…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteFileDescriptor lacks a recognized caller authorization on this path. Entry=AbilitySchedulerStub::OpenFileInner; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=((199, 'uri == nullptr => False'), (204, 'mode.empty() => False'), (209, 'fd < 0 => False'))

  Pinned source `9bf0339c2b17…`, lines 209-217:

  ```c++
       209      if (fd < 0) {
       210          HILOG_ERROR("OpenFile fail, fd is %{pubilc}d", fd);
       211          return ERR_INVALID_VALUE;
       212      }
  >    213      if (!reply.WriteFileDescriptor(fd)) {
       214          HILOG_ERROR("fail to WriteFileDescriptor fd");
       215          return ERR_INVALID_VALUE;
       216      }
       217      return NO_ERROR;
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

### Candidate 16: `ipc.capability.export` at `services/abilitymgr/src/ability_scheduler_stub.cpp:628`

- Symbol: `AbilitySchedulerStub::CallRequestInner`
- Seen by passes: `all-files`
- File parse status: `partial` (analysis status `not_analyzed`, reason `incomplete_ast:partial`)
- Source binding: `bound` (`7d57447bdce60b32…`)
- Mechanism CWE: CWE-926; possible consequence: capability_exposure CWE-668

  CAP-01 candidate: Capability export WriteRemoteObject lacks a recognized caller authorization on this path. Entry=AbilitySchedulerStub::CallRequestInner; possible consequence (not established): an object reference, file descriptor or service capability may leave the authorized owner [capability_exposure CWE-668]; path=((618, 'call => True'), (623, 'reply.WriteInt32(NO_ERROR) => True'))

  Pinned source `9bf0339c2b17…`, lines 624-632:

  ```c++
       624          HILOG_ERROR("CallRequestInner result error");
       625          return ERR_INVALID_VALUE;
       626      }
       627
  >    628      if (!reply.WriteRemoteObject(call)) {
       629          HILOG_ERROR("Connect done remote object error.");
       630          return ERR_INVALID_VALUE;
       631      }
       632
  ```

  Still unproven before any claim:

  - `entry_reachability` [unknown] (origin `shared_runner`) — Verify actual caller reachability and product build/macro conditions.
  - `callee_and_policy` [unknown] (origin `shared_runner`) — Verify overload/receiver binding, required permission and any upstream guard.
  - `security_impact` [unknown] (origin `shared_runner`) — Independently review attacker control, trust boundary and concrete effect.
  - `consequence` [unknown] (origin `shared_runner`) — Establish what the modeled path can actually expose: which data, capability or state the caller reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated in the message is a possibility, not a demonstrated effect.

## 4. Not audited

- Include prefixes: `frameworks/kits/ability/native/src/continuation/distributed/reverse_continuation_scheduler_primary_stub.cpp`, `frameworks/kits/ability/native/src/continuation/remote_register_service/connect_callback_stub.cpp`, `interfaces/innerkits/app_manager/src/appmgr/app_mgr_stub.cpp`, `services/abilitymgr/src/ability_manager_stub.cpp`, `services/abilitymgr/src/ability_scheduler_stub.cpp`
- Exclusions applied: —

| File | Reason |
|---|---|
| — | nothing was dropped outside the include prefixes |

## 5. Root-cause intersection

- State: `not_measured`
- No labelled root-cause set is bound to this component. The curated historical pairs are measured by measure_entry_coverage.py; a component audit reports candidates and coverage only.

## 6. Limitations

- Candidates are unverified syntax evidence, not vulnerabilities.
- Zero candidates does NOT mean the component is free of vulnerabilities.
- The declared repository is user input; source is pinned local Git objects, not an OpenHarmony product build.
- Excluded, oversize, non-UTF8, symlink, submodule and unreadable entries are outside the audited scope; their counts are reported, not hidden.
- No compilation flags, macro configuration, symbolic execution or reachability proof. Preprocessor-conditional code is parsed as written.
- Candidates from a partially parsed file carry a partial AST; the finding is kept but its parse depth is reported per row.
- Where the shared runner recorded no obligations for a candidate, the driver attaches its standing questions at status unknown and marks them origin: audit_driver. That is a gap in the recorded evidence, not an absence of obligations, and not runner-produced evidence. Where the record is present the driver adds nothing of its own.
- A candidate seen by both passes is one interpretation applied twice to the same file, not two independent sources of evidence.
- Sharding is deterministic and the candidate set matched on one component under one alternative shard configuration. Invariance under arbitrary sharding is not claimed: a rule with a component-global view would need whole-component evaluation, which no pass here performs.
- `elapsed_seconds` and `peak_rss_kb` describe one run of one process, including the interpreter start and the report write. The RSS figure is a per-process high-water mark, so it is the audit's own cost only when the audit owns its process; a caller auditing several components in one process gets a running maximum. Neither number is a bound, and neither says anything about detection quality.
