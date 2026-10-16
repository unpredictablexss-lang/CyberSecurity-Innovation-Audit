# AUTH-01 precision probe (report-field screen + pinned-blob read)

Rule: `ipc.relay.descriptor-boundary`. Modes are read off the report's own
fields, so the screen needs no source access and reproduces from the
artifact. Every flagged candidate is then excerpted from the pinned blob
at its own commit. Nothing is deleted or re-scored here.

- **baseline30**: 92 candidates, 10 flagged (11%) -- guard_symbol=8, empty_path=6, enforced_path=0
- **bline12**: 11 candidates, 5 flagged (45%) -- guard_symbol=2, empty_path=2, enforced_path=1

## Flagged candidates

### baseline30 -- communication_ipc

`ipc/native/src/taihe/src/ohos.rpc.rpc.impl.cpp:231` entry `ANIRemoteObject::OnRemoteRequest`

- modes: empty_path
- handler the message names: `ANIRemoteObject::callOnRemoteMessageRequest`

```
   226     auto jsReply = taihe::make_holder<MessageSequenceImpl, ::ohos::rpc::rpc::MessageSequence>(&reply);
   227     jsReply->AddJsObjWeakRef(jsReply);
   228     auto jsOption = taihe::make_holder<MessageOptionImpl, ::ohos::rpc::rpc::MessageOption>(option.GetFlags(),
   229         option.GetWaitTime());
   230     ::ohos::rpc::rpc::OnRemoteMessageRequestResultUnion res =
   231         callOnRemoteMessageRequest(code, jsData, jsReply, jsOption);
   232     if (res.holds_booleanValue()) {
   233         bool boolRes = res.get_booleanValue_ref();
   234         return boolRes ? OHOS::ERR_NONE : OHOS::ERR_UNKNOWN_TRANSACTION;
   235     } else {
   236         res.get_promiseValue_ref().on_complete(
```

### baseline30 -- distributeddatamgr_pasteboard

`services/zidl/src/pasteboard_disposable_observer_stub.cpp:48` entry `PasteboardDisposableObserverStub::OnRemoteRequest`

- modes: empty_path
- handler the message names: `PasteboardDisposableObserverStub::OnRemoteRequest`

```
    43         "invalid code, code=%{public}u", code);
    44     auto memberFunc = iter->second;
    45     PASTEBOARD_CHECK_AND_RETURN_RET_LOGE(memberFunc != nullptr,
    46         static_cast<int32_t>(PasteboardError::INVALID_PARAM_ERROR), PASTEBOARD_MODULE_SERVICE,
    47         "func is null, code=%{public}u", code);
    48     return (this->*memberFunc)(data, reply);
    49 }
    50 
    51 int32_t PasteboardDisposableObserverStub::OnTextReceivedStub(MessageParcel &data, MessageParcel &reply)
    52 {
    53     std::string text = data.ReadString();
```

### baseline30 -- inputmethod_imf

`services/src/input_method_system_ability.cpp:168` entry `InputMethodSystemAbility::ResetDelayUnloadTask`

- modes: guard_symbol
- handler the message names: `InputMethodSystemAbility::IsImeInUse`

```
   163 }
   164 void InputMethodSystemAbility::ResetDelayUnloadTask(uint32_t code)
   165 {
   166     auto task = [this]() {
   167         IMSA_HILOGI("start unload task");
   168         if (IsImeInUse()) {
   169             IMSA_HILOGI("ime in use");
   170             return;
   171         }
   172         auto onDemandStartStopSa = std::make_shared<OnDemandStartStopSa>();
   173         onDemandStartStopSa->UnloadInputMethodSystemAbility();
```

### baseline30 -- multimedia_player_framework

`services/services/player/ipc/player_service_stub.cpp:376` entry `PlayerServiceStub::OnRemoteRequest`

- modes: guard_symbol
- handler the message names: `PlayerServiceStub::CheckandDoUnFreeze`

```
   371                 FAKE_POINTER(this), funcName.c_str());
   372         }
   373         if (memberFunc != nullptr) {
   374             auto task = std::make_shared<TaskHandler<int>>([&, this] {
   375                 (void)IpcRecovery(false);
   376                 auto res = CheckandDoUnFreeze();
   377                 CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, res, "UnFreeze failed");
   378                 int32_t ret = -1;
   379                 ret = memberFunc(data, reply);
   380                 return ret;
   381             });
```

### baseline30 -- multimedia_player_framework

`services/services/recorder/ipc/recorder_service_stub.cpp:215` entry `RecorderServiceStub::OnRemoteRequest`

- modes: guard_symbol
- handler the message names: `RecorderServiceStub::CheckPermission`

```
   210         audioSourceType_ = static_cast<AudioSourceType>(type);
   211     }
   212 
   213     int32_t permissionResult = Security::AccessToken::PERMISSION_GRANTED;
   214     if (AUDIO_REQUEST.count(code) != 0) {
   215         permissionResult = CheckPermission();
   216         needAudioPermissionCheck = true;
   217     } else if (COMMON_REQUEST.count(code) != 0 && needAudioPermissionCheck) {
   218         permissionResult = CheckPermission();
   219     } else {
   220         // none audio request no need to check permission in recorder server
```

### baseline30 -- multimedia_player_framework

`services/services/recorder/ipc/recorder_service_stub.cpp:218` entry `RecorderServiceStub::OnRemoteRequest`

- modes: guard_symbol
- handler the message names: `RecorderServiceStub::CheckPermission`

```
   213     int32_t permissionResult = Security::AccessToken::PERMISSION_GRANTED;
   214     if (AUDIO_REQUEST.count(code) != 0) {
   215         permissionResult = CheckPermission();
   216         needAudioPermissionCheck = true;
   217     } else if (COMMON_REQUEST.count(code) != 0 && needAudioPermissionCheck) {
   218         permissionResult = CheckPermission();
   219     } else {
   220         // none audio request no need to check permission in recorder server
   221     }
   222     if (permissionResult == Security::AccessToken::PERMISSION_DENIED) {
   223         MEDIA_LOGE("User do not have the required permissions for the current operation.");
```

### baseline30 -- systemabilitymgr_samgr

`frameworks/native/source/system_ability_load_callback_stub.cpp:36` entry `SystemAbilityLoadCallbackStub::OnRemoteRequest`

- modes: guard_symbol, empty_path
- handler the message names: `SystemAbilityLoadCallbackStub::EnforceInterceToken`

```
    31 }
    32 int32_t SystemAbilityLoadCallbackStub::OnRemoteRequest(uint32_t code,
    33     MessageParcel& data, MessageParcel& reply, MessageOption& option)
    34 {
    35     HILOGD("SystemAbilityLoadCallbackStub::OnRemoteRequest, code = %{public}u", code);
    36     if (!EnforceInterceToken(data)) {
    37         HILOGW("SystemAbilityLoadCallbackStub::OnRemoteRequest check interface token failed!");
    38         return ERR_PERMISSION_DENIED;
    39     }
    40     switch (code) {
    41         case ON_LOAD_SYSTEM_ABILITY_SUCCESS:
```

### baseline30 -- systemabilitymgr_samgr

`frameworks/native/source/system_ability_status_change_stub.cpp:46` entry `SystemAbilityStatusChangeStub::OnRemoteRequest`

- modes: guard_symbol, empty_path
- handler the message names: `SystemAbilityStatusChangeStub::EnforceInterceToken`

```
    41 
    42 int32_t SystemAbilityStatusChangeStub::OnRemoteRequest(uint32_t code,
    43     MessageParcel& data, MessageParcel& reply, MessageOption& option)
    44 {
    45     HILOGD("SystemAbilityStatusChangeStub::code:%{public}u, flags:%{public}d", code, option.GetFlags());
    46     if (!EnforceInterceToken(data)) {
    47         HILOGW("check interface token failed!");
    48         return ERR_PERMISSION_DENIED;
    49     }
    50     auto iter = memberFuncMap_.find(code);
    51     if (iter != memberFuncMap_.end()) {
```

### baseline30 -- systemabilitymgr_samgr

`frameworks/native/source/system_process_status_change_stub.cpp:39` entry `SystemProcessStatusChangeStub::OnRemoteRequest`

- modes: guard_symbol, empty_path
- handler the message names: `SystemProcessStatusChangeStub::EnforceInterceToken`

```
    34 
    35 int32_t SystemProcessStatusChangeStub::OnRemoteRequest(uint32_t code,
    36     MessageParcel& data, MessageParcel& reply, MessageOption& option)
    37 {
    38     HILOGD("ProcStaChange,code:%{public}u,flags:%{public}d", code, option.GetFlags());
    39     if (!EnforceInterceToken(data)) {
    40         HILOGW("check interface token failed!");
    41         return ERR_PERMISSION_DENIED;
    42     }
    43     auto iter = memberFuncMap_.find(code);
    44     if (iter != memberFuncMap_.end()) {
```

### baseline30 -- systemabilitymgr_samgr

`services/samgr/native/source/system_ability_manager_stub.cpp:222` entry `SystemAbilityManagerStub::OnRemoteRequest`

- modes: guard_symbol, empty_path
- handler the message names: `SystemAbilityManagerStub::EnforceInterceToken`

```
   217     MessageParcel& data, MessageParcel& reply, MessageOption &option)
   218 {
   219     HILOGD("SAMStub::OnReceived, code = %{public}u, callerPid = %{public}d",
   220         code, IPCSkeleton::GetCallingPid());
   221     Samgr::MemoryGuard cacheGuard;
   222     if (!EnforceInterceToken(data)) {
   223         HILOGE("SAMStub::OnReceived, code = %{public}u, check interfaceToken failed", code);
   224         return ERR_PERMISSION_DENIED;
   225     }
   226     auto itFunc = memberFuncMap_.find(code);
   227     if (itFunc != memberFuncMap_.end()) {
```

### bline12 -- ability_dmsfwk

`services/dtbschedmgr/src/distributed_sched_stub.cpp:266` entry `DistributedSchedStub::OnRemoteRequest`

- modes: guard_symbol
- handler the message names: `DistributedSchedStub::EnforceInterfaceToken`

```
   261 
   262     const auto& funcsMap = IsLocalCalling ? localFuncsMap_ : remoteFuncsMap_;
   263     auto iter = funcsMap.find(code);
   264     if (iter != funcsMap.end()) {
   265         auto func = iter->second;
   266         if (!EnforceInterfaceToken(data)) {
   267             HILOGW("OnRemoteRequest interface token check failed!");
   268             return DMS_PERMISSION_DENIED;
   269         }
   270         if (func != nullptr) {
   271             return (this->*func)(data, reply);
```

### bline12 -- ability_dmsfwk

`services/dtbschedmgr/src/distributed_sched_stub.cpp:271` entry `DistributedSchedStub::OnRemoteRequest`

- modes: enforced_path
- handler the message names: `DistributedSchedStub::OnRemoteRequest`
- recorded condition already True: `EnforceInterfaceToken(data) => True`

```
   266         if (!EnforceInterfaceToken(data)) {
   267             HILOGW("OnRemoteRequest interface token check failed!");
   268             return DMS_PERMISSION_DENIED;
   269         }
   270         if (func != nullptr) {
   271             return (this->*func)(data, reply);
   272         }
   273     }
   274 
   275     HILOGW("OnRemoteRequest default case, need check.");
   276     return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
```

### bline12 -- telephony_core_service

`frameworks/native/src/iesim_service_callback_stub.cpp:219` entry `IEsimServiceCallbackStub::OnRemoteRequest`

- modes: empty_path
- handler the message names: `IEsimServiceCallbackStub::OnRemoteRequest`

```
   214 
   215 int IEsimServiceCallbackStub::OnRemoteRequest(
   216     uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
   217 {
   218     TELEPHONY_LOGI("IEsimServiceCallbackStub::OnRemoteRequest requestId:%{public}d", code);
   219     return OnEsimServiceCallback(static_cast<EsimServiceCallback>(code), data);
   220 }
   221 void IEsimServiceCallbackStub::OnGetEuiccInfo(const EuiccInfo &result, const int32_t errorCode)
   222 {}
   223 
   224 void IEsimServiceCallbackStub::OnDeleteProfile(const int32_t &result, const int32_t errorCode)
```

### bline12 -- telephony_core_service

`frameworks/native/src/raw_parcel_callback_stub.cpp:31` entry `RawParcelCallbackStub::Transfer`

- modes: guard_symbol
- handler the message names: `RawParcelCallbackStub::CheckCurrentDescriptor`

```
    26 void RawParcelCallbackStub::Transfer(std::function<void(MessageParcel&)> writer, MessageParcel &data)
    27 {
    28     if (writer) { // same process ipc call
    29         writer(data);
    30     } else {
    31         if (!CheckCurrentDescriptor(data)) {
    32             return;
    33         }
    34     }
    35     if (reader_) {
    36         reader_(data);
```

### bline12 -- telephony_core_service

`frameworks/native/src/raw_parcel_callback_stub.cpp:44` entry `RawParcelCallbackStub::OnRemoteRequest`

- modes: empty_path
- handler the message names: `RawParcelCallbackStub::Transfer`

```
    39 }
    40 
    41 int RawParcelCallbackStub::OnRemoteRequest(
    42     uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    43 {
    44     Transfer(nullptr, data);
    45     return TELEPHONY_ERR_SUCCESS;
    46 }
    47 
    48 bool RawParcelCallbackStub::WaitForResult(int64_t timeoutMs)
    49 {
```
