# shared_ptr_race candidate triage (2026-10-18)

> Candidate-only lexical triage; counts are access-point diagnostics,
> not vulnerability, root-cause, or Precision/Recall measurements.

| Component | Files | Candidates | File/symbol groups | Class/member groups |
|---|---:|---:|---:|---:|
| `communication_dsoftbus` | 1656 | 87 | 13 | 19 |
| `distributeddatamgr_kv_store` | 1446 | 179 | 35 | 68 |
| `security_access_token` | 550 | 71 | 22 | 50 |
| `update_updateservice` | 219 | 24 | 4 | 13 |
| `window_window_manager` | 1112 | 143 | 34 | 62 |

| Category | Member groups | Attributed candidate findings |
|---|---:|---:|
| `constructor_only` | 53 | 0 |
| `cross_function_unknown` | 82 | 451 |
| `mutable_owner` | 24 | 42 |
| `stable_owner` | 45 | 0 |
| `write_only` | 8 | 9 |

## Class/member groups

### `communication_dsoftbus`

- `Communication::StreamManager::msgManager_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `Communication::StreamManager::socketListener_`: category=mutable_owner, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `Communication::StreamManager::socketMap_`: category=stable_owner, accesses=15 (reads=15, writes=0, initializations=0), locks=none, candidate_findings=0
- `Communication::StreamManager::streamListener_`: category=cross_function_unknown, accesses=3 (reads=1, writes=1, initializations=1), locks=none, candidate_findings=3
- `Communication::VtpInstance::instance_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=vtpLock_, candidate_findings=2
- `DurationStatistic::calculators_`: category=stable_owner, accesses=4 (reads=4, writes=0, initializations=0), locks=none, candidate_findings=0
- `InnerLink::channel_`: category=cross_function_unknown, accesses=4 (reads=3, writes=1, initializations=0), locks=none, candidate_findings=4
- `InnerLink::linkIds_`: category=stable_owner, accesses=9 (reads=9, writes=0, initializations=0), locks=none, candidate_findings=0
- `LinkManager::links_`: category=stable_owner, accesses=33 (reads=33, writes=0, initializations=0), locks=none, candidate_findings=0
- `NegotiateCommand::channel_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::StreamAdaptor::streamManager_`: category=cross_function_unknown, accesses=7 (reads=6, writes=1, initializations=0), locks=none, candidate_findings=7
- `P2pConnectState::operation_`: category=cross_function_unknown, accesses=19 (reads=15, writes=4, initializations=0), locks=none, candidate_findings=19
- `P2pCreateGroupState::operation_`: category=cross_function_unknown, accesses=13 (reads=9, writes=4, initializations=0), locks=none, candidate_findings=13
- `P2pDestroyGroupState::operation_`: category=cross_function_unknown, accesses=13 (reads=9, writes=4, initializations=0), locks=none, candidate_findings=13
- `P2pEntity::pendingOperations_`: category=stable_owner, accesses=6 (reads=6, writes=0, initializations=0), locks=none, candidate_findings=0
- `ProcessorSelectorFactory::selector_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `WifiDirectEventQueue::queue_`: category=stable_owner, accesses=7 (reads=7, writes=0, initializations=0), locks=m_, candidate_findings=0
- `WifiDirectExecutor::processor_`: category=cross_function_unknown, accesses=16 (reads=13, writes=2, initializations=1), locks=none, candidate_findings=16
- `WifiDirectSchedulerFactory::scheduler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3

### `distributeddatamgr_kv_store`

- `<anonymous>::KVManagerImpl::jsDeathCbList_`: category=constructor_only, accesses=6 (reads=4, writes=0, initializations=2), locks=cbDeathListMutex_, candidate_findings=0
- `<anonymous>::KVManagerImpl::kvDataManager_`: category=constructor_only, accesses=19 (reads=18, writes=0, initializations=1), locks=cbDeathListMutex_, candidate_findings=0
- `<anonymous>::KVStoreResultSetImpl::nativeResultSet_`: category=constructor_only, accesses=28 (reads=27, writes=0, initializations=1), locks=none, candidate_findings=0
- `<anonymous>::KVStoreResultSetImpl::proxy_`: category=constructor_only, accesses=2 (reads=1, writes=0, initializations=1), locks=none, candidate_findings=0
- `<anonymous>::QueryImpl::nativeQueryPtr_`: category=constructor_only, accesses=45 (reads=44, writes=0, initializations=1), locks=none, candidate_findings=0
- `<anonymous>::ResultSetProxy::resultSet_`: category=constructor_only, accesses=1 (reads=0, writes=0, initializations=1), locks=none, candidate_findings=0
- `<anonymous>::SingleKVStoreImpl::nativeStore_`: category=constructor_only, accesses=73 (reads=72, writes=0, initializations=1), locks=dataObserversMutex_,syncObserversMutex_, candidate_findings=0
- `<anonymous>::SingleKVStoreImpl::syncObservers_`: category=stable_owner, accesses=6 (reads=6, writes=0, initializations=0), locks=syncObserversMutex_, candidate_findings=0
- `AutoSyncTimer::dmsAdapter_`: category=mutable_owner, accesses=5 (reads=4, writes=1, initializations=0), locks=delegateMutex_, candidate_findings=0
- `DevManager::deviceAdapter_`: category=mutable_owner, accesses=5 (reads=4, writes=1, initializations=0), locks=delegateMutex_, candidate_findings=0
- `DistributedDB::DBStatusAdapter::dbInfoHandle_`: category=cross_function_unknown, accesses=3 (reads=1, writes=1, initializations=1), locks=handleMutex_, candidate_findings=1
- `DistributedDB::Logger::logHandler`: category=cross_function_unknown, accesses=5 (reads=4, writes=1, initializations=0), locks=logMutex, candidate_findings=2
- `DistributedDB::RelationalSyncAbleStorage::storageEngine_`: category=constructor_only, accesses=54 (reads=53, writes=0, initializations=1), locks=securityOptionMutex_,transactionMutex_, candidate_findings=0
- `DistributedDB::RelationalSyncAbleStorage::syncAbleEngine_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=none, candidate_findings=1
- `DistributedDB::RuntimeContextImpl::assetsDownloadManager_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=assetsDownloadManagerLock_, candidate_findings=0
- `DistributedDB::RuntimeContextImpl::dataTranslate_`: category=cross_function_unknown, accesses=9 (reads=8, writes=1, initializations=0), locks=dataTranslateLock_, candidate_findings=8
- `DistributedDB::RuntimeContextImpl::dbStatusAdapter_`: category=cross_function_unknown, accesses=6 (reads=3, writes=1, initializations=2), locks=statusAdapterMutex_, candidate_findings=2
- `DistributedDB::RuntimeContextImpl::subscribeRecorder_`: category=cross_function_unknown, accesses=6 (reads=3, writes=1, initializations=2), locks=subscribeRecorderMutex_, candidate_findings=2
- `DistributedDB::RuntimeContextImpl::systemApiAdapter_`: category=cross_function_unknown, accesses=13 (reads=10, writes=1, initializations=2), locks=systemApiAdapterLock_, candidate_findings=2
- `DistributedDB::RuntimeContextImpl::timeTickMonitor_`: category=cross_function_unknown, accesses=18 (reads=13, writes=3, initializations=2), locks=timeTickMonitorLock_, candidate_findings=2
- `DistributedDB::SQLiteSingleVerRelationalStorageExecutor::assetLoader_`: category=cross_function_unknown, accesses=6 (reads=4, writes=1, initializations=1), locks=none, candidate_findings=6
- `DistributedDB::SingleVerDataSync::metadata_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=unsubscribeLock_, candidate_findings=0
- `DistributedDB::StorageEngineManager::instance_`: category=cross_function_unknown, accesses=8 (reads=7, writes=1, initializations=0), locks=instanceMutex_,storageEnginesLock_, candidate_findings=2
- `DistributedDB::StrategyProxy::handler_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=strategyMutex_, candidate_findings=1
- `DistributedDB::StrategyProxy::strategy_`: category=cross_function_unknown, accesses=18 (reads=15, writes=3, initializations=0), locks=strategyMutex_, candidate_findings=1
- `DistributedDB::SyncEngine::metadata_`: category=cross_function_unknown, accesses=4 (reads=1, writes=2, initializations=1), locks=none, candidate_findings=4
- `DistributedDB::SyncEngine::subManager_`: category=cross_function_unknown, accesses=17 (reads=16, writes=1, initializations=0), locks=none, candidate_findings=17
- `DistributedDB::SyncStateMachine::metadata_`: category=write_only, accesses=2 (reads=0, writes=1, initializations=1), locks=none, candidate_findings=2
- `DistributedDB::SyncerProxy::syncer_`: category=cross_function_unknown, accesses=67 (reads=65, writes=1, initializations=1), locks=syncerLock_, candidate_findings=65
- `DistributedDB::ThreadPoolStub::threadPool_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=threadPoolLock_, candidate_findings=1
- `DocumentDB::ResultSet::context_`: category=cross_function_unknown, accesses=12 (reads=11, writes=1, initializations=0), locks=none, candidate_findings=12
- `JSProxy::instance_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `JsKVStore::kvStore_`: category=cross_function_unknown, accesses=6 (reads=5, writes=1, initializations=0), locks=none, candidate_findings=6
- `JsKVStore::param_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=none, candidate_findings=1
- `JsKVStore::syncObservers_`: category=stable_owner, accesses=3 (reads=3, writes=0, initializations=0), locks=listMutex_, candidate_findings=0
- `JsKVStore::uvQueue_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=none, candidate_findings=1
- `JsSingleKVStore::kvStore_`: category=cross_function_unknown, accesses=6 (reads=5, writes=1, initializations=0), locks=none, candidate_findings=6
- `JsSingleKVStore::param_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `JsSingleKVStore::syncObservers_`: category=stable_owner, accesses=3 (reads=3, writes=0, initializations=0), locks=listMutex_, candidate_findings=0
- `JsSingleKVStore::uvQueue_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=none, candidate_findings=1
- `OHOS::AbilityContext::abilityInfo_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::ContextImpl::applicationInfo_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::ContextImpl::config_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::ContextImpl::hapModuleInfo_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::ContextImpl::parentContext_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=none, candidate_findings=1
- `OHOS::ContextImpl::resourceManager_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::Executor::self_`: category=cross_function_unknown, accesses=3 (reads=1, writes=1, initializations=1), locks=mutex_, candidate_findings=2
- `OHOS::ExecutorPool::scheduler_`: category=cross_function_unknown, accesses=5 (reads=3, writes=2, initializations=0), locks=mtx_, candidate_findings=0
- `OHOS::ExpireLruCache::data_`: category=stable_owner, accesses=13 (reads=13, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::Extension::callingInfo_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::ExtensionContext::abilityInfo_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=0
- `OHOS::KvStoreDataShareBridge::kvResultSet_`: category=constructor_only, accesses=7 (reads=6, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::KvStoreObserverClient::kvStoreObserver_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::MessageParcel::rawData_`: category=cross_function_unknown, accesses=6 (reads=4, writes=2, initializations=0), locks=none, candidate_findings=6
- `OHOS::MockAbilityContext::abilityInfo_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::MockAbilityContext::config_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::MockAbilityContext::localCallContainer_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::Node::data`: category=stable_owner, accesses=3 (reads=3, writes=0, initializations=0), locks=mutex_, candidate_findings=0
- `OHOS::TaskExecutor::pool_`: category=cross_function_unknown, accesses=17 (reads=14, writes=3, initializations=0), locks=mtx_, candidate_findings=10
- `ObserverBridge::observer_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=mutex_, candidate_findings=0
- `PredicatesProxy::predicates_`: category=stable_owner, accesses=2 (reads=2, writes=0, initializations=0), locks=none, candidate_findings=0
- `SecurityManager::kvdbCrypto_`: category=mutable_owner, accesses=5 (reads=4, writes=1, initializations=0), locks=cryptoMutex_, candidate_findings=0
- `SingleStoreImpl::observers_`: category=stable_owner, accesses=6 (reads=6, writes=0, initializations=0), locks=rwMutex_, candidate_findings=0
- `SingleStoreImpl::syncObserver_`: category=constructor_only, accesses=7 (reads=6, writes=0, initializations=1), locks=none, candidate_findings=0
- `StoreManager::switchObservers_`: category=stable_owner, accesses=2 (reads=2, writes=0, initializations=0), locks=none, candidate_findings=0
- `StoreResultSet::dbStore_`: category=cross_function_unknown, accesses=4 (reads=2, writes=1, initializations=1), locks=mutex_, candidate_findings=1
- `SwitchObserverBridge::switchObservers_`: category=stable_owner, accesses=4 (reads=4, writes=0, initializations=0), locks=switchMutex_, candidate_findings=0
- `SyncObserver::callbacks_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=mutex_, candidate_findings=0

### `security_access_token`

- `OHOS::ActiveStatusCallbackManager::eventHandler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=eventHandlerLock_, candidate_findings=1
- `OHOS::AppManagerAccessClient::appManagerDeathCallbackList_`: category=stable_owner, accesses=3 (reads=3, writes=0, initializations=0), locks=deathCallbackMutex_, candidate_findings=0
- `OHOS::AuthorizationResult::data_`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::CallbackRecord::scopePtr_`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::ClawTicketManager::appManagerDeathCallback_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::DisablePolicyCbkManager::eventHandler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=eventHandlerLock_, candidate_findings=1
- `OHOS::El5FilekeyManagerService::subscriber_`: category=mutable_owner, accesses=4 (reads=2, writes=2, initializations=0), locks=none, candidate_findings=4
- `OHOS::El5FilekeyManagerService::unloadHandler_`: category=cross_function_unknown, accesses=4 (reads=3, writes=1, initializations=0), locks=none, candidate_findings=4
- `OHOS::El5FilekeyManagerServiceAbility::service_`: category=cross_function_unknown, accesses=10 (reads=7, writes=2, initializations=1), locks=none, candidate_findings=10
- `OHOS::KernelAndDBWriteTransaction::addTask_`: category=cross_function_unknown, accesses=6 (reads=4, writes=2, initializations=0), locks=none, candidate_findings=6
- `OHOS::KernelAndDBWriteTransaction::removeTask_`: category=cross_function_unknown, accesses=6 (reads=4, writes=2, initializations=0), locks=none, candidate_findings=6
- `OHOS::KernelAndDBWriteTransaction::updateTask_`: category=cross_function_unknown, accesses=6 (reads=4, writes=2, initializations=0), locks=none, candidate_findings=6
- `OHOS::OpenOnSettingAsyncContextHandle::asyncContextPtr`: category=constructor_only, accesses=1 (reads=0, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::OpenOnSettingAsyncInstanceControl::instanceIdMap_`: category=stable_owner, accesses=7 (reads=7, writes=0, initializations=0), locks=instanceIdMutex_, candidate_findings=0
- `OHOS::OpenPermOnSettingUICallback::reqContext_`: category=constructor_only, accesses=23 (reads=22, writes=0, initializations=1), locks=g_lockFlag, candidate_findings=0
- `OHOS::PermActiveStatusChangeCallback::customizedCallback_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::PermDisablePolicyChangeCallback::customizedCallback_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::PermissionManager::abilityManagerLoader_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=abilityManagerMutex_, candidate_findings=2
- `OHOS::PermissionRecordManager::abilityManagerLoader_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=abilityManagerMutex_, candidate_findings=0
- `OHOS::PermissionRecordManager::appManagerDeathCallback_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=appManagerDeathMutex_, candidate_findings=0
- `OHOS::PermissionStateChangeCallback::customizedCallback_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::PrivacyManagerClient::activeCbkMap_`: category=stable_owner, accesses=11 (reads=11, writes=0, initializations=0), locks=activeCbkMutex_, candidate_findings=0
- `OHOS::PrivacyManagerClient::disableCbkMap_`: category=stable_owner, accesses=10 (reads=10, writes=0, initializations=0), locks=disableCbkMutex_, candidate_findings=0
- `OHOS::PrivacyManagerService::proxyDeathHandler_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=deathHandlerMutex_, candidate_findings=0
- `OHOS::RdbDlopenManager::eventHandler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=eventHandlerLock_, candidate_findings=1
- `OHOS::RdbDlopenManager::eventRunner_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::RemoteCommandExecutor::commands_`: category=constructor_only, accesses=9 (reads=8, writes=0, initializations=1), locks=mutex_, candidate_findings=0
- `OHOS::RemoteCommandExecutor::ptrChannel_`: category=cross_function_unknown, accesses=9 (reads=6, writes=2, initializations=1), locks=mutex_, candidate_findings=7
- `OHOS::RemoteCommandManager::executors_`: category=constructor_only, accesses=13 (reads=12, writes=0, initializations=1), locks=mutex_, candidate_findings=0
- `OHOS::RequestAsyncContextBase::handler_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::RequestAsyncContextBase::stageContext_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::RequestAsyncContextHandle::asyncContextPtr`: category=constructor_only, accesses=1 (reads=0, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::RequestAsyncInstanceControl::instanceIdMap_`: category=stable_owner, accesses=5 (reads=5, writes=0, initializations=0), locks=instanceIdMutex_, candidate_findings=0
- `OHOS::RequestGlobalSwitchAsyncContextHandle::asyncContextPtr`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::RequestGlobalSwitchAsyncInstanceControl::instanceIdMap_`: category=stable_owner, accesses=7 (reads=7, writes=0, initializations=0), locks=instanceIdMutex_, candidate_findings=0
- `OHOS::RequestInstanceControl::instanceIdMap_`: category=stable_owner, accesses=7 (reads=7, writes=0, initializations=0), locks=instanceIdMutex_, candidate_findings=0
- `OHOS::RequestOnSettingAsyncContextHandle::asyncContextPtr`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::RequestOnSettingAsyncInstanceControl::instanceIdMap_`: category=stable_owner, accesses=7 (reads=7, writes=0, initializations=0), locks=instanceIdMutex_, candidate_findings=0
- `OHOS::ShortGrantManager::appManagerDeathCallback_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=appManagerDeathMutex_, candidate_findings=0
- `OHOS::ShortGrantManager::eventHandler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=eventHandlerLock_, candidate_findings=1
- `OHOS::StateChangeCallback::customizedCallback_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::TempPermissionObserver::appManagerDeathCallback_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=appManagerDeathMutex_, candidate_findings=0
- `OHOS::TempPermissionObserver::eventHandler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=eventHandlerLock_, candidate_findings=1
- `OHOS::TokenSyncCallback::tokenSyncCallback_`: category=constructor_only, accesses=7 (reads=6, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::TokenSyncManagerService::recvHandler_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::TokenSyncManagerService::recvRunner_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::TokenSyncManagerService::sendHandler_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::TokenSyncManagerService::sendRunner_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::ToolTokenInfoManager::toolTokenInfoMap_`: category=stable_owner, accesses=14 (reads=14, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::UIExtensionCallback::controllerInstance_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3

### `update_updateservice`

- `OHOS::AccessManager::accessMap_`: category=stable_owner, accesses=6 (reads=6, writes=0, initializations=0), locks=mutex_, candidate_findings=0
- `OHOS::FirmwareDownloadExecutor::downloadThread_`: category=mutable_owner, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::FirmwareFlowManager::executeMode_`: category=cross_function_unknown, accesses=15 (reads=14, writes=1, initializations=0), locks=none, candidate_findings=15
- `OHOS::FirmwareFlowManager::executor_`: category=mutable_owner, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::FirmwareManager::preferencesUtil_`: category=stable_owner, accesses=7 (reads=7, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::FirmwareStatusCache::statusCache_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::IUpdater::sessionsMgr_`: category=stable_owner, accesses=2 (reads=2, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::ScheduleManager::accessManager_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::ScheduleManager::startupSchedule_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::StartupManager::scheduleManager_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::StatusCache::timeUtilsProxy_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::TimerManager::timer_`: category=cross_function_unknown, accesses=4 (reads=3, writes=1, initializations=0), locks=none, candidate_findings=4
- `OHOS::UpdateServiceImplFirmware::preferencesUtil_`: category=stable_owner, accesses=2 (reads=2, writes=0, initializations=0), locks=none, candidate_findings=0

### `window_window_manager`

- `DataHandler::eventHandler_`: category=cross_function_unknown, accesses=4 (reads=3, writes=1, initializations=0), locks=none, candidate_findings=4
- `DmRsSurfaceNode::surfaceNode_`: category=constructor_only, accesses=2 (reads=1, writes=0, initializations=1), locks=none, candidate_findings=0
- `FoldScreenController::screenPowerTaskScheduler_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `JsRootSceneSession::jsCbMap_`: category=stable_owner, accesses=6 (reads=6, writes=0, initializations=0), locks=jsCbMapMutex_, candidate_findings=0
- `JsRootSceneSession::taskScheduler_`: category=constructor_only, accesses=3 (reads=2, writes=0, initializations=1), locks=none, candidate_findings=0
- `JsSceneSession::jsCbMap_`: category=stable_owner, accesses=6 (reads=6, writes=0, initializations=0), locks=jsCbMapMutex_, candidate_findings=0
- `JsSceneSession::taskScheduler_`: category=constructor_only, accesses=104 (reads=103, writes=0, initializations=1), locks=none, candidate_findings=0
- `MoveDragBoundsApplier::leashWinShadowSurfaceNode_`: category=mutable_owner, accesses=6 (reads=5, writes=1, initializations=0), locks=none, candidate_findings=6
- `MoveDragBoundsApplier::shadowSurfaceNode_`: category=mutable_owner, accesses=5 (reads=4, writes=1, initializations=0), locks=none, candidate_findings=5
- `MultiInstanceManager::taskScheduler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::AniFbWindowListener::eventHandler_`: category=cross_function_unknown, accesses=7 (reads=6, writes=1, initializations=0), locks=none, candidate_findings=7
- `OHOS::AniFvWindowListener::eventHandler_`: category=cross_function_unknown, accesses=7 (reads=6, writes=1, initializations=0), locks=none, candidate_findings=7
- `OHOS::AniPiPListener::eventHandler_`: category=cross_function_unknown, accesses=13 (reads=12, writes=1, initializations=0), locks=none, candidate_findings=13
- `OHOS::AniPipController::mainHandler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `OHOS::AniTransitionController::eventHandler_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::CjWindowListener::eventHandler_`: category=write_only, accesses=1 (reads=0, writes=1, initializations=0), locks=none, candidate_findings=1
- `OHOS::DualDisplaySensorFoldStateManager::ffrtQueue_`: category=constructor_only, accesses=2 (reads=1, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::DualDisplaySensorFoldStateManager::screenPowerTaskScheduler_`: category=constructor_only, accesses=1 (reads=0, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::FoldScreenStateMachine::callbacks_`: category=stable_owner, accesses=9 (reads=9, writes=0, initializations=0), locks=mutex_, candidate_findings=0
- `OHOS::FvOption::storage_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::GtxInputEventSender::mCallbackInstance`: category=cross_function_unknown, accesses=4 (reads=2, writes=2, initializations=0), locks=none, candidate_findings=4
- `OHOS::JsExtensionWindow::extensionWindow_`: category=constructor_only, accesses=43 (reads=41, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::JsExtensionWindowRegisterManager::jsCbMap_`: category=stable_owner, accesses=23 (reads=23, writes=0, initializations=0), locks=mtx_, candidate_findings=0
- `OHOS::JsFbWindowListener::jsCallBack_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::JsFloatViewListener::jsCallBack_`: category=constructor_only, accesses=5 (reads=4, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::JsPiPWindowListener::jsCallBack_`: category=constructor_only, accesses=8 (reads=7, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::MoveDragController::vsyncCallback_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::PictureInPictureController::mainWindowXComponentController_`: category=cross_function_unknown, accesses=16 (reads=13, writes=3, initializations=0), locks=none, candidate_findings=16
- `OHOS::PictureInPictureControllerAni::mainWindowXComponentController_`: category=cross_function_unknown, accesses=16 (reads=13, writes=3, initializations=0), locks=none, candidate_findings=16
- `OHOS::PictureInPictureControllerBase::pipXComponentController_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::PipOption::customNodeController_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::PipOption::pipContentlistenerMap_`: category=stable_owner, accesses=4 (reads=4, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::PipOption::storage_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::PipOption::typeNode_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::PipOption::xComponentController_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::SnapshotController::handler_`: category=stable_owner, accesses=2 (reads=2, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::SnapshotController::performReport_`: category=stable_owner, accesses=2 (reads=2, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::StartAnimationSystemOptions::animationConfig`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::StartingWindowRdbManager::handler_`: category=constructor_only, accesses=4 (reads=3, writes=0, initializations=1), locks=none, candidate_findings=0
- `OHOS::StartingWindowRdbManager::rdbStore_`: category=mutable_owner, accesses=4 (reads=3, writes=1, initializations=0), locks=rdbMutex_, candidate_findings=0
- `OHOS::SuperFoldSensorManager::taskScheduler_`: category=cross_function_unknown, accesses=7 (reads=6, writes=1, initializations=0), locks=none, candidate_findings=7
- `OHOS::SurfaceCaptureFuture::hdrPixelMap_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::SurfaceCaptureFuture::pixelMap_`: category=stable_owner, accesses=1 (reads=1, writes=0, initializations=0), locks=none, candidate_findings=0
- `OHOS::WindowCommonEvent::eventHandler_`: category=constructor_only, accesses=5 (reads=3, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::WindowCommonEvent::subscriber_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::WindowCreateParams::animationParams`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::WindowCreateParams::animationSystemParams`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `OHOS::WindowNode::snapshot_`: category=cross_function_unknown, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `OHOS::WindowNode::surfaceNode_`: category=constructor_only, accesses=2 (reads=0, writes=0, initializations=2), locks=none, candidate_findings=0
- `PcFoldScreenController::onFoldScreenStatusChangeCallback_`: category=mutable_owner, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `PcFoldScreenController::onSystemKeyboardStatusChangeCallback_`: category=mutable_owner, accesses=2 (reads=1, writes=1, initializations=0), locks=none, candidate_findings=2
- `RssEventListener::callbackRef_`: category=constructor_only, accesses=2 (reads=1, writes=0, initializations=1), locks=none, candidate_findings=0
- `ScreenSessionPublish::oneHopDeviceDownSubscriber_`: category=cross_function_unknown, accesses=4 (reads=2, writes=2, initializations=0), locks=none, candidate_findings=4
- `ScreenSessionPublish::subscriber_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `ScreenSessionPublish::userSwitchedSubscriber_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `TaskScheduler::exportHandler_`: category=cross_function_unknown, accesses=6 (reads=5, writes=1, initializations=0), locks=none, candidate_findings=6
- `TaskScheduler::handler_`: category=constructor_only, accesses=10 (reads=9, writes=0, initializations=1), locks=none, candidate_findings=0
- `TaskSequenceProcess::taskScheduler_`: category=cross_function_unknown, accesses=3 (reads=2, writes=1, initializations=0), locks=none, candidate_findings=3
- `UIEffectParams::backgroundFilter_`: category=cross_function_unknown, accesses=6 (reads=4, writes=2, initializations=0), locks=none, candidate_findings=6
- `UIEffectParams::effect_`: category=cross_function_unknown, accesses=6 (reads=4, writes=2, initializations=0), locks=none, candidate_findings=6
- `WindowEventSubscribeProxy::eventReceiver_`: category=cross_function_unknown, accesses=5 (reads=3, writes=2, initializations=0), locks=mutex_, candidate_findings=0
- `WindowEventSubscribeProxy::windowEventReceiver_`: category=cross_function_unknown, accesses=4 (reads=2, writes=2, initializations=0), locks=mutex_, candidate_findings=0


## Top members

### `communication_dsoftbus`

- `core/connection/wifi_direct_cpp/entity/p2p_connect_state.cpp` `operation_`: 19 candidate(s), reads=15, writes=4, shape=mutable_owner
- `core/connection/wifi_direct_cpp/wifi_direct_executor.cpp` `processor_`: 16 candidate(s), reads=13, writes=2, shape=mutable_owner
- `core/connection/wifi_direct_cpp/entity/p2p_create_group_state.cpp` `operation_`: 13 candidate(s), reads=9, writes=4, shape=mutable_owner
- `core/connection/wifi_direct_cpp/entity/p2p_destroy_group_state.cpp` `operation_`: 13 candidate(s), reads=9, writes=4, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/adaptor/src/stream_adaptor.cpp` `streamManager_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `core/connection/wifi_direct_cpp/data/inner_link.cpp` `channel_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner
- `core/connection/wifi_direct_cpp/command/processor_selector_factory.cpp` `selector_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `core/connection/wifi_direct_cpp/wifi_direct_scheduler_factory.cpp` `scheduler_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp` `socketListener_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp` `streamListener_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h` `msgManager_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner
- `sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/vtp_instance.cpp` `instance_`: 2 candidate(s), reads=2, writes=0, shape=read_only

### `distributeddatamgr_kv_store`

- `frameworks/libs/distributeddb/syncer/src/device/syncer_proxy.cpp` `syncer_`: 65 candidate(s), reads=64, writes=0, shape=read_only
- `frameworks/libs/distributeddb/syncer/src/device/sync_engine.cpp` `subManager_`: 17 candidate(s), reads=16, writes=1, shape=mutable_owner
- `frameworks/libs/distributeddb/gaussdb_rd/src/interface/src/result_set.cpp` `context_`: 12 candidate(s), reads=11, writes=1, shape=mutable_owner
- `frameworks/innerkitsimpl/kvdb/src/task_executor.cpp` `pool_`: 10 candidate(s), reads=10, writes=0, shape=read_only
- `frameworks/libs/distributeddb/common/src/runtime_context_impl.cpp` `dataTranslate_`: 8 candidate(s), reads=8, writes=0, shape=read_only
- `frameworks/jskitsimpl/distributeddata/src/js_kv_store.cpp` `kvStore_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp` `kvStore_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `kvstoremock/external_inner_kit/ipc/mock_ipc.cpp` `rawData_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `frameworks/libs/distributeddb/syncer/src/device/sync_engine.cpp` `metadata_`: 4 candidate(s), reads=1, writes=2, shape=mutable_owner
- `frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp` `param_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `frameworks/libs/distributeddb/storage/src/sqlite/relational/sqlite_single_ver_relational_storage_executor.cpp` `assetLoader_`: 3 candidate(s), reads=2, writes=0, shape=read_only
- `frameworks/libs/distributeddb/storage/src/sqlite/relational/sqlite_single_ver_relational_storage_extend_executor.cpp` `assetLoader_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner

### `security_access_token`

- `services/el5filekeymanager/src/el5_filekey_manager_service_ability.cpp` `service_`: 10 candidate(s), reads=7, writes=2, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `addTask_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `removeTask_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/transaction/kernel_and_db_transaction.cpp` `updateTask_`: 6 candidate(s), reads=4, writes=2, shape=mutable_owner
- `services/tokensyncmanager/src/remote/remote_command_executor.cpp` `ptrChannel_`: 5 candidate(s), reads=4, writes=0, shape=read_only
- `services/el5filekeymanager/src/el5_filekey_manager_service.cpp` `subscriber_`: 4 candidate(s), reads=2, writes=2, shape=mutable_owner
- `services/el5filekeymanager/src/el5_filekey_manager_service.cpp` `unloadHandler_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner
- `frameworks/ets/ani/accesstoken/src/ani_request_base.cpp` `controllerInstance_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/clawtoken/claw_ticket_manager.cpp` `appManagerDeathCallback_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/accesstokenmanager/main/cpp/src/database/rdb_dlopen_manager.cpp` `eventRunner_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/tokensyncmanager/src/service/token_sync_manager_service.cpp` `recvRunner_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/tokensyncmanager/src/service/token_sync_manager_service.cpp` `sendRunner_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner

### `update_updateservice`

- `services/firmware/upgrade/flow/src/firmware_flow_manager.cpp` `executeMode_`: 15 candidate(s), reads=14, writes=1, shape=mutable_owner
- `services/core/ability/alarm/src/timer_manager.cpp` `timer_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner
- `services/firmware/upgrade/flow/src/firmware_flow_manager.cpp` `executor_`: 3 candidate(s), reads=2, writes=1, shape=mutable_owner
- `services/firmware/upgrade/executor/src/firmware_download_executor.cpp` `downloadThread_`: 2 candidate(s), reads=1, writes=1, shape=mutable_owner

### `window_window_manager`

- `wm/src/picture_in_picture_controller.cpp` `mainWindowXComponentController_`: 14 candidate(s), reads=12, writes=2, shape=mutable_owner
- `wm/src/picture_in_picture_controller_ani.cpp` `mainWindowXComponentController_`: 14 candidate(s), reads=12, writes=2, shape=mutable_owner
- `interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_listener.cpp` `eventHandler_`: 13 candidate(s), reads=12, writes=1, shape=mutable_owner
- `interfaces/kits/ani/float_view/float_view_ani/src/ani_fv_window_listener.cpp` `eventHandler_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_listener.cpp` `eventHandler_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `window_scene/screen_session_manager/src/fold_screen_controller/super_fold_sensor_manager.cpp` `taskScheduler_`: 7 candidate(s), reads=6, writes=1, shape=mutable_owner
- `window_scene/common/src/task_scheduler.cpp` `exportHandler_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `window_scene/session/host/src/move_drag_bounds_applier.cpp` `leashWinShadowSurfaceNode_`: 6 candidate(s), reads=5, writes=1, shape=mutable_owner
- `utils/src/ui_effect_controller_common.cpp` `backgroundFilter_`: 5 candidate(s), reads=3, writes=2, shape=mutable_owner
- `utils/src/ui_effect_controller_common.cpp` `effect_`: 5 candidate(s), reads=3, writes=2, shape=mutable_owner
- `window_scene/session/host/src/move_drag_bounds_applier.cpp` `shadowSurfaceNode_`: 5 candidate(s), reads=4, writes=1, shape=mutable_owner
- `window_scene/common/src/extension_data_handler.cpp` `eventHandler_`: 4 candidate(s), reads=3, writes=1, shape=mutable_owner

## Boundary

- Source is read from local pinned Git objects; no fetch or checkout.
- Candidates remain `candidate/unassessed`; no product entry or CIA claim.
- This triage does not rewrite the historical 229/208 records.
