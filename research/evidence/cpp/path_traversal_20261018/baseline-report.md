# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/applications_contacts_data`
- Pinned commit: `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`
- Git tree: `2054824c04bb403eeea128a9262edfb3001efa4f`
- Snapshot SHA-256: `375f9962e275d88a2ea3e1915ddea3a48f8f06008e96509b7e432324f4ba3afc`
- Source files indexed: 360
- Parsing coverage: `{"complete": 199, "not_run": 142, "partial": 19}`
- Detector runs: 3
- Total unverified diagnostics: 29
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.lifetime` | blocked | 199 | 185 | 14 | 19 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | blocked | 199 | 198 | 1 | 19 | 25 | partial |
| `ohscanner.interface.ipc` | completed | 218 | 199 | 19 | 0 | 4 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:60c7f92e7f12b458` | `ability/common/utils/include/async_task.h:338` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9ba1cede992ac4c5` | `ability/common/utils/include/async_task.h:342` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:f2de9d019744f89a` | `ability/common/utils/include/async_task.h:344` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:fe164d14df511c9d` | `ability/common/utils/include/async_task.h:344` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9586626ad3a4f6b9` | `ability/common/utils/include/async_task.h:404` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2ad55820c0282ada` | `ability/common/utils/include/async_task.h:408` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:586033f6cafef2ca` | `ability/common/utils/include/async_task.h:412` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:380e5c43ef22b3c9` | `ability/common/utils/include/async_task.h:415` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:eee16613f75a99e0` | `ability/common/utils/include/async_task.h:415` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:75e61dfac95483bf` | `ability/common/utils/include/async_task.h:438` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:301dc17ea8a14f72` | `ability/common/utils/include/async_task.h:443` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:70f5c8f601c554d5` | `ability/common/utils/include/async_task.h:446` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:74a4a86196059b36` | `ability/common/utils/include/async_task.h:446` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:d47bb1ef0d95f6df` | `test/unittest/include/calllogability_test.h:52` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:95a130c5cac570ce` | `test/unittest/include/calllogability_test.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:bf462ae31a04a33d` | `test/unittest/include/calllogability_test.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:89669598ec7d5703` | `test/unittest/include/calllogability_test.h:104` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:608f508d34c40ed5` | `test/unittest/include/contactability_test.h:52` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2dd1910ba26f59c9` | `test/unittest/include/contactability_test.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:cfe302bc02044a17` | `test/unittest/include/contactability_test.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:37a2526c651d3eeb` | `test/unittest/include/contactability_test.h:105` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a3472e2e8ac46d62` | `test/unittest/include/voicemailability_test.h:52` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a16763ee12d7c8e7` | `test/unittest/include/voicemailability_test.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:f9c67beb9138d130` | `test/unittest/include/voicemailability_test.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:acc1dd728e26728c` | `test/unittest/include/voicemailability_test.h:104` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:df83fa56c82497e4` | `ability/common/utils/src/contacts_common_event.cpp:45` | `ipc.auth.missing` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:38e3899d42ce56b8` | `ability/common/utils/src/contacts_common_event.cpp:67` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:23587f4c026cbc23` | `dataBusiness/poster/src/poster_call_stub.cpp:44` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:ed1dffc9c2e48502` | `dataBusiness/poster/src/poster_call_stub.cpp:46` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 142
- `contacts/src/contact.js`
- `dataBusiness/calllog/src/types/libcontactsdataability/index.d.ts`
- `entry/hvigorfile.ts`
- `entry/src/main/ets/Application/ContactsDataAbilityStage.ets`
- `entry/src/main/ets/DataShareExtAbility/DataShareExtAbility.ts`
- `entry/src/main/ets/ServiceAbility/HandleContactEventsServiceAbility.ets`
- `entry/src/main/ets/ServiceAbility/ServiceAbility.ets`
- `entry/src/main/ets/WorkScheduler/Common.ets`
- `entry/src/main/ets/aggregation/AggregatorRawContact.ets`
- `entry/src/main/ets/aggregation/ContactAggregator.ets`
- `entry/src/main/ets/common/DbConstants.ets`
- `entry/src/main/ets/common/SqlConstants.ets`
- `entry/src/main/ets/common/contract/Account.ets`
- `entry/src/main/ets/common/contract/BaseColumns.ets`
- `entry/src/main/ets/common/contract/BlockListDoubleConstant.ets`
- `entry/src/main/ets/common/contract/BlockListSingleConstant.ets`
- `entry/src/main/ets/common/contract/CallLogArdConstant.ets`
- `entry/src/main/ets/common/contract/CallLogDoubleConstant.ets`
- `entry/src/main/ets/common/contract/CallLogSingleConstant.ets`
- `entry/src/main/ets/common/contract/CloneDbColumns.ets`
- `entry/src/main/ets/common/contract/ContactBigPhotoConstant.ets`
- `entry/src/main/ets/common/contract/Contacts.ets`
- `entry/src/main/ets/common/contract/ContactsColumns.ets`
- `entry/src/main/ets/common/contract/Data.ets`
- `entry/src/main/ets/common/contract/DataColumns.ets`
- `entry/src/main/ets/common/contract/DeleteRawContact.ets`
- `entry/src/main/ets/common/contract/DoubleAccountBean.ets`
- `entry/src/main/ets/common/contract/DoubleContactBean.ets`
- `entry/src/main/ets/common/contract/Group.ets`
- `entry/src/main/ets/common/contract/GroupColumns.ets`
- `entry/src/main/ets/common/contract/Mimetype.ets`
- `entry/src/main/ets/common/contract/RawContacts.ets`
- `entry/src/main/ets/common/contract/RawContactsColumns.ets`
- `entry/src/main/ets/common/contract/SearchContact.ets`
- `entry/src/main/ets/common/contract/SearchContactColumns.ets`
- `entry/src/main/ets/common/data/ContactInfo.ets`
- `entry/src/main/ets/common/data/Contacts.ets`
- `entry/src/main/ets/common/data/Data.ets`
- `entry/src/main/ets/common/data/DataBaseMode.ets`
- `entry/src/main/ets/common/data/DataColumns.ets`
- `entry/src/main/ets/common/data/FullContactData.ets`
- `entry/src/main/ets/common/data/GroupFileInfo.ets`
- `entry/src/main/ets/common/data/MasterContact.ets`
- `entry/src/main/ets/common/data/MergeRawContact.ets`
- `entry/src/main/ets/common/data/RawContactsColumns.ets`
- `entry/src/main/ets/common/data/SettingsColumns.ets`
- `entry/src/main/ets/common/data/SimpleContact.ets`
- `entry/src/main/ets/common/data/SimpleContactData.ets`
- `entry/src/main/ets/common/data/SimpleRawContact.ets`
- `entry/src/main/ets/common/data/vo/DataItemType.ets`
- `entry/src/main/ets/common/data/vo/MeeTimeAbilityInfoModel.ets`
- `entry/src/main/ets/common/data/vo/RawContact.ets`
- `entry/src/main/ets/common/helperBase/BaseDbHelper.ets`
- `entry/src/main/ets/common/helperBase/BaseRdbHelperForCloudSync.ets`
- `entry/src/main/ets/common/helperBase/BaseSingleRdbInsertHelper.ets`
- `entry/src/main/ets/common/helperUtils/CallLogRdbHelperForCloudSync.ets`
- `entry/src/main/ets/common/helperUtils/ContactsRdbHelperForCloudSync.ets`
- `entry/src/main/ets/common/helperUtils/ContactsSingleInsertHelper.ets`
- `entry/src/main/ets/common/model/MigrateProgressInfo.ets`
- `entry/src/main/ets/common/model/bean/ContactEventDataItem.ets`
- `entry/src/main/ets/common/model/bean/ContactItem.ets`
- `entry/src/main/ets/common/model/bean/DataItem.ets`
- `entry/src/main/ets/common/model/bean/DataItemFactory.ets`
- `entry/src/main/ets/common/model/bean/EmailDataItem.ets`
- `entry/src/main/ets/common/model/bean/GroupDataItem.ets`
- `entry/src/main/ets/common/model/bean/GroupItem.ets`
- `entry/src/main/ets/common/model/bean/ImDataItem.ets`
- `entry/src/main/ets/common/model/bean/NameDataItem.ets`
- `entry/src/main/ets/common/model/bean/OrganizationDataItem.ets`
- `entry/src/main/ets/common/model/bean/PhoneDataItem.ets`
- `entry/src/main/ets/common/model/bean/PhotoDataItem.ets`
- `entry/src/main/ets/common/model/bean/PostalAddressDataItem.ets`
- `entry/src/main/ets/common/model/bean/RawContactItem.ets`
- `entry/src/main/ets/common/model/bean/RelationDataItem.ets`
- `entry/src/main/ets/common/utils/ArrayUtil.ets`
- `entry/src/main/ets/common/utils/ChineseCharacterUtils.ets`
- `entry/src/main/ets/common/utils/ContactStatisticsCount.ets`
- `entry/src/main/ets/common/utils/DatabaseUtils.ets`
- `entry/src/main/ets/common/utils/GroupIdUtil.ets`
- `entry/src/main/ets/common/utils/HashUtils.ets`
- `entry/src/main/ets/common/utils/HmsAuthentication.ets`
- `entry/src/main/ets/common/utils/LogUtils.ets`
- `entry/src/main/ets/common/utils/LogUtils.ts`
- `entry/src/main/ets/common/utils/NumberFormatUtil.ets`
- `entry/src/main/ets/common/utils/NumberLocationUtil.ets`
- `entry/src/main/ets/common/utils/ObjectUtil.ts`
- `entry/src/main/ets/common/utils/PreferenceMigrateDataToClkvUtil.ets`
- `entry/src/main/ets/common/utils/PreferenceUtil.ets`
- `entry/src/main/ets/common/utils/PreferenceUtilAbstract.ets`
- `entry/src/main/ets/common/utils/PreferenceUtilClkv.ets`
- `entry/src/main/ets/common/utils/PreferenceUtilXml.ets`
- `entry/src/main/ets/common/utils/StringUtil.ets`
- `entry/src/main/ets/common/utils/SystemModeController.ets`
- `entry/src/main/ets/common/utils/TaskUtil.ets`
- `entry/src/main/ets/components/Log.ets`
- `entry/src/main/ets/components/PlatformInterface/Base64Interface.ets`
- `entry/src/main/ets/components/PlatformInterface/Contact.ets`
- `entry/src/main/ets/components/PlatformInterface/HOSBase64.ets`
- `entry/src/main/ets/components/PlatformInterface/HOSLineReader.ets`
- `entry/src/main/ets/components/PlatformInterface/LineReaderInterface.ets`
- `entry/src/main/ets/components/PlatformInterface/PlatformFactory.ets`
- `entry/src/main/ets/components/utils/ContainerUtils.ets`
- `entry/src/main/ets/components/utils/HOSStringBuilder.ets`
- `entry/src/main/ets/components/utils/LineReader.ets`
- `entry/src/main/ets/components/utils/PhoneNumberUtils.ets`
- `entry/src/main/ets/components/utils/TextUtils.ets`
- `entry/src/main/ets/components/utils/Utf.ets`
- `entry/src/main/ets/pages/Index.ets`
- `entry/src/main/ets/pages/PermissionDialog.ets`
- `entry/src/main/ets/serivce/BirthdayManager.ets`
- `entry/src/main/ets/serivce/BoardHiSysEventUtil.ets`
- `entry/src/main/ets/serivce/ContactsDataService.ets`
- `entry/src/main/ets/serivce/DirtyDataClearServiceUpdate.ets`
- `entry/src/main/ets/serivce/HandleUniqueKeyService.ets`
- `entry/src/main/ets/serivce/RepeatContactHandleService.ets`
- `entry/src/main/ets/uiExtensionAbility/PermissionExtAbility.ets`
- `entry/src/ohosTest/ets/application/TestApplication.ts`
- `entry/src/ohosTest/ets/application/TestApplication2.ts`
- `entry/src/ohosTest/ets/test/Ability.test.ets`
- `entry/src/ohosTest/ets/test/CloneUtil.test.ets`
- `entry/src/ohosTest/ets/test/List.test.ets`
- `entry/src/ohosTest/ets/test/PreferenceUtil.test.ets`
- `entry/src/ohosTest/ets/test/SystemModeController.test.ets`
- `entry/src/ohosTest/ets/testability/TestAbility.ets`
- `entry/src/ohosTest/ets/testability/pages/Index.ets`
- `entry/src/ohosTest/ets/testrunner/OpenHarmonyTestRunner.ets`
- `hvigor/@ohos.data.preferences.d.ts`
- `hvigor/@ohos.data.relationalStore.d.ts`
- `hvigorfile.ts`
- `jstest/Calllog_test.js`
- `jstest/ContactCard_test.js`
- `jstest/ContactMerge_test.js`
- `jstest/Contacts_test.js`
- `jstest/Groups_test.js`
- `jstest/List.test.js`
- `jstest/ObjectCallback.js`
- `jstest/ObjectInterface_test.js`
- `jstest/Performance_test.js`
- `jstest/Stability_test.js`
- `jstest/Voicemail_test.js`
- `jstest/common.js`
- `jstest/recovery_test.js`
- `ohscanner.cpp.lifetime`: partial, 185/218 applicable files examined; unexamined=33
- `ohscanner.cpp.shared_ptr_race`: partial, 198/218 applicable files examined; unexamined=20
- `ohscanner.interface.ipc`: partial, 199/218 applicable files examined; unexamined=19

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.cpp.lifetime`: Detector Contract v1 remains unfrozen; this is a proposed implementation against the current M0 interface.
- `ohscanner.cpp.lifetime`: Dominating CFG paths, exception/early-return behavior, destructor timing, escaping aliases, and cross-function transfers are not modeled.
- `ohscanner.cpp.lifetime`: Empty findings are not proof of safety and are never benchmark misses.
- `ohscanner.cpp.lifetime`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.lifetime`: Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.
- `ohscanner.cpp.lifetime`: Partial/failed/not_run parse coverage remains unknown and is never a benchmark miss.
- `ohscanner.cpp.lifetime`: Sync scope classification is descriptive; a lock does not preserve destroyed-object lifetime.
- `ohscanner.cpp.lifetime`: ability/account/src/account_sync.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: ability/account/src/account_sync.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: ability/datadisasterrecovery/src/database_disaster_recovery.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: ability/datadisasterrecovery/src/database_disaster_recovery.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: contacts/src/contacts_napi_utils.cpp: Member-access owner.get() storage is outside local declaration binding and may escape the modeled scope; those observations remain unknown.
- `ohscanner.cpp.lifetime`: contacts/src/contacts_napi_utils.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/calllog/src/calllog_database.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/calllog/src/calllog_database.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/calllog/src/calllog_manager.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/calllog/src/calllog_manager.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/auto_sync_detail_progress_observer.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/auto_sync_detail_progress_observer.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/blocklist_database.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/blocklist_database.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/cloud_contacts_observer.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/cloud_contacts_observer.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contact_connect_ability.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contact_connect_ability.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contacts_account.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contacts_account.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contacts_datashare_stub_impl.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contacts_manager.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/contacts_manager.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/profile_database.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/contacts/src/profile_database.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: dataBusiness/voicemail/src/voicemail_database.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: dataBusiness/voicemail/src/voicemail_database.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 19 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: ability/account/include/account_change_event.h: ability/account/include/account_change_event.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/account/include/account_data_collection.h: ability/account/include/account_data_collection.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/account/include/account_manager.h: ability/account/include/account_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/account/src/account_data_collection.cpp: ability/account/src/account_data_collection.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/account/src/account_sync.cpp: not_applicable: global shared_ptr declaration 'g_contactsAccount' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: ability/common/include/calllog_common.h: ability/common/include/calllog_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/include/common.h: ability/common/include/common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/include/contacts_columns.h: ability/common/include/contacts_columns.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/include/contacts_common.h: ability/common/include/contacts_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/include/hilog_wrapper.h: ability/common/include/hilog_wrapper.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/async_task.h: pairwise analysis of 'ability/common/utils/include/async_task.h::OHOS::AsyncDataShareProxyTask::dataShareHelper' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/async_task.h: pairwise analysis of 'ability/common/utils/include/async_task.h::OHOS::AsyncMeetimeAvatarAddTask::rdbStore' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/async_task.h: pairwise analysis of 'ability/common/utils/include/async_task.h::OHOS::AsyncTask::store' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/board_report_util.h: ability/common/utils/include/board_report_util.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/contacts_path.h: ability/common/utils/include/contacts_path.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/contacts_string_utils.h: ability/common/utils/include/contacts_string_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/delay_async_task.h: modeled non-atomic accesses to 'ability/common/utils/include/delay_async_task.h::OHOS::DelayAsyncTask::taskMap' are read-only and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/delay_async_task.h: modeled non-atomic accesses to 'ability/common/utils/include/delay_async_task.h::OHOS::DelayAsyncTask::taskQueue' are read-only and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/file_utils.h: ability/common/utils/include/file_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/hi_audit.h: ability/common/utils/include/hi_audit.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/phone_number_utils.h: ability/common/utils/include/phone_number_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/pixel_map_util.h: ability/common/utils/include/pixel_map_util.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/predicates_convert.h: ability/common/utils/include/predicates_convert.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/sql_analyzer.h: ability/common/utils/include/sql_analyzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/uri_utils.h: ability/common/utils/include/uri_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/include/zip_util.h: ability/common/utils/include/zip_util.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/board_report_util.cpp: ability/common/utils/src/board_report_util.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/contacts_path.cpp: ability/common/utils/src/contacts_path.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/contacts_string_utils.cpp: ability/common/utils/src/contacts_string_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/file_utils.cpp: ability/common/utils/src/file_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/hi_audit.cpp: ability/common/utils/src/hi_audit.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/phone_number_utils.cpp: ability/common/utils/src/phone_number_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/pixel_map_util.cpp: ability/common/utils/src/pixel_map_util.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/predicates_convert.cpp: ability/common/utils/src/predicates_convert.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/sql_analyzer.cpp: ability/common/utils/src/sql_analyzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/uri_utils.cpp: ability/common/utils/src/uri_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/common/utils/src/zip_util.cpp: ability/common/utils/src/zip_util.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/merge/include/candidate.h: ability/merge/include/candidate.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/merge/src/candidate.cpp: ability/merge/src/candidate.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/sinicization/include/character_transliterate.h: ability/sinicization/include/character_transliterate.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/sinicization/include/construction_name.h: ability/sinicization/include/construction_name.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/sinicization/src/character_transliterate.cpp: ability/sinicization/src/character_transliterate.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: ability/sinicization/src/construction_name.cpp: ability/sinicization/src/construction_name.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/contacts_build.h: contacts/include/contacts_build.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/contacts_napi_common.h: modeled accesses to 'contacts/include/contacts_napi_common.h::OHOS::ExecuteHelper::resultSet' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/contacts_sync_api.h: contacts/include/contacts_sync_api.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/contacts_sync_operations.h: contacts/include/contacts_sync_operations.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/contacts_telephony_permission.h: contacts/include/contacts_telephony_permission.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/hilog_wrapper_api.h: contacts/include/hilog_wrapper_api.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/kit_bundle_mgr_helper.h: contacts/include/kit_bundle_mgr_helper.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/include/sync_json_helper.h: contacts/include/sync_json_helper.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/src/contacts_build.cpp: contacts/src/contacts_build.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/src/contacts_telephony_permission.cpp: contacts/src/contacts_telephony_permission.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/src/kit_bundle_mgr_helper.cpp: contacts/src/kit_bundle_mgr_helper.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/src/native_module.cpp: contacts/src/native_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contacts/src/sync_json_helper.cpp: contacts/src/sync_json_helper.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/include/contacts.h: contactsCJ/include/contacts.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/include/contacts_permission.h: contactsCJ/include/contacts_permission.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/include/contacts_picker_ffi.h: contactsCJ/include/contacts_picker_ffi.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/include/hilog_wrapper_api.h: contactsCJ/include/hilog_wrapper_api.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_ffi.cpp: contactsCJ/src/contacts_ffi.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_permission.cpp: contactsCJ/src/contacts_permission.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 137 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 142 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 143 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 147 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 154 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 159 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 165 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 178 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 180 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 184 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 187 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 188 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 191 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 198 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 203 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 204 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 209 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 216 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 217 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 218 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 240 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 241 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 250 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 251 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 260 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 261 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 331 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 332 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 381 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 399 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 400 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 430 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 431 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 433 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 434 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 440 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 441 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 442 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 473 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: contactsCJ/src/contacts_picker.cpp: shared_ptr member 'pickerCallBack' occurrence at line 478 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: modeled non-atomic accesses to 'contactsCJ/src/contacts_picker.cpp::OHOS::ModalUICallbackForPicker::pickerContext_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: contactsCJ/src/contacts_picker.cpp: partial; no safety verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/calllog/include/calllog_backup_napi.h: dataBusiness/calllog/include/calllog_backup_napi.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/calllog/include/native_module_ohos_calllog_backup.h: dataBusiness/calllog/include/native_module_ohos_calllog_backup.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/calllog/src/native_module_ohos_calllog_backup.cpp: dataBusiness/calllog/src/native_module_ohos_calllog_backup.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/contacts/include/blocklist_database.h: not_applicable: global shared_ptr declaration 'contactsDataBase_' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/contacts/include/common_tool_type.h: dataBusiness/contacts/include/common_tool_type.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/contacts/src/contacts_database.cpp: not_applicable: global shared_ptr declaration 'SystemSoundManager_' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/contacts/src/ptivacy_contacts_manager.cpp: not_applicable: global shared_ptr declaration 'instance_' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/poster/include/poster_call_adapter.h: dataBusiness/poster/include/poster_call_adapter.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/poster/include/poster_call_stub.h: dataBusiness/poster/include/poster_call_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/poster/src/poster_call_adapter.cpp: dataBusiness/poster/src/poster_call_adapter.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/spam_call/include/spam_call_adapter.h: dataBusiness/spam_call/include/spam_call_adapter.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/spam_call/include/spam_call_stub.h: dataBusiness/spam_call/include/spam_call_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/spam_call/src/spam_call_adapter.cpp: dataBusiness/spam_call/src/spam_call_adapter.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dataBusiness/spam_call/src/spam_call_stub.cpp: dataBusiness/spam_call/src/spam_call_stub.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/calllog_fuzzer/calllog_ability_fuzz_test.cpp: not_applicable: global shared_ptr declaration 'gRdb' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/calllog_fuzzer/calllog_ability_fuzz_test.h: test/fuzztest/calllog_fuzzer/calllog_ability_fuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/contactsdata_fuzzer/contactfuzz_test.h: test/fuzztest/contactsdata_fuzzer/contactfuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/contactsother_fuzzer/other_fuzz_test.cpp: not_applicable: global shared_ptr declaration 'gRdb' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/contactsother_fuzzer/other_fuzz_test.h: test/fuzztest/contactsother_fuzzer/other_fuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/contactsutils_fuzzer/utils_fuzz_test.cpp: not_applicable: global shared_ptr declaration 'gRdb' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/contactsutils_fuzzer/utils_fuzz_test.h: test/fuzztest/contactsutils_fuzzer/utils_fuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/database_fuzzer/contacts_database_fuzz_test.cpp: not_applicable: global shared_ptr declaration 'gRdb' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/database_fuzzer/contacts_database_fuzz_test.h: test/fuzztest/database_fuzzer/contacts_database_fuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/transliterate_fuzzer/character_transliteratefuzz_test.cpp: test/fuzztest/transliterate_fuzzer/character_transliteratefuzz_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/transliterate_fuzzer/character_transliteratefuzz_test.h: test/fuzztest/transliterate_fuzzer/character_transliteratefuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/voicemail_fuzzer/voicemailfuzz_test.h: test/fuzztest/voicemail_fuzzer/voicemailfuzz_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/fuzztest/voicemail_fuzzer/voicemailsafuzz_test.cpp: test/fuzztest/voicemail_fuzzer/voicemailsafuzz_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/calllogability_test.h: pairwise analysis of 'test/unittest/include/calllogability_test.h::Contacts::CallLogAsync::resultSet' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/contactability_test.h: pairwise analysis of 'test/unittest/include/contactability_test.h::Contacts::ContactAsync::resultSet' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/performance_test.h: test/unittest/include/performance_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/random_number_utils.h: test/unittest/include/random_number_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/recovery_test.h: test/unittest/include/recovery_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/stability_test.h: test/unittest/include/stability_test.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/test_common.h: test/unittest/include/test_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/include/voicemailability_test.h: pairwise analysis of 'test/unittest/include/voicemailability_test.h::Contacts::VoicemailAsync::resultSet' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: test/unittest/src/random_number_utils.cpp: test/unittest/src/random_number_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 19 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.interface.ipc`: Model=oh-ipc-2026.10-v12; first-party bounded structured syntax interpretation, no external scanner execution.
- `ohscanner.interface.ipc`: Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.
- `ohscanner.interface.ipc`: FD backing rule skipped: MessageParcelWarp::ReadRawData body is absent or ambiguous.
- `ohscanner.interface.ipc`: No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is never an #include resolution, and what the expander refused is counted in the macro-expansion limitation rather than assumed away.
- `ohscanner.interface.ipc`: Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.
- `ohscanner.interface.ipc`: Interface-descriptor identity is read from the class's own base clause: a comparison is counted as this transaction's guard only when the source names the interface the class implements. A comparison against another interface, or one whose identity the analysed sources do not state, is reported with that reason instead of counting as a guard or as a proven mismatch.
- `ohscanner.interface.ipc`: Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.
- `ohscanner.interface.ipc`: Entry roots come from the name allowlist plus source-derived dispatch bindings (function-pointer tables, switch/if code dispatch, and source-declared virtual overrides). Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.
- `ohscanner.interface.ipc`: Entry-coverage measurements are published in the interface research report, not in this result.
- `ohscanner.interface.ipc`: Cross-service boundary coverage: 0 call(s) on a handle built by iface_cast<> in the scanned sources, 0 carrying the original caller's identity (SetCallingIdentity with a calling-token value active), 0 executing as the service. Each boundary is recorded with the identity that crossed it; no candidate is emitted from the boundary itself, and a downstream service's own guards are not read from this corpus.
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 2 dispatcher(s) (2 in stub classes, 0 with a recognizable guard before dispatch), 1 binding(s) by grade {'virtual_override': 1}, transactions {'dynamic': 1}, unresolved dispatch {}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
- `ohscanner.interface.ipc`: Loops are conservatively explored zero/one iterations; no induction or termination proof.
- `ohscanner.interface.ipc`: Macro expansion: 130 invocation(s) expanded in 53 file(s), 41 of them carrying control flow; 9 file(s) left unexpanded (conditional_definition_requires_build_profile=2390,raw_string_tokenization_not_supported=2,source_local_undef_not_supported=7,variadic_stringify_or_token_paste=4). The catalogue is the scan's own sources, never #include; where a macro was expanded, quoted conditions come from the expanded form while a finding's line is mapped back to the original file.
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in contactsCJ/include/contacts_ffi.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in dataBusiness/poster/include/i_poster_call.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in dataBusiness/poster/include/poster_call_callback.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in dataBusiness/poster/src/poster_call_stub.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in dataBusiness/spam_call/include/i_spam_call.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in dataBusiness/spam_call/include/spam_call_callback.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/calllogability_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/calllogfuzzyquery_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/contactability_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/contactgroup_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/contactpinyin_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/contactprofile_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/contactquery_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/mergecontact_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/performance_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/recovery_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/stability_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in test/unittest/src/voicemailability_test.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/account/include/account_change_event.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/account/include/account_data_collection.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/account/include/account_sync.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/async_task.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/delay_async_task.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/hi_audit.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/phone_number_utils.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/sql_analyzer.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/telephony_permission.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/common/utils/include/zip_util.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/datadisasterrecovery/include/database_disaster_recovery.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/merge/include/candidate_status.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/merge/include/match_candidate.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/merge/include/merger_contacts.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: ability/sinicization/include/character_transliterate.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contacts/include/contacts_build.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contacts/include/contacts_napi_utils.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contacts/include/result_convert.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contacts/src/contacts_api.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contacts/src/contacts_napi_utils.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contacts/src/result_convert.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: contactsCJ/src/contacts_picker.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/calllog/include/calllog_ability.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/calllog/include/calllog_backup_napi.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/calllog/include/calllog_database.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/calllog/include/calllog_manager.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/calllog/include/calllogcheck_ability.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/calllog/src/calllog_backup_napi.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/auto_sync_detail_progress_observer.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/blocklist_database.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/cloud_contacts_observer.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contact_connect_ability.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts_account.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts_data_ability.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts_database.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts_datashare_stub_impl.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts_manager.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/contacts_update_helper.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/number_identity_helper.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/privacy_contacts_manager.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/contacts/include/profile_database.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/poster/include/poster_call_adapter.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/poster/include/poster_call_connection.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/poster/include/poster_call_proxy.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/poster/include/poster_callback_stub.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/spam_call/include/callback_stub_helper.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/spam_call/include/spam_call_adapter.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/spam_call/include/spam_call_connection.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/spam_call/include/spam_call_proxy.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/spam_call/include/spam_call_stub.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/voicemail/include/voicemail_ability.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: dataBusiness/voicemail/include/voicemail_database.h
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: ContactsCommonEvent::SendPosterEvent
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `140637c231c8c6fa18f29b927fa6adae30ccd07329044293728f51d5eaccc418`
- Language matching plans attempts; actual coverage remains in the results above.
