int ContactsDataAbility::batchInsertHandleOneByOne(const Uri &uri, std::string isSyncFromCloud,
    int code, std::vector<DataShare::DataShareValuesBucket> &valuesHandle)
{
    unsigned int size = valuesHandle.size();
    int ret = contactDataBase_->BeginTransaction();
    if (!IsBeginTransactionOK(ret)) {
        return Contacts::RDB_EXECUTE_FAIL;
    }
// LCOV_EXCL_START
    bool isContainEvent = false;
    int rawContactId = -1;
    for (unsigned int i = 0; i < size; i++) {
        DataShare::DataShareValuesBucket rawContactValues = valuesHandle[i];
        int result = ProcessSingleInsert(rawContactValues, isContainEvent, rawContactId, code, isSyncFromCloud);
        if (result != Contacts::OPERATION_OK) {
            return result;
        }
    }
    int markRet = contactDataBase_->Commit();
    if (!IsCommitOK(markRet)) {
        HILOG_ERROR("batchInsertHandleOneByOne IsCommitOK error!");
        return Contacts::RDB_EXECUTE_FAIL;
    }

    //valuesHandle 这个里面是否有生日，如果有更新到日历数据库，如果没有，则不处理
    if (isContainEvent && rawContactId != -1) {
        contactsConnectAbility_ = OHOS::Contacts::ContactConnectAbility::GetInstance();
        contactsConnectAbility_->
          ConnectEventsHandleAbility(Contacts::CONTACTS_BIRTHDAY_INSERT, std::to_string(rawContactId), "");
    }

    // 成功
    DataBaseNotifyChange(Contacts::CONTACT_INSERT, uri, isSyncFromCloud);
    HILOG_INFO("batchInsertHandleOneByOne end ts = %{public}lld", (long long) time(NULL));
    return Contacts::OPERATION_OK;
// LCOV_EXCL_STOP
}
