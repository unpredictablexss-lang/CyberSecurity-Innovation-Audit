int ContactsDataAbility::BatchInsert(const Uri &uri,
    const std::vector<DataShare::DataShareValuesBucket> &values)
{
    if (!Telephony::TelephonyPermission::CheckPermission(Telephony::Permission::WRITE_CONTACTS)) {
        HILOG_ERROR("Permission denied!");
        return Contacts::RDB_PERMISSION_ERROR;
    }
    unsigned int size = values.size();
    if (size < 1) {
        HILOG_INFO("ContactsDataAbility BatchInsert values < 1");
        return Contacts::RDB_EXECUTE_FAIL;
    }
    g_mutex.lock();
    contactDataBase_ = Contacts::ContactsDataBase::GetInstance();
    profileDataBase_ = Contacts::ProfileDatabase::GetInstance();
    // 如果名称信息没有值，其他信息（如公司，职位，手机号码等有值），需要根据其他信息的值，设置到名称（如将公司名称设置到displayName）
    // 生成displayName情况，需要再bucket集合新增元素，但集合为const，不可修改，要使用一个新的集合
    OHOS::Uri uriTemp = uri;
    int code = UriParseAndSwitch(uriTemp);
    std::vector<DataShare::DataShareValuesBucket> valuesHandle = values;
    std::string isSyncFromCloud = UriParseParam(uriTemp);
    std::string isFromBatch = UriParseBatchParam(uriTemp);
    HILOG_INFO("getLockThen BatchInsert,isSyncFromCloud = %{public}s,isFromBatch = %{public}s",
        isSyncFromCloud.c_str(), isFromBatch.c_str());
    // batchInsert onebyone会调用到单个插入，会发送大量消息
    // uri 带isfrombatch的标记，批量操作，否则，一个一个插入
    if (isFromBatch == "true" && (code == Contacts::CONTACTS_CONTACT_DATA || code == Contacts::PROFILE_CONTACT_DATA ||
        code == Contacts::CONTACTS_RAW_CONTACT)) {
        int batchCode = BatchInsertByMigrate(code, uri, valuesHandle);
        // 插入成功，且操作contact_data表，新增完数据后，处理更新calllog
        handleUpdateCalllogAfterBatchInsertData(batchCode, code, values);
        g_mutex.unlock();
        return batchCode;
    }
    if (code == Contacts::PRIVACY_CONTACTS_BACKUP) {
        std::vector<OHOS::NativeRdb::ValuesBucket> valueRdb;
        ContactsDataAbility::transferDataShareToRdbBucket(valuesHandle, valueRdb);
        int batchCode = contactDataBase_->BatchInsertPrivacyContactsBackup(
            Contacts::ContactTableName::PRIVACY_CONTACTS_BACKUP, valueRdb);
        g_mutex.unlock();
        return batchCode;
    }
    if (code == Contacts::CONTACTS_BLOCKLIST) {
        int batchCode = contactDataBase_->BatchInsertBlockList(valuesHandle);
        g_mutex.unlock();
        return batchCode;
    }
    if (code == Contacts::ADD_CONTACT_INFO_BATCH) {
        int ret = contactDataBase_->addContactInfoBatch(valuesHandle);
        DataBaseNotifyChange(Contacts::CONTACT_INSERT, uri, "false");
        g_mutex.unlock();
        return ret;
    }
    int ret = batchInsertHandleOneByOne(uri, isSyncFromCloud, code, valuesHandle);
    // 插入成功，且操作contact_data表，新增完数据后，处理更新calllog
    handleUpdateCalllogAfterBatchInsertData(ret, code, values);
    g_mutex.unlock();
    HandleHwRelationData(values);
    return ret;
}
