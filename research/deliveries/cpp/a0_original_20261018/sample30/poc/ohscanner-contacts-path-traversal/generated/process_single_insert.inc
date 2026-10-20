int ContactsDataAbility::ProcessSingleInsert(DataShare::DataShareValuesBucket &rawContactValues,
    bool &isContainEvent, int &rawContactId, int &code, std::string &isSyncFromCloud)
{
// LCOV_EXCL_START
    int errorCode = HandleContactPortrait(rawContactValues);
    if (errorCode != Contacts::OPERATION_OK) {
        return errorCode;
    }
    OHOS::NativeRdb::ValuesBucket value = RdbDataShareAdapter::RdbUtils::ToValuesBucket(rawContactValues);
    // 根据code，处理插入contact_data或contact等信息
    int rowRet = InsertExecute(code, value, isSyncFromCloud);
    if (rowRet == Contacts::OPERATION_ERROR) {
        HILOG_ERROR("batchInsertHandleOneByOne rowRet error!");
        contactDataBase_->RollBack();
        return rowRet;
    }
    if (!isContainEvent) {
        int typeId = Contacts::RDB_EXECUTE_FAIL;
        int id = OHOS::NativeRdb::E_OK;
        std::string typeText;
        contactDataBase_->GetTypeText(value, typeId, id, typeText);
        if (typeId == Contacts::ContentTypeData::CONTACT_EVENT_INT_VALUE) {
            isContainEvent = true;
        }
    }
    
    if (rawContactId == -1) {
        OHOS::NativeRdb::ValueObject valueObject;
        value.GetObject(Contacts::ContactDataColumns::RAW_CONTACT_ID, valueObject);
        contactDataBase_->GetContactByValue(rawContactId, valueObject);
        HILOG_INFO("batchInsertHandleOneByOne rawContactId  = %{public}d", rawContactId);
    }
    return Contacts::OPERATION_OK;
// LCOV_EXCL_STOP
}
