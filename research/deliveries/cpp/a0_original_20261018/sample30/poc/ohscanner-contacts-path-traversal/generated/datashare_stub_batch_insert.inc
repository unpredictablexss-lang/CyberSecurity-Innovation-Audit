int ContactsDataShareStubImpl::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    std::string callingBundleName;
    if (!GetBundleNameByUid(uid, callingBundleName)) {
        HILOG_ERROR("ContactsDataShareStubImpl BatchInsert getbundleName faild");
    }
    unsigned int size = values.size();
    OHOS::Uri uriTemp = uri;
    std::chrono::milliseconds beginTime = std::chrono::duration_cast<std::chrono::milliseconds >(
        std::chrono::system_clock::now().time_since_epoch());
    HILOG_WARN("batch insert begin. uri = %{public}s,beginTime = %{public}lld,callingBundleName = %{public}s,"
        "values.size is %{public}d", Contacts::ContactsDataBase::getUriLogPrintByUri(uriTemp).c_str(),
        beginTime.count(), callingBundleName.c_str(), size);
    int ret = 0;
    auto extension = GetOwner(uri);
    if (extension == nullptr) {
        HILOG_ERROR("batch insert failed, extension is null.");
        return ret;
    }
    ret = extension->BatchInsert(uri, values);
    if (ret != Contacts::OPERATION_ERROR && uriTemp.ToString().find("noNotifyChange") == std::string::npos) {
        if (uriTemp.GetQuery() == "isFromBatch=true") {
            std::string noQueryUri =
                uriTemp.ToString().substr(0, uriTemp.ToString().length() - uriTemp.GetQuery().length() - 1);
            HILOG_INFO("no query uri: %{public}s", noQueryUri.c_str());
            NotifyChangeExt(Uri(noQueryUri), values, Contacts::OPERATE_TYPE_INSERT);
        } else if (uriTemp.ToString() == Contacts::ADD_CONTACT_INFO_BATCH_URI ||
                   uriTemp.ToString() == Contacts::CONTACTS_HARD_DELETE_URI) {
            OHOS::Uri uriContact(Contacts::CONTACT_CHANGE_URI);
            NotifyChangeExt(uriContact, {}, Contacts::OPERATE_TYPE_INSERT);
        } else {
            uriTemp = getUriPrintByUri(uri);
            NotifyChangeExt(uriTemp, values, Contacts::OPERATE_TYPE_INSERT);
        }
    }
    std::chrono::milliseconds endTime = std::chrono::duration_cast<std::chrono::milliseconds >(
        std::chrono::system_clock::now().time_since_epoch());
    if (endTime.count() - beginTime.count() > g_operateDataTime) {
        HILOG_WARN("batch insert end successfully.ret: %{public}d,uri = %{public}s,contact db cost time = %{public}lld",
            ret, Contacts::ContactsDataBase::getUriLogPrintByUri(uriTemp).c_str(), endTime.count() - beginTime.count());
    } else {
        HILOG_WARN("batch insert end successfully.ret: %{public}d,uri = %{public}s,endTime = %{public}lld",
            ret, Contacts::ContactsDataBase::getUriLogPrintByUri(uriTemp).c_str(), endTime.count());
    }
    return ret;
}
