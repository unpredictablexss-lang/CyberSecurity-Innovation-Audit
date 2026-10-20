void ContactsDataAbility::GetPortraitValue(const DataShare::DataShareValuesBucket &dataShareValue,
    std::string &portraitFileName, std::string &contactId, std::string &rawContactId, bool &isValid)
{
    portraitFileName = GetStringValueFromDataShareValue(dataShareValue, "PortraitFileName", isValid);
    if (!isValid) {
        HILOG_DEBUG("not have portraitFileName");
        return;
    }
    contactId = GetStringValueFromDataShareValue(dataShareValue, "contactId", isValid);
    if (!isValid) {
        HILOG_DEBUG("not have contactId");
        return;
    }
    rawContactId = GetStringValueFromDataShareValue(dataShareValue, "rawContactId", isValid);
    if (!isValid) {
        HILOG_DEBUG("not have rawContactId");
        return;
    }

}
