void ContactsDataAbility::BuildPortraitValue(DataShare::DataShareValuesBucket &value, const std::string &contactId,
    const std::string &rawContactId, const std::vector<uint8_t> &blob, int32_t blobSource)
{
    value.Clear();
    value.Put("raw_contact_id", rawContactId);
    value.Put("blob_data", blob);
    value.Put("type_id", Contacts::ContentTypeData::PHOTO_INT_VALUE);
    std::string fileName = "photo/" + contactId + "_" + rawContactId;
    value.Put("blob_source", blobSource);
    value.Put("detail_info", fileName);
}
