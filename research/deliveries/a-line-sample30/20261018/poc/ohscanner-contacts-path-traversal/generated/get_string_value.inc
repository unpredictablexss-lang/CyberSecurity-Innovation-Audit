std::string ContactsDataAbility::GetStringValueFromDataShareValue(
    const DataShare::DataShareValuesBucket &dataShareValue, const std::string &valueName, bool &isValid)
{
    std::string value;
    DataShare::DataShareValueObject valueObject = dataShareValue.Get(valueName, isValid);
    if (!isValid) {
        return value;
    }
    
    if (const auto* stringPtr = std::get_if<std::string>(&valueObject.value)) {
        value = *stringPtr;
    }
    if (value.empty()) {
        isValid = false;
    }
    return value;
}
