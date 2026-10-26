namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

std::string extract_name(const DataShare::DataShareValuesBucket &values)
{
    return values.GetString("field");
}

void read_picture(const DataShare::DataShareValuesBucket &values, const std::string &root)
{
    auto name = extract_name(values);
    auto path = root + "/" + name;
    open(path.c_str(), O_RDONLY);
}
