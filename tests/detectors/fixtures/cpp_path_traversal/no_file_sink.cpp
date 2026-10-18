namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

std::string make_label(const DataShare::DataShareValuesBucket &values)
{
    auto name = values.GetString("label");
    return std::string("preview/") + name;
}
