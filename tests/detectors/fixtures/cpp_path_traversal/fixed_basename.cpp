namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

void load_picture(const DataShare::DataShareValuesBucket &values, const std::string &root)
{
    auto supplied = values.GetString("picture");
    auto name = std::filesystem::path(supplied).filename().string();
    auto path = root + "/" + name;
    open(path.c_str(), O_RDONLY);
}
