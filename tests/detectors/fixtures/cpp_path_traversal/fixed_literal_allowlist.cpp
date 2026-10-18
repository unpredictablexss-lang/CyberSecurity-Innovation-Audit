namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

void load_picture(const DataShare::DataShareValuesBucket &values, const std::string &root)
{
    auto name = values.GetString("picture");
    if (name != "avatar.png" && name != "cover.jpg") {
        return;
    }
    auto path = root + "/" + name;
    open(path.c_str(), O_RDONLY);
}
