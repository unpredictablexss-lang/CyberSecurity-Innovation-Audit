namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }
void incomplete(const DataShare::DataShareValuesBucket &values) {
    auto path = values.GetString("name");
    open(path.c_str(), O_RDONLY);
