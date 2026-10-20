namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

void process(const DataShare::DataShareValuesBucket &values, const std::string &root)
{
    auto name = values.GetString("file");
    auto path = root + "/" + name;
    FileUtils::DeleteFile(path);
}
