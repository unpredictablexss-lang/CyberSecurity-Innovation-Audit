namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

void save_or_remove(const DataShare::DataShareValuesBucket &values, const std::string &root)
{
    auto supplied = values.GetString("name");
    std::string target = root;
    target += "/";
    target += supplied;
    int fd = creat(target.c_str(), 0600);
    unlink(target.c_str());
}
