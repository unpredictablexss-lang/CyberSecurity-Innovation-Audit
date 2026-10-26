namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

std::string extract_name(const DataShare::DataShareValuesBucket &values)
{
    return values.GetString("picture");
}

std::string make_path(const std::string &root, const std::string &name)
{
    return root + "/" + name;
}

void delete_path(const std::string &path)
{
    unlink(path.c_str());
}

void update(const DataShare::DataShareValuesBucket &values, const std::string &root)
{
    delete_path(make_path(root, extract_name(values)));
}
