namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

void load_picture(const DataShare::DataShareValuesBucket &values, const std::filesystem::path &root)
{
    auto supplied = values.GetString("picture");
    auto resolved = std::filesystem::canonical(root / supplied);
    auto canonical_root = std::filesystem::canonical(root);
    auto relative = resolved.lexically_relative(canonical_root);
    if (relative.empty() || *relative.begin() == "..") {
        return;
    }
    open(resolved.c_str(), O_RDONLY);
}
