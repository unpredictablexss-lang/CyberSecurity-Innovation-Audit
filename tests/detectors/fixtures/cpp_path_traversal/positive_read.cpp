struct DataShareValuesBucket {
    std::string GetString(const std::string &) const;
};

void load_picture(const DataShareValuesBucket &bucket, const std::string &root)
{
    auto field = bucket.GetString("picture");
    std::string path = root + "/" + field;
    open(path.c_str(), O_RDONLY);
}
