struct FakeBucket { std::string GetString(const std::string &) const; };

void load_picture(const FakeBucket &bucket, const std::string &root)
{
    auto name = bucket.GetString("picture");
    auto path = root + "/" + name;
    open(path.c_str(), O_RDONLY);
}
