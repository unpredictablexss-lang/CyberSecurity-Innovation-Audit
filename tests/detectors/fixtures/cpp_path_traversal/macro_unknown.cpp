#define FILE_OPEN(path) open(path, O_RDONLY)
namespace DataShare { struct DataShareValuesBucket { std::string GetString(const std::string &) const; }; }

void load_picture(const DataShare::DataShareValuesBucket &values)
{
    auto path = values.GetString("picture");
    FILE_OPEN(path.c_str());
}
