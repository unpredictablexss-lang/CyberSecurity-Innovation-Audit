#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

namespace OHOS {

class Uri {
public:
    Uri() = default;
    explicit Uri(std::string value) : value_(std::move(value)) {}
    std::string ToString() const { return value_; }
    std::string GetQuery() const {
        auto pos = value_.find('?');
        return pos == std::string::npos ? std::string{} : value_.substr(pos + 1);
    }
    void GetPathSegments(std::vector<std::string> &segments) const {
        auto body = value_.substr(0, value_.find('?'));
        segments.clear();
        std::stringstream stream(body);
        std::string item;
        while (std::getline(stream, item, '/')) {
            if (!item.empty()) segments.push_back(item);
        }
    }
private:
    std::string value_;
};

namespace DataShare {
struct DataShareValueObject {
    using Type = std::variant<std::monostate, std::string, int32_t, int64_t, double, bool, std::vector<uint8_t>>;
    Type value{};
    DataShareValueObject() = default;
    DataShareValueObject(std::string v) : value(std::move(v)) {}
    DataShareValueObject(const char *v) : value(std::string(v)) {}
    DataShareValueObject(int32_t v) : value(v) {}
    DataShareValueObject(int64_t v) : value(v) {}
    DataShareValueObject(double v) : value(v) {}
    DataShareValueObject(bool v) : value(v) {}
    DataShareValueObject(std::vector<uint8_t> v) : value(std::move(v)) {}
};

class DataShareValuesBucket {
public:
    void Put(const std::string &columnName, const DataShareValueObject &value = {}) {
        valuesMap[columnName] = value.value;
    }
    void Clear() { valuesMap.clear(); }
    DataShareValueObject Get(const std::string &columnName, bool &isValid) const {
        auto it = valuesMap.find(columnName);
        if (it == valuesMap.end()) {
            isValid = false;
            return {};
        }
        isValid = true;
        DataShareValueObject result;
        result.value = it->second;
        return result;
    }
    std::map<std::string, DataShareValueObject::Type> valuesMap;
};
using DataShareValuesBuckets = std::vector<DataShareValuesBucket>;
} // namespace DataShare

namespace NativeRdb {
constexpr int E_OK = 0;
struct ValueObject {
    std::string text;
    void GetObject(ValueObject &out) const { out = *this; }
};
struct ValuesBucket {
    ValueObject object;
    void GetObject(const std::string &, ValueObject &out) const { out = object; }
};
} // namespace NativeRdb

namespace Contacts {
constexpr int OPERATION_OK = 0;
constexpr int OPERATION_ERROR = -1;
constexpr int RDB_PERMISSION_ERROR = -2;
constexpr int RDB_EXECUTE_FAIL = -3;
constexpr int CONTACTS_CONTACT_DATA = 100;
constexpr int PROFILE_CONTACT_DATA = 101;
constexpr int CONTACTS_RAW_CONTACT = 102;
constexpr int PRIVACY_CONTACTS_BACKUP = 103;
constexpr int CONTACTS_BLOCKLIST = 104;
constexpr int ADD_CONTACT_INFO_BATCH = 105;
inline constexpr const char *OPERATE_TYPE_INSERT = "insert";
inline constexpr const char *ADD_CONTACT_INFO_BATCH_URI = "datashare://com.ohos.contactsdataability/add_contact_info_batch";
inline constexpr const char *CONTACTS_HARD_DELETE_URI = "datashare://com.ohos.contactsdataability/contacts/hard_delete";
inline constexpr const char *CONTACT_CHANGE_URI = "datashare://com.ohos.contactsdataability/contacts/contact_change";
inline constexpr int64_t g_operateDataTime = 10000;
constexpr int PHOTO_INT_VALUE = 1;
constexpr char APP_PATH_PREFIX[] = "/tmp/ohscanner_contacts_demo_20261021/data/storage/el2/group/";
constexpr char GROUP_PATH_PREFIX[] = "/tmp/ohscanner_contacts_demo_20261021/data/storage/el2/group/";
constexpr char PHOTO_STR[] = "/photo/";

class PixelMap {};
namespace PixelMapUtil {
inline std::shared_ptr<PixelMap> GetPixelMapFromFile(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return nullptr;
    char magic[8] = {};
    input.read(magic, sizeof(magic));
    static const unsigned char png[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    return std::memcmp(magic, png, sizeof(png)) == 0 ? std::make_shared<PixelMap>() : nullptr;
}
inline void GetThumbnailPixelMap(const std::shared_ptr<PixelMap> &, int) {}
inline int SavePixelMapToFile(const std::shared_ptr<PixelMap> &, int fd) {
    static const char png[] = "\x89PNG\r\n\x1a\n";
    return write(fd, png, sizeof(png) - 1) >= 0 ? OPERATION_OK : OPERATION_ERROR;
}
inline int32_t GetBlobSourceFromPixelMap(const std::shared_ptr<PixelMap> &) { return 1; }
inline int GetArrayBufferFromPixelMap(const std::shared_ptr<PixelMap> &, std::vector<uint8_t> &blob) {
    blob.assign({'P', 'N', 'G'});
    return OPERATION_OK;
}
} // namespace PixelMapUtil

class FileUtils {
public:
    int IsFolderExist(std::string path) {
        struct stat st {};
        return stat(path.c_str(), &st) == 0 ? OPERATION_OK : OPERATION_ERROR;
    }
    void Mkdir(const std::string &path, mode_t mode) { mkdir(path.c_str(), mode); }
    bool GetGroupDir(std::string &path) {
        path = "/tmp/ohscanner_contacts_demo_20261021/data/storage/el2/group/com.ohos.contactsdataability";
        return true;
    }
    bool GetGroupPath(std::string &groupPath);
    bool DeleteFile(const std::string &filePath);
};

struct ContactTableName {
    static constexpr int PRIVACY_CONTACTS_BACKUP = 103;
};
class ContactsDataBase {
public:
    int BatchInsertPrivacyContactsBackup(int, const std::vector<NativeRdb::ValuesBucket> &) { return OPERATION_OK; }
    int BatchInsertBlockList(const std::vector<DataShare::DataShareValuesBucket> &) { return OPERATION_OK; }
    int addContactInfoBatch(const std::vector<DataShare::DataShareValuesBucket> &) { return OPERATION_OK; }
    static std::shared_ptr<ContactsDataBase> GetInstance() {
        static auto instance = std::make_shared<ContactsDataBase>();
        return instance;
    }
    static std::string getUriLogPrintByUri(const Uri &uri) { return uri.ToString(); }
    int BeginTransaction() { return OPERATION_OK; }
    int Commit() { return OPERATION_OK; }
    int RollBack() { return OPERATION_OK; }
    void GetTypeText(const NativeRdb::ValuesBucket &, int &typeId, int &, std::string &) { typeId = -1; }
    void GetContactByValue(int &out, const NativeRdb::ValueObject &) { out = 1; }
};
class ProfileDatabase {
public:
    static std::shared_ptr<ProfileDatabase> GetInstance() {
        static auto instance = std::make_shared<ProfileDatabase>();
        return instance;
    }
};
class ContactConnectAbility {
public:
    static std::shared_ptr<ContactConnectAbility> GetInstance() {
        static auto instance = std::make_shared<ContactConnectAbility>();
        return instance;
    }
    void ConnectEventsHandleAbility(int, const std::string &, const std::string &) {}
};
} // namespace Contacts

namespace Telephony {
struct Permission { static constexpr int WRITE_CONTACTS = 1; };
class TelephonyPermission {
public:
    static bool CheckPermission(int) { return true; }
};
} // namespace Telephony

namespace RdbDataShareAdapter {
class RdbUtils {
public:
    static NativeRdb::ValuesBucket ToValuesBucket(const DataShare::DataShareValuesBucket &) { return {}; }
};
} // namespace RdbDataShareAdapter

namespace AbilityRuntime {
class ContactsDataAbility {
public:
    int BatchInsert(const Uri &uri, const std::vector<DataShare::DataShareValuesBucket> &values);
    int BatchInsertByMigrate(int, const Uri &, const std::vector<DataShare::DataShareValuesBucket> &) {
        return Contacts::OPERATION_OK;
    }
    int batchInsertHandleOneByOne(const Uri &uri, std::string isSyncFromCloud,
        int code, std::vector<DataShare::DataShareValuesBucket> &valuesHandle);
    int ProcessSingleInsert(DataShare::DataShareValuesBucket &rawContactValues,
        bool &isContainEvent, int &rawContactId, int &code, std::string &isSyncFromCloud);
    int HandleContactPortrait(DataShare::DataShareValuesBucket &value);
    int SavePortraitFileAndBlob(const std::string &srcFilePath, const std::string &filePath,
        std::vector<uint8_t> &blob, int32_t &blobSource);
    void BuildPortraitValue(DataShare::DataShareValuesBucket &value, const std::string &contactId,
        const std::string &rawContactId, const std::vector<uint8_t> &blob, int32_t blobSource);
    void GetPortraitValue(const DataShare::DataShareValuesBucket &dataShareValue,
        std::string &portraitFileName, std::string &contactId, std::string &rawContactId, bool &isValid);
    std::string GetStringValueFromDataShareValue(const DataShare::DataShareValuesBucket &dataShareValue,
        const std::string &valueName, bool &isValid);

    std::shared_ptr<Contacts::ContactsDataBase> contactDataBase_ = Contacts::ContactsDataBase::GetInstance();
    std::shared_ptr<Contacts::ProfileDatabase> profileDataBase_ = Contacts::ProfileDatabase::GetInstance();
    std::shared_ptr<Contacts::ContactConnectAbility> contactsConnectAbility_ = Contacts::ContactConnectAbility::GetInstance();

    static void transferDataShareToRdbBucket(const std::vector<DataShare::DataShareValuesBucket> &in,
        std::vector<NativeRdb::ValuesBucket> &out) { out.assign(in.size(), {}); }
    static int UriParseAndSwitch(Uri &) { return Contacts::CONTACTS_RAW_CONTACT; }
    std::string UriParseParam(Uri &) { return ""; }
    std::string UriParseBatchParam(Uri &) { return "false"; }
    int InsertExecute(int &, const NativeRdb::ValuesBucket &, std::string) { return Contacts::OPERATION_OK; }
    void handleUpdateCalllogAfterBatchInsertData(int, int, const std::vector<DataShare::DataShareValuesBucket> &) {}
    void HandleHwRelationData(const std::vector<DataShare::DataShareValuesBucket> &) {}
    void DataBaseNotifyChange(int, Uri, std::string) {}
    bool IsBeginTransactionOK(int code) { return code == Contacts::OPERATION_OK; }
    bool IsCommitOK(int code) { return code == Contacts::OPERATION_OK; }
};
} // namespace AbilityRuntime

namespace DataShare {
class ContactsDataShareStubImpl {
public:
    int BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values);
    Uri getUriPrintByUri(const Uri &uriTemp);
    bool NotifyChangeExt(const Uri &, const std::vector<DataShareValuesBucket> &, std::string) { return true; }
    bool GetBundleNameByUid(int32_t, std::string &bundleName) {
        bundleName = "com.ohos.contactsdataability";
        return true;
    }
    void SetContactsDataAbility(std::shared_ptr<AbilityRuntime::ContactsDataAbility> extension) {
        extension_ = std::move(extension);
    }
    std::shared_ptr<AbilityRuntime::ContactsDataAbility> GetOwner(const Uri &) { return extension_; }
private:
    std::shared_ptr<AbilityRuntime::ContactsDataAbility> extension_;
};

class IPCSkeleton {
public:
    static int32_t GetCallingUid() { return 20010000; }
};
} // namespace DataShare

inline std::mutex g_mutex;

inline std::string GetStringValueFromDataShareValueShim() { return ""; }

} // namespace OHOS

#define HILOG_ERROR(...) do { (void)sizeof(#__VA_ARGS__); } while (0)
#define HILOG_WARN(...) do { (void)sizeof(#__VA_ARGS__); } while (0)
#define HILOG_INFO(...) do { (void)sizeof(#__VA_ARGS__); } while (0)
#define HILOG_DEBUG(...) do { } while (0)
