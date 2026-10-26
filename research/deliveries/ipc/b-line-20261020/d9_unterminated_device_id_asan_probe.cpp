// Layout-level sanitizer probe for the source-bound DHandleEntryTxRx field.
// This is not a product integration test: it isolates the exact allocation,
// fixed-array declaration and C-string conversion semantics without opening
// a SoftBus socket or contacting a device.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

constexpr int DEVICEID_LENGTH = 64;
constexpr int SERVICENAME_LENGTH = 200;
using binder_uintptr_t = uint64_t;

struct DeviceIdInfo {
    uint32_t tokenId;
    char fromDeviceId[DEVICEID_LENGTH + 1];
    char toDeviceId[DEVICEID_LENGTH + 1];
};

struct DHandleEntryHead {
    uint32_t len;
    uint32_t version;
};

struct DHandleEntryTxRx {
    DHandleEntryHead head;
    uint32_t transType;
    uint32_t dBinderCode;
    uint16_t fromPort;
    uint16_t toPort;
    uint64_t stubIndex;
    uint32_t seqNumber;
    binder_uintptr_t binderObject;
    DeviceIdInfo deviceIdInfo;
    binder_uintptr_t stub;
    uint16_t serviceNameLength;
    char serviceName[SERVICENAME_LENGTH + 1];
    uint32_t pid;
    uint32_t uid;
};

static_assert(offsetof(DHandleEntryTxRx, deviceIdInfo.fromDeviceId) == 52);
static_assert(sizeof(DHandleEntryTxRx) == 408);

int main(int argc, char **argv)
{
    auto message = std::make_shared<DHandleEntryTxRx>();
    std::memset(message.get(), 0x41, sizeof(*message));
    message->head.len = sizeof(*message);
    message->dBinderCode = 1; // MESSAGE_AS_INVOKER
    const bool unterminated = argc > 1 && std::string(argv[1]) == "unterminated";
    if (!unterminated) {
        message->deviceIdInfo.fromDeviceId[DEVICEID_LENGTH] = '\0';
    }

    // Mirrors the implicit const-char* -> std::string conversion at the
    // pinned product call site. ASan should report a read past the make_shared
    // object in unterminated mode; the default mode models a valid 64-byte ID.
    std::string deviceId(message->deviceIdInfo.fromDeviceId);
    return unterminated ? 0 : (deviceId.size() == DEVICEID_LENGTH ? 0 : 1);
}
