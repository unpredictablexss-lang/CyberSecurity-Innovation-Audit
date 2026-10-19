// Definitions for the two classes that the target translation unit calls but
// does not define: Message and MessageHandler.
//
// Their *declarations* are the real ones from the vulnerable commit's headers;
// only the definitions live here, and MessageHandler::SendMessage records the
// call instead of dispatching it. That recording is the observable the PoC
// reads: it is the moment the service accepts the request and acts on it.
#include "message.h"
#include "message_handler.h"

#include "observations.h"

namespace OHOS {
namespace MiscServices {

Message::Message(int32_t msgId, MessageParcel *msgContent) : msgId_(msgId), msgContent_(msgContent) {}

Message::Message(const Message &msg) : msgId_(msg.msgId_), msgContent_(msg.msgContent_) {}

Message &Message::operator=(const Message &msg)
{
    if (this != &msg) {
        msgId_ = msg.msgId_;
        msgContent_ = msg.msgContent_;
    }
    return *this;
}

Message::~Message() = default;

MessageHandler::MessageHandler() = default;
MessageHandler::~MessageHandler() = default;

MessageHandler *MessageHandler::Instance()
{
    static MessageHandler handler;
    return &handler;
}

void MessageHandler::SendMessage(Message *msg)
{
    if (msg == nullptr) {
        return;
    }
    poc::SentMessage record{};
    record.msgId = msg->msgId_;
    record.contentBytes = (msg->msgContent_ != nullptr) ? msg->msgContent_->GetDataSize() : 0;
    record.userId = -1;
    record.contentCount = -1;
    if (msg->msgContent_ != nullptr) {
        // Read the queued content back the way the service consumer would: the
        // service wrote userId, then the content count, then the entries.
        msg->msgContent_->RewindRead(0);
        record.userId = msg->msgContent_->ReadInt32();
        record.contentCount = msg->msgContent_->ReadInt32();
    }
    poc::sent().push_back(record);
}

Message *MessageHandler::GetMessage()
{
    return nullptr;
}

} // namespace MiscServices
} // namespace OHOS
