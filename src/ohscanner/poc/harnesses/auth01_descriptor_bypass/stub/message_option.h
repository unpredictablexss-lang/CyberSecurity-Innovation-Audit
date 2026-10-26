// Minimal stand-in for the ipc_core public header of the same name.
// The target translation unit only forwards this object.
#ifndef STUB_MESSAGE_OPTION_H
#define STUB_MESSAGE_OPTION_H

#include <cstdint>

namespace OHOS {
class MessageOption {
public:
    enum {
        TF_SYNC = 0x00,
        TF_ASYNC = 0x01,
        TF_STATUS_CODE = 0x08,
        TF_ACCEPT_FDS = 0x10,
        TF_WAIT_TIME = 0x8,
    };
    explicit MessageOption(int flags = TF_SYNC, int waitTime = TF_WAIT_TIME)
        : flags_(flags), waitTime_(waitTime) {}
    ~MessageOption() = default;
    void SetFlags(int flags)
    {
        flags_ = flags;
    }
    int GetFlags() const
    {
        return flags_;
    }
    void SetWaitTime(int waitTime)
    {
        waitTime_ = waitTime;
    }
    int GetWaitTime() const
    {
        return waitTime_;
    }

private:
    int flags_;
    int waitTime_;
};
} // namespace OHOS

#endif
