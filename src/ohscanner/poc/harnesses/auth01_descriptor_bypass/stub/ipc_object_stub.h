// Minimal stand-in: the target translation unit never touches IPCObjectStub
// directly; it only reaches IRemoteStub's default OnRemoteRequest.
//
// Deliberately does NOT declare GetDescriptor(), so that the only GetDescriptor
// in scope for the stub class is the one the interface's
// DECLARE_INTERFACE_DESCRIPTOR provides -- that is the one the fixed code
// compares the incoming token against.
#ifndef STUB_IPC_OBJECT_STUB_H
#define STUB_IPC_OBJECT_STUB_H

#include "refbase.h"

namespace OHOS {
class IPCObjectStub {
public:
    IPCObjectStub() = default;
    explicit IPCObjectStub(const std::u16string &descriptor) : stubDescriptor_(descriptor) {}
    virtual ~IPCObjectStub() = default;

protected:
    std::u16string stubDescriptor_;
};
} // namespace OHOS

#endif
