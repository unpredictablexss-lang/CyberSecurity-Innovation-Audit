// Minimal stand-in for the ipc_core template of the same name.
//
// The real IRemoteStub derives from IPCObjectStub and inherits the real
// OnRemoteRequest. Here the default request handler is a stub, because the
// harness never exercises the default branch: it drives the interface-specific
// code path (NOTIFY_EVENT) that the component's own OnRemoteRequest dispatches.
#ifndef STUB_IREMOTE_STUB_H
#define STUB_IREMOTE_STUB_H

#include <cstdint>

#include "ipc_object_stub.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
template <typename INTERFACE>
class IRemoteStub : public IPCObjectStub, public INTERFACE {
public:
    IRemoteStub() = default;
    ~IRemoteStub() override = default;

    virtual int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                MessageOption &option)
    {
        (void)data;
        (void)reply;
        (void)option;
        return static_cast<int>(code) == 0 ? 0 : -1;
    }
};
} // namespace OHOS

#endif
