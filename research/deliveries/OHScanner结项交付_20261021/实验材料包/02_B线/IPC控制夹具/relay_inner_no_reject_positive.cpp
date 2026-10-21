// M2 negative: the callee compares the token but the mismatch branch only logs.
// Execution falls through to the dispatcher either way, so no guard dominates the
// relayed transaction.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class RelayInnerNoRejectStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerNoRejectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerNoRejectStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFoo::GetDescriptor()) {
        LOG("interface token mismatch");
    }
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
