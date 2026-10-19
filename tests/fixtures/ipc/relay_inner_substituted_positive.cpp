// M2 negative: the call is not a relay. It replaces the transaction code with a
// literal, so what the callee guards is a different transaction than the one the
// caller arrived on; the caller's own boundary is still unestablished.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class RelayInnerSubstitutedStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerSubstitutedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(0, data, reply, option);
}

int RelayInnerSubstitutedStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFoo::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
