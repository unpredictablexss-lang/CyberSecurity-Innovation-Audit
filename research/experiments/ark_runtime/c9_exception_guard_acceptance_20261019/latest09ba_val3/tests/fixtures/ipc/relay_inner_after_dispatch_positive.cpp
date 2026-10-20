// M2 negative: the callee does compare the token, but only after it already routed
// the request through the switch. A check that runs after the dispatch does not
// dominate it, so the relay is not the guard.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class RelayInnerAfterDispatchStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerAfterDispatchStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerAfterDispatchStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    if (data.ReadInterfaceToken() != IFoo::GetDescriptor()) {
        return -1;
    }
    return 0;
}
