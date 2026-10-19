// M2 negative: the relayed-to function never compares the interface token, so the
// hop hands the request straight to the dispatcher. The call site stays a candidate.
#include "common_types.h"

class RelayInnerNoGuardStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerNoGuardStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerNoGuardStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
