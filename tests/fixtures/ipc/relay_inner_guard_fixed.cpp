// M2: OnRemoteRequest only hands the request to OnRemoteRequestInner, and that
// callee compares the interface token at top level and leaves on mismatch before
// it routes the request. The call site is not itself an unguarded boundary, and
// the transaction is still guarded -- inside the function that dispatches.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class RelayInnerGuardStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerGuardStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerGuardStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
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
