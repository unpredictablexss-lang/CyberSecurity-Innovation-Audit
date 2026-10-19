// M2 negative: the comparison is real but nested inside another condition, so it
// may not run at all and does not dominate the dispatcher. Only a top-level check
// of the callee is read as the relay's guard.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class RelayInnerNestedStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerNestedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerNestedStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (code != 0) {
        if (data.ReadInterfaceToken() != IFoo::GetDescriptor()) {
            return -1;
        }
    }
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
