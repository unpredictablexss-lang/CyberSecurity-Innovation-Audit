// M2: same as relay_inner_guard_fixed, but the callee holds the token in a local
// first. The variable does not make the guard less of a guard -- the declaration
// on the way to the comparison is bound before the comparison is read.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class RelayInnerLocalGuardStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerLocalGuardStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerLocalGuardStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string token = data.ReadInterfaceToken();
    if (token != IFoo::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
