// M2 negative: the callee does compare a descriptor, but against another
// interface than the one this stub implements. The comparison is present and not
// accepted, so the candidate is kept and both identities are cited.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class IBar {
public:
    static const char *GetDescriptor();
};

class RelayInnerWrongInterfaceStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerWrongInterfaceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerWrongInterfaceStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IBar::GetDescriptor()) {
        return -1;
    }
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
