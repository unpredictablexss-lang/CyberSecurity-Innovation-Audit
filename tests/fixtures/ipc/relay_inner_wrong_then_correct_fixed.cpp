// An unrelated descriptor comparison precedes the actual interface guard.
// The first comparison must not mask the later guard for this stub.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class IBar {
public:
    static const char *GetDescriptor();
};

class RelayInnerWrongThenCorrectStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int RelayInnerWrongThenCorrectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int RelayInnerWrongThenCorrectStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    const auto token = data.ReadInterfaceToken();
    if (token != IBar::GetDescriptor()) {
        return -1;
    }
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
