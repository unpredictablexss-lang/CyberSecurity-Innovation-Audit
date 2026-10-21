#include "common_types.h"

class IFoo { public: static const char *GetDescriptor(); };
class T5GuardBeforeAllStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &);
    int OnRemoteRequestInner(uint32_t, MessageParcel &, MessageParcel &, MessageOption &);
};

int T5GuardBeforeAllStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int T5GuardBeforeAllStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFoo::GetDescriptor()) return -1;
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    switch (code) {
    case 2:
        OnCallback();
        break;
    }
    return 0;
}
