#include "common_types.h"

class IFoo { public: static const char *GetDescriptor(); };
class T5AmbiguousHelperStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &);
    int OnRemoteRequestInner(uint32_t, MessageParcel &, MessageParcel &, MessageOption &);
    int OnRemoteRequestInner(uint32_t, MessageParcel &, MessageParcel &, const MessageOption &);
};

int T5AmbiguousHelperStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int T5AmbiguousHelperStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
    if (data.ReadInterfaceToken() != IFoo::GetDescriptor()) return -1;
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}

int T5AmbiguousHelperStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data,
        MessageParcel &reply, const MessageOption &option) {
    switch (code) {
    case 1:
        OnCallback();
        break;
    }
    return 0;
}
