#include "common_types.h"

class IFoo { public: static const char *GetDescriptor(); };
class IBar { public: static const char *GetDescriptor(); };
class T5WrongThenCorrectStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &);
    int OnRemoteRequestInner(uint32_t, MessageParcel &, MessageParcel &, MessageOption &);
};

int T5WrongThenCorrectStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
    return OnRemoteRequestInner(code, data, reply, option);
}

int T5WrongThenCorrectStub::OnRemoteRequestInner(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) {
    const auto token = data.ReadInterfaceToken();
    if (code == 1) {
        if (token != IBar::GetDescriptor()) return -1;
        switch (code) {
        case 1:
            OnCallback();
            break;
        }
    }
    if (code == 2) {
        if (token != IFoo::GetDescriptor()) return -1;
        switch (code) {
        case 2:
            OnCallback();
            break;
        }
    }
    return 0;
}
