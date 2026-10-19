// The real OpenHarmony stub shape: the class implements IFoo and the guard
// compares the caller's descriptor against IFoo::GetDescriptor(). Accepted.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class DescriptorInterfaceStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorInterfaceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IFoo::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
