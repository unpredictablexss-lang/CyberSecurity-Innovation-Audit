// Multi-level inheritance: the stub names no interface itself, its base does.
// The walk follows bases' bases, so the identity is still source-derived. Accepted.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class DescriptorMidBase : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

class DescriptorInheritedStub : public DescriptorMidBase {
};

int DescriptorInheritedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IFoo::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
