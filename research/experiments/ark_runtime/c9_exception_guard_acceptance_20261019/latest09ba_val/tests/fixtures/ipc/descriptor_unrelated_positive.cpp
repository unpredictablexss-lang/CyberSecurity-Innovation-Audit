// The qualifier is an unrelated concrete class that happens to declare the same
// method name. It resolves, and it is not the interface this stub implements.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class Unrelated {
public:
    static const char *GetDescriptor();
};

class DescriptorUnrelatedStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorUnrelatedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != Unrelated::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
