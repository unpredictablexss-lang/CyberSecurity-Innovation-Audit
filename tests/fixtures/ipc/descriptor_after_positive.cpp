// The guard is correct but runs after the operation it was supposed to protect.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class DescriptorAfterStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorAfterStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    OnCallback();
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IFoo::GetDescriptor()) return -1;
    return 0;
}
