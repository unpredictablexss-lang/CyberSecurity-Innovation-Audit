// The comparison is against the right interface, but a mismatch does not stop the
// transaction. Both paths reach the handler, so no guard dominates: a descriptor
// comparison is only a guard when the rejecting branch actually leaves.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class DescriptorNoRejectStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorNoRejectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IFoo::GetDescriptor()) {
        LOG("unexpected descriptor");
    }
    OnCallback();
    return 0;
}
