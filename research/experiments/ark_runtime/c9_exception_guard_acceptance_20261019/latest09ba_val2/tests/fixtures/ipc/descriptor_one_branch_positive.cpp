// The guard covers one dispatch branch only; the other reaches its handler with
// no guard at all.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class DescriptorOneBranchStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void HandleMessage(MessageParcel &data);
};

int DescriptorOneBranchStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    if (code == 1) {
        std::u16string descriptor = data.ReadInterfaceToken();
        if (descriptor != IFoo::GetDescriptor()) return -1;
        HandleMessage(data);
        return 0;
    }
    OnCallback();
    return 0;
}

void DescriptorOneBranchStub::HandleMessage(MessageParcel &data) {
    OnResult(data);
}
