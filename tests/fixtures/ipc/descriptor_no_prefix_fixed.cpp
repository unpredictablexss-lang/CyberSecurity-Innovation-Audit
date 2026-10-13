// The interface is named without an I prefix (as OnPermissionUsedRecordCallback
// really is in security_access_token). The identity is read from the base clause,
// so a name convention is neither needed nor used. Accepted.
#include "common_types.h"

class OnPermissionUsedRecordCallback {
public:
    static const char *GetDescriptor();
};

class DescriptorNoPrefixStub : public IRemoteStub<OnPermissionUsedRecordCallback> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorNoPrefixStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != OnPermissionUsedRecordCallback::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
