// The descriptor is fetched but never compared with the caller's token, so no
// guard exists on this path. Seeing the call is not seeing a check.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class DescriptorCallOnlyStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorCallOnlyStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string expected = IFoo::GetDescriptor();
    (void)expected;
    OnCallback();
    return 0;
}
