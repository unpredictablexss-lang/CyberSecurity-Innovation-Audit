// The stub implements IFoo but the guard validates IBar, so a caller that writes
// IBar's descriptor passes while this transaction expects IFoo. The comparison is
// present and is not this transaction's guard: reported as such, with both sides.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

class IBar {
public:
    static const char *GetDescriptor();
};

class DescriptorWrongInterfaceStub : public IRemoteStub<IFoo> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorWrongInterfaceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IBar::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
