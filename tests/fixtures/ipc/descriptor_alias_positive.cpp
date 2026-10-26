// The base is an alias. Following it would need a typedef table the index does
// not keep, so the interface this class implements is unknown rather than
// assumed -- an alias is not a licence to guess the identity.
#include "common_types.h"

class IFoo {
public:
    static const char *GetDescriptor();
};

using AliasBase = IRemoteStub<IFoo>;

class DescriptorAliasStub : public AliasBase {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

int DescriptorAliasStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IFoo::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
