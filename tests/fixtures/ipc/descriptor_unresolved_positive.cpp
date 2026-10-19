// The class declaration is outside the analysed unit, as it is when a header is
// out of scope or only partly parsed. Which interface this stub implements is
// therefore unknown: neither a working guard nor a proven mismatch.
#include "common_types.h"

class IElsewhere {
public:
    static const char *GetDescriptor();
};

int DescriptorUnresolvedStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IElsewhere::GetDescriptor()) return -1;
    OnCallback();
    return 0;
}
